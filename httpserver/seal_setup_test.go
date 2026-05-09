package httpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/golang-htcondor/httpserver/appdb/seal"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestSealedRoundtripRSAKey exercises the OAuth2Storage RSA-key path
// end-to-end with envelope encryption: SaveRSAKey writes ciphertext +
// wrapped DEK, LoadRSAKey decrypts cleanly, and the on-disk row is
// not the plaintext.
func TestSealedRoundtripRSAKey(t *testing.T) {
	db := newTestDB(t, filepath.Join(t.TempDir(), "sealed.db"))

	masterKEK := mustRand32(t)
	salt, err := seal.NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	dbKey, err := seal.DeriveDBKey(masterKEK, salt)
	if err != nil {
		t.Fatalf("DeriveDBKey: %v", err)
	}
	sealer, err := seal.New(dbKey)
	if err != nil {
		t.Fatalf("seal.New: %v", err)
	}

	storage := NewOAuth2Storage(db)
	storage.SetSealer(sealer)

	// The "RSA PRIVATE KEY" markers are not a real key — gosec G101
	// flags the literal as a "potential hardcoded credential", but
	// the body is just "MIIE..." placeholder text. We only need a
	// distinctive plaintext to roundtrip through the sealer; using a
	// real PEM here would be wasteful (and a different gosec issue).
	const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----" //nolint:gosec // not a real key, just a roundtrip fixture
	if err := storage.SaveRSAKey(context.Background(), pem); err != nil {
		t.Fatalf("SaveRSAKey: %v", err)
	}
	got, err := storage.LoadRSAKey(context.Background())
	if err != nil {
		t.Fatalf("LoadRSAKey: %v", err)
	}
	if got != pem {
		t.Errorf("LoadRSAKey roundtrip mismatch")
	}

	// Direct DB read: confirm the on-disk PEM column is NOT the
	// plaintext, AND that the dek column is non-null. That's the
	// whole reason the encryption exists.
	var rawData []byte
	var rawDEK []byte
	err = db.QueryRowContext(context.Background(),
		`SELECT private_key_pem, private_key_pem_dek FROM oauth2_rsa_keys WHERE id = 1`).
		Scan(&rawData, &rawDEK)
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if bytes.Equal(rawData, []byte(pem)) {
		t.Errorf("on-disk private_key_pem is plaintext; encryption broken")
	}
	if len(rawDEK) == 0 {
		t.Errorf("on-disk private_key_pem_dek is empty; encryption skipped")
	}
}

// TestSealedLoadRejectsMissingKEK confirms that a sealed row cannot
// be silently treated as plaintext when the operator forgets to
// provide the KEK. We want a clear error, not a garbled key.
func TestSealedLoadRejectsMissingKEK(t *testing.T) {
	db := newTestDB(t, filepath.Join(t.TempDir(), "sealed.db"))

	sealer, err := seal.New(mustRand32(t))
	if err != nil {
		t.Fatalf("seal.New: %v", err)
	}
	storage := NewOAuth2Storage(db)
	storage.SetSealer(sealer)
	if err := storage.SaveRSAKey(context.Background(), "secret-pem"); err != nil {
		t.Fatalf("SaveRSAKey: %v", err)
	}

	// Drop the sealer — simulate a redeploy that forgot to provide
	// HTTP_API_KEK_FILE.
	storage.SetSealer(nil)
	if _, err := storage.LoadRSAKey(context.Background()); err == nil {
		t.Errorf("LoadRSAKey accepted sealed row without KEK; expected error")
	}
}

// TestPlaintextFallback confirms that when no sealer is configured
// the storage continues to behave like the pre-encryption code: the
// PEM is stored verbatim, the DEK column stays NULL, and Load
// returns the same plaintext.
func TestPlaintextFallback(t *testing.T) {
	db := newTestDB(t, filepath.Join(t.TempDir(), "plain.db"))
	storage := NewOAuth2Storage(db) // no sealer

	const pem = "plaintext-pem"
	if err := storage.SaveRSAKey(context.Background(), pem); err != nil {
		t.Fatalf("SaveRSAKey: %v", err)
	}
	got, err := storage.LoadRSAKey(context.Background())
	if err != nil {
		t.Fatalf("LoadRSAKey: %v", err)
	}
	if got != pem {
		t.Errorf("plaintext roundtrip mismatch")
	}

	var dek []byte
	err = db.QueryRowContext(context.Background(),
		`SELECT private_key_pem_dek FROM oauth2_rsa_keys WHERE id = 1`).Scan(&dek)
	if err != nil {
		t.Fatalf("raw dek: %v", err)
	}
	if len(dek) != 0 {
		t.Errorf("expected NULL dek in plaintext mode, got %d bytes", len(dek))
	}
}

// TestBackfillEncryptsPlaintextRows simulates the upgrade path: an
// old DB has plaintext RSA + HMAC rows; setupSealer must encrypt them
// in place on first start with a KEK.
func TestBackfillEncryptsPlaintextRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "backfill.db")
	db := newTestDB(t, dbPath)

	// Write plaintext rows directly — this is what an older deploy
	// would have left behind before the encryption switch.
	const pem = "old-plaintext-pem"
	hmac := []byte("old-plaintext-hmac-32-bytes-aaaa")
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO oauth2_rsa_keys (id, private_key_pem) VALUES (1, ?)`, pem)
	if err != nil {
		t.Fatalf("seed RSA: %v", err)
	}
	_, err = db.ExecContext(context.Background(),
		`INSERT INTO oauth2_hmac_secrets (id, secret) VALUES (1, ?)`, hmac)
	if err != nil {
		t.Fatalf("seed HMAC: %v", err)
	}

	// Drop the master KEK in a 0600 file.
	kekPath := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(kekPath, mustRand32(t), 0o600); err != nil {
		t.Fatalf("write kek: %v", err)
	}
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})

	sealer, migrated, err := setupSealer(context.Background(), db, kekPath, logger)
	if err != nil {
		t.Fatalf("setupSealer: %v", err)
	}
	if sealer == nil {
		t.Fatalf("setupSealer returned nil sealer with KEK present")
	}
	if migrated != 2 {
		t.Errorf("backfill migrated %d rows, want 2 (the seeded RSA + HMAC)", migrated)
	}

	// Confirm rows now have non-null DEKs.
	var rsaDEK, hmacDEK []byte
	if err := db.QueryRowContext(context.Background(),
		`SELECT private_key_pem_dek FROM oauth2_rsa_keys WHERE id = 1`).Scan(&rsaDEK); err != nil {
		t.Fatalf("rsa dek: %v", err)
	}
	if len(rsaDEK) == 0 {
		t.Errorf("RSA row not encrypted after backfill")
	}
	if err := db.QueryRowContext(context.Background(),
		`SELECT secret_dek FROM oauth2_hmac_secrets WHERE id = 1`).Scan(&hmacDEK); err != nil {
		t.Fatalf("hmac dek: %v", err)
	}
	if len(hmacDEK) == 0 {
		t.Errorf("HMAC row not encrypted after backfill")
	}

	// Confirm the storage layer can still load the plaintexts back.
	storage := NewOAuth2Storage(db)
	storage.SetSealer(sealer)
	gotPEM, err := storage.LoadRSAKey(context.Background())
	if err != nil || gotPEM != pem {
		t.Errorf("LoadRSAKey post-backfill: %q err=%v", gotPEM, err)
	}
	gotHMAC, err := storage.LoadHMACSecret(context.Background())
	if err != nil || !bytes.Equal(gotHMAC, hmac) {
		t.Errorf("LoadHMACSecret post-backfill: err=%v match=%v", err, bytes.Equal(gotHMAC, hmac))
	}
}

// TestBackfillIdempotent confirms that running setupSealer a second
// time (typical: every server restart) doesn't re-encrypt rows that
// are already sealed and doesn't lose the data.
func TestBackfillIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "idem.db")
	db := newTestDB(t, dbPath)

	const pem = "test-pem"
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO oauth2_rsa_keys (id, private_key_pem) VALUES (1, ?)`, pem)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	kekPath := filepath.Join(t.TempDir(), "kek")
	kek := mustRand32(t)
	if err := os.WriteFile(kekPath, []byte(hex.EncodeToString(kek)+"\n"), 0o600); err != nil {
		t.Fatalf("write kek: %v", err)
	}

	// First run — backfill encrypts the row.
	_, migrated1, err := setupSealer(context.Background(), db, kekPath, nil)
	if err != nil {
		t.Fatalf("first setupSealer: %v", err)
	}
	if migrated1 != 1 {
		t.Errorf("first run migrated %d rows, want 1", migrated1)
	}

	// Second run — same KEK, salt persisted, nothing to do.
	_, migrated2, err := setupSealer(context.Background(), db, kekPath, nil)
	if err != nil {
		t.Fatalf("second setupSealer: %v", err)
	}
	if migrated2 != 0 {
		t.Errorf("second run migrated %d rows, want 0 (idempotent)", migrated2)
	}
}

// TestScrubbedFormDataRemovesSecrets pins the contract that the
// helper drops the two fields fosite would otherwise persist next to
// a bcrypt-hashed copy in oauth2_clients (client_secret) or past
// the PKCE redemption window (code_verifier), while leaving every
// other field intact.
func TestScrubbedFormDataRemovesSecrets(t *testing.T) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"my-client"},
		"client_secret": {"super-secret"},
		"code":          {"abc"},
		"code_verifier": {"verifier-xyz"},
		"redirect_uri":  {"https://example.com/cb"},
		"scope":         {"openid email"},
	}
	out := scrubbedFormData(form)
	got := string(out)

	for _, dropped := range []string{"client_secret", "super-secret", "code_verifier", "verifier-xyz"} {
		if bytes.Contains(out, []byte(dropped)) {
			t.Errorf("scrubbedFormData leaked %q in %s", dropped, got)
		}
	}
	for _, kept := range []string{"grant_type", "authorization_code", "client_id", "my-client", "redirect_uri", "openid"} {
		if !bytes.Contains(out, []byte(kept)) {
			t.Errorf("scrubbedFormData dropped non-secret %q from %s", kept, got)
		}
	}
}

func mustRand32(t *testing.T) []byte {
	t.Helper()
	out := make([]byte, 32)
	// The KEK reader (seal.LoadMasterKEK) trims trailing
	// \r\n\t<space> before validating length, so a raw byte from
	// rand.Read landing on one of those four values would shrink
	// the file below 32 bytes and fail validation. Re-roll the
	// trailing byte until it's outside the trim set; uniformity
	// over the remaining 252 byte values is fine for test KEKs.
	for {
		if _, err := rand.Read(out); err != nil {
			t.Fatalf("rand: %v", err)
		}
		switch out[len(out)-1] {
		case '\r', '\n', '\t', ' ':
			continue
		}
		return out
	}
}
