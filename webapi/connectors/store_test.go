package connectors

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb/seal"
)

func newTestStore(t *testing.T, sealed bool) (*Store, *sql.DB) {
	t.Helper()
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var sealer *seal.Sealer
	if sealed {
		key := bytes.Repeat([]byte{7}, 32)
		sealer, err = seal.New(key)
		if err != nil {
			t.Fatalf("seal.New: %v", err)
		}
	}
	return NewStore(db, sealer), db
}

func mustPut(t *testing.T, s *Store, c Stored, secret []byte) {
	t.Helper()
	if err := s.PutConnector(context.Background(), c, secret); err != nil {
		t.Fatalf("PutConnector: %v", err)
	}
}

func sampleConnector() Stored {
	return Stored{
		ID:       MustParse("site:cryoem"),
		Kind:     KindOAuth2,
		ClientID: "client-123",
		Groups:   []string{"smith_lab"},
		Enabled:  true,
	}
}

func TestConnectorRoundTrip(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()

	in := sampleConnector()
	in.AuthorizationURL = "https://example.org/auth"
	in.TokenURL = "https://example.org/token" //nolint:gosec // G101: a test endpoint
	in.Scopes = []string{"read", "write"}
	mustPut(t, s, in, []byte("s3cret"))

	got, found, err := s.Connector(ctx, in.ID)
	if err != nil || !found {
		t.Fatalf("Connector: found=%v err=%v", found, err)
	}
	if got.ID != in.ID || got.Kind != in.Kind || got.ClientID != in.ClientID {
		t.Errorf("got %+v, want the stored values", got)
	}
	if len(got.Scopes) != 2 || len(got.Groups) != 1 {
		t.Errorf("scopes=%v groups=%v", got.Scopes, got.Groups)
	}
	// Transfer defaults rather than coming back empty.
	if got.Transfer != TransferSpool {
		t.Errorf("Transfer = %q, want spool", got.Transfer)
	}
}

// Stored carries no secret, by construction. A struct with a secret
// field is a struct that ends up in a JSON response the first time
// somebody adds an endpoint.
func TestStoredCarriesNoSecretOnlyWhetherOneIsSet(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()

	mustPut(t, s, sampleConnector(), []byte("s3cret"))
	got, _, _ := s.Connector(ctx, MustParse("site:cryoem"))

	if !got.SecretSet {
		t.Error("SecretSet = false after storing one")
	}
	if got.SecretUpdatedAt.IsZero() {
		t.Error("SecretUpdatedAt is zero; the page shows this instead of the secret")
	}
	// The only way to the bytes is the call named for it.
	secret, err := s.ClientSecret(ctx, MustParse("site:cryoem"))
	if err != nil {
		t.Fatalf("ClientSecret: %v", err)
	}
	if string(secret) != "s3cret" {
		t.Errorf("ClientSecret = %q", secret)
	}
}

// nil secret means unchanged; an empty slice means clear. A form that
// round-tripped an absent field as "" would wipe a working connector's
// secret on an unrelated edit.
func TestNilSecretLeavesTheStoredOneAlone(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()
	id := MustParse("site:cryoem")

	mustPut(t, s, sampleConnector(), []byte("original"))

	edited := sampleConnector()
	edited.ClientID = "client-456"
	mustPut(t, s, edited, nil) // an unrelated edit

	got, _, _ := s.Connector(ctx, id)
	if got.ClientID != "client-456" {
		t.Errorf("the edit did not take: ClientID = %q", got.ClientID)
	}
	secret, err := s.ClientSecret(ctx, id)
	if err != nil {
		t.Fatalf("the secret was lost by an unrelated edit: %v", err)
	}
	if string(secret) != "original" {
		t.Errorf("ClientSecret = %q, want it unchanged", secret)
	}
}

func TestEmptySecretClearsIt(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()
	id := MustParse("site:cryoem")

	mustPut(t, s, sampleConnector(), []byte("original"))
	mustPut(t, s, sampleConnector(), []byte{}) // explicit clear

	got, _, _ := s.Connector(ctx, id)
	if got.SecretSet {
		t.Error("SecretSet is still true after an explicit clear")
	}
	if _, err := s.ClientSecret(ctx, id); err == nil {
		t.Error("ClientSecret returned one after it was cleared")
	}
}

// --- sealing ----------------------------------------------------------

func TestSecretsAreSealedOnDisk(t *testing.T) {
	s, db := newTestStore(t, true)
	ctx := context.Background()
	id := MustParse("site:cryoem")

	mustPut(t, s, sampleConnector(), []byte("s3cret"))

	var data, dek []byte
	if err := db.QueryRowContext(ctx,
		`SELECT client_secret, client_secret_dek FROM connectors WHERE id = ?`,
		id.String()).Scan(&data, &dek); err != nil {
		t.Fatal(err)
	}
	if len(dek) == 0 {
		t.Fatal("no wrapped data key; the secret was stored in the clear")
	}
	if bytes.Contains(data, []byte("s3cret")) {
		t.Fatal("the plaintext secret is in the database")
	}

	// And it comes back.
	got, err := s.ClientSecret(ctx, id)
	if err != nil || string(got) != "s3cret" {
		t.Errorf("ClientSecret = %q, %v", got, err)
	}
}

// A sealed row read by a server with no KEK is refused, not guessed at.
// Treating the ciphertext as plaintext would send it to a provider as if
// it were the secret.
func TestSealedValueWithoutAKEKIsRefused(t *testing.T) {
	sealed, db := newTestStore(t, true)
	ctx := context.Background()
	id := MustParse("site:cryoem")
	mustPut(t, sealed, sampleConnector(), []byte("s3cret"))

	unsealed := NewStore(db, nil)
	_, err := unsealed.ClientSecret(ctx, id)
	if !errors.Is(err, ErrNoKEK) {
		t.Fatalf("err = %v, want ErrNoKEK", err)
	}
}

func TestRefreshTokenIsSealedToo(t *testing.T) {
	s, db := newTestStore(t, true)
	ctx := context.Background()
	id := MustParse("site:cryoem")
	mustPut(t, s, sampleConnector(), nil)

	if err := s.PutCredential(ctx, Credential{Subject: "alice", Connector: id},
		[]byte("refresh-abc")); err != nil {
		t.Fatalf("PutCredential: %v", err)
	}

	var data []byte
	if err := db.QueryRowContext(ctx,
		`SELECT refresh_token FROM connector_credentials WHERE subject = ?`,
		"alice").Scan(&data); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("refresh-abc")) {
		t.Fatal("the plaintext refresh token is in the database")
	}
	got, err := s.RefreshToken(ctx, "alice", id)
	if err != nil || string(got) != "refresh-abc" {
		t.Errorf("RefreshToken = %q, %v", got, err)
	}
}

// --- credentials ------------------------------------------------------

func TestPutCredentialRefusesAnEmptyToken(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()
	id := MustParse("site:cryoem")
	mustPut(t, s, sampleConnector(), nil)

	for _, token := range [][]byte{nil, {}} {
		err := s.PutCredential(ctx, Credential{Subject: "alice", Connector: id}, token)
		if err == nil {
			t.Fatalf("an empty refresh token (%v) was stored; it would read back "+
				"as a live grant", token)
		}
		// The column is NOT NULL, so the database would refuse this too
		// -- but with a constraint violation, which names neither the
		// connector nor the user. Assert on the guard's message, or this
		// test passes while testing the schema instead of the code.
		if !strings.Contains(err.Error(), "refresh token") ||
			!strings.Contains(err.Error(), "alice") {
			t.Errorf("error = %q, want it to name the refresh token and the user", err)
		}
	}
}

func TestMarkUsedAndCount(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()
	id := MustParse("site:cryoem")
	mustPut(t, s, sampleConnector(), nil)

	for _, who := range []string{"alice", "bob"} {
		if err := s.PutCredential(ctx, Credential{Subject: who, Connector: id},
			[]byte("r-"+who)); err != nil {
			t.Fatal(err)
		}
	}

	users, lastUsed, err := s.CountCredentials(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if users != 2 {
		t.Errorf("users = %d, want 2", users)
	}
	if !lastUsed.IsZero() {
		t.Errorf("lastUsed = %v before anybody used it", lastUsed)
	}

	when := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return when }
	if err := s.MarkUsed(ctx, "alice", id); err != nil {
		t.Fatal(err)
	}

	_, lastUsed, _ = s.CountCredentials(ctx, id)
	if lastUsed.IsZero() {
		t.Error("last use was not recorded; a connector cannot report whether anyone uses it")
	}

	cred, found, err := s.Credential(ctx, "alice", id)
	if err != nil || !found {
		t.Fatalf("Credential: found=%v err=%v", found, err)
	}
	if cred.LastUsedAt.IsZero() {
		t.Error("the credential does not carry its last use")
	}
}

// --- revoke vs delete -------------------------------------------------

// Revoke drops grants and leaves the connector. It is what to do when a
// client secret has leaked: the stored tokens were issued to the old
// registration and users have to consent again.
func TestRevokeDropsGrantsAndKeepsTheConnector(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()
	id := MustParse("site:cryoem")
	mustPut(t, s, sampleConnector(), []byte("s3cret"))
	for _, who := range []string{"alice", "bob"} {
		if err := s.PutCredential(ctx, Credential{Subject: who, Connector: id},
			[]byte("r")); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.RevokeConnector(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("revoked %d, want 2", n)
	}
	if _, found, _ := s.Connector(ctx, id); !found {
		t.Error("revoke removed the connector; that is delete's job")
	}
	if _, found, _ := s.Credential(ctx, "alice", id); found {
		t.Error("a grant survived revoke")
	}
}

// Delete takes the credentials with it and says how many, because a
// credential whose connector is gone is unreachable: nothing lists it,
// nothing refreshes it, and nobody can revoke it.
func TestDeleteTakesTheCredentialsAndReportsTheCount(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()
	id := MustParse("site:cryoem")
	mustPut(t, s, sampleConnector(), []byte("s3cret"))
	for _, who := range []string{"alice", "bob", "carol"} {
		if err := s.PutCredential(ctx, Credential{Subject: who, Connector: id},
			[]byte("r")); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.DeleteConnector(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("DeleteConnector reported %d credentials, want 3", n)
	}
	if _, found, _ := s.Connector(ctx, id); found {
		t.Error("the connector survived delete")
	}

	users, _, _ := s.CountCredentials(ctx, id)
	if users != 0 {
		t.Errorf("%d credentials were orphaned by the delete", users)
	}
}

// --- validation -------------------------------------------------------

func TestPutConnectorRefusesABadKindOrTransfer(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()

	bad := sampleConnector()
	bad.Kind = "something"
	if err := s.PutConnector(ctx, bad, nil); err == nil {
		t.Error("an unknown kind was stored")
	}

	bad = sampleConnector()
	bad.Transfer = "teleport"
	if err := s.PutConnector(ctx, bad, nil); err == nil {
		t.Error("an unknown transfer mode was stored")
	}
}

func TestPutConnectorRefusesABadID(t *testing.T) {
	s, _ := newTestStore(t, false)
	bad := sampleConnector()
	bad.ID = ID{Namespace: "vendor", Name: "thing"}
	if err := s.PutConnector(context.Background(), bad, nil); err == nil {
		t.Error("a connector in an unknown namespace was stored")
	}
}

func TestUpdateKeepsCreatedAt(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()
	id := MustParse("site:cryoem")

	mustPut(t, s, sampleConnector(), nil)
	first, _, _ := s.Connector(ctx, id)

	s.now = func() time.Time { return first.CreatedAt.Add(time.Hour) }
	edited := sampleConnector()
	edited.ClientID = "later"
	mustPut(t, s, edited, nil)

	got, _, _ := s.Connector(ctx, id)
	if !got.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("CreatedAt moved on update: %v -> %v", first.CreatedAt, got.CreatedAt)
	}
	if !got.UpdatedAt.After(first.UpdatedAt) {
		t.Errorf("UpdatedAt did not move: %v", got.UpdatedAt)
	}
}

func TestConnectorsListsInIDOrder(t *testing.T) {
	s, _ := newTestStore(t, false)
	ctx := context.Background()
	for _, id := range []string{"site:zeta", "builtin:gdrive", "site:alpha"} {
		c := sampleConnector()
		c.ID = MustParse(id)
		mustPut(t, s, c, nil)
	}
	got, err := s.Connectors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("listed %d", len(got))
	}
	want := []string{"builtin:gdrive", "site:alpha", "site:zeta"}
	for i, w := range want {
		if got[i].ID.String() != w {
			t.Errorf("[%d] = %s, want %s", i, got[i].ID, w)
		}
	}
}

func TestNilStoreIsSafe(t *testing.T) {
	var s *Store
	ctx := context.Background()
	if _, found, err := s.Connector(ctx, MustParse("site:x")); found || err != nil {
		t.Errorf("Connector on a nil store: found=%v err=%v", found, err)
	}
	if list, err := s.Connectors(ctx); list != nil || err != nil {
		t.Errorf("Connectors on a nil store: %v %v", list, err)
	}
	if err := s.MarkUsed(ctx, "alice", MustParse("site:x")); err != nil {
		t.Errorf("MarkUsed on a nil store: %v", err)
	}
}
