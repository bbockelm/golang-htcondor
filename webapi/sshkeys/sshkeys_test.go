// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sshkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb/seal"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testSealer(t *testing.T, seed byte) *seal.Sealer {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed
	}
	s, err := seal.New(key)
	if err != nil {
		t.Fatalf("seal.New: %v", err)
	}
	return s
}

// writeKeyFile drops an unencrypted ed25519 private key at path with
// the given mode and returns its fingerprint.
func writeKeyFile(t *testing.T, path string, mode os.FileMode) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	// WriteFile is subject to umask, so set the mode explicitly.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return ssh.FingerprintSHA256(signer.PublicKey())
}

func countRows(t *testing.T, db *sql.DB, purpose Purpose) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM ssh_gateway_keys WHERE purpose = ?`,
		string(purpose)).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// A key minted on first use must come back identically afterwards.
// This is the property the whole package exists for: a restart that
// changes the host key is indistinguishable from an attack.
func TestMintsOnceThenReturnsTheSameKey(t *testing.T) {
	ctx := context.Background()
	opts := Options{DB: testDB(t), Sealer: testSealer(t, 1)}

	first, err := Resolve(ctx, HostKey, opts)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if first.Source != "application database" {
		t.Errorf("source = %q, want the database", first.Source)
	}

	second, err := Resolve(ctx, HostKey, opts)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Errorf("host key changed across calls: %s then %s", first.Fingerprint, second.Fingerprint)
	}
	if n := countRows(t, opts.DB, HostKey); n != 1 {
		t.Errorf("rows = %d, want exactly 1", n)
	}
}

// The host key and the CA key are independent secrets; deriving one
// from the other would let a stolen host key forge certificates.
func TestHostAndCAAreDistinct(t *testing.T) {
	ctx := context.Background()
	opts := Options{DB: testDB(t), Sealer: testSealer(t, 2)}

	host, err := Resolve(ctx, HostKey, opts)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	ca, err := Resolve(ctx, CAKey, opts)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	if host.Fingerprint == ca.Fingerprint {
		t.Fatal("host key and CA key are the same key")
	}
}

// The public half and fingerprint stay in the clear so an operator can
// read them out of the database without starting the server.
func TestPublicHalfIsStoredInTheClear(t *testing.T) {
	ctx := context.Background()
	opts := Options{DB: testDB(t), Sealer: testSealer(t, 3)}

	key, err := Resolve(ctx, CAKey, opts)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	var pub, fp string
	if err := opts.DB.QueryRowContext(ctx,
		`SELECT public_key, fingerprint FROM ssh_gateway_keys WHERE purpose = ?`,
		string(CAKey)).Scan(&pub, &fp); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n := countRows(t, opts.DB, CAKey); n != 1 {
		t.Errorf("rows = %d, want exactly 1", n)
	}
	if fp != key.Fingerprint {
		t.Errorf("stored fingerprint %q != resolved %q", fp, key.Fingerprint)
	}
	if pub != key.Authorized {
		t.Errorf("stored public key %q != resolved %q", pub, key.Authorized)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub)); err != nil {
		t.Errorf("stored public key does not parse as an authorized_keys line: %v", err)
	}
}

// A configured file beats a stored key, and does not disturb it.
func TestFileWinsOverTheDatabase(t *testing.T) {
	ctx := context.Background()
	db, sealer := testDB(t), testSealer(t, 4)

	stored, err := Resolve(ctx, HostKey, Options{DB: db, Sealer: sealer})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "host_key")
	want := writeKeyFile(t, path, 0o600)

	got, err := Resolve(ctx, HostKey, Options{DB: db, Sealer: sealer, HostKeyFile: path})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Fingerprint != want {
		t.Errorf("fingerprint = %s, want the file's %s", got.Fingerprint, want)
	}
	if !strings.HasPrefix(got.Source, "file ") {
		t.Errorf("source = %q, want the file", got.Source)
	}

	// The stored key is left alone, so removing the file restores the
	// previous behaviour rather than losing the key.
	back, err := Resolve(ctx, HostKey, Options{DB: db, Sealer: sealer})
	if err != nil {
		t.Fatalf("resolve after: %v", err)
	}
	if back.Fingerprint != stored.Fingerprint {
		t.Errorf("stored key changed: %s then %s", stored.Fingerprint, back.Fingerprint)
	}
}

// A configured file that cannot be read is fatal. Falling back to the
// database would substitute a different key exactly when the
// operator's intent failed to load -- silently, as far as the server
// is concerned, and visibly to every client at once.
func TestConfiguredFileNeverFallsBack(t *testing.T) {
	ctx := context.Background()
	db, sealer := testDB(t), testSealer(t, 5)
	missing := filepath.Join(t.TempDir(), "absent_key")

	_, err := Resolve(ctx, HostKey, Options{DB: db, Sealer: sealer, HostKeyFile: missing})
	if err == nil {
		t.Fatal("resolve succeeded with a missing key file")
	}
	if !strings.Contains(err.Error(), "HTTP_API_SSH_HOST_KEY_FILE") {
		t.Errorf("error does not name the knob to fix: %v", err)
	}
	if n := countRows(t, db, HostKey); n != 0 {
		t.Errorf("rows = %d; a failed file load must not mint a shadow key", n)
	}
}

// A world-readable key file is refused, matching the posture
// seal.LoadMasterKEKFromFile takes on the master KEK.
func TestWorldReadableFileRefused(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "host_key")
	writeKeyFile(t, path, 0o644)

	_, err := Resolve(ctx, HostKey, Options{HostKeyFile: path})
	if err == nil {
		t.Fatal("resolve accepted a world-readable key file")
	}
	if !strings.Contains(err.Error(), "world-accessible") {
		t.Errorf("error does not explain the problem: %v", err)
	}
}

// A group-readable file is accepted: kubelet's fsGroup turns a 0400
// mounted secret into 0440, and refusing that would refuse the
// deployment shape this option exists for.
func TestGroupReadableFileAccepted(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "host_key")
	want := writeKeyFile(t, path, 0o440)

	key, err := Resolve(ctx, HostKey, Options{HostKeyFile: path})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if key.Fingerprint != want {
		t.Errorf("fingerprint = %s, want %s", key.Fingerprint, want)
	}
}

// A passphrase-protected key cannot be used by an unattended daemon,
// and the error has to say so -- ssh.ParsePrivateKey's own message
// does not suggest a fix.
func TestPassphraseProtectedFileRejectedClearly(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte("hunter2"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "host_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = Resolve(ctx, HostKey, Options{HostKeyFile: path})
	if err == nil {
		t.Fatal("resolve accepted a passphrase-protected key")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error does not mention the passphrase: %v", err)
	}
}

// THE test. A stored key that cannot be decrypted must fail the call
// and leave the row untouched. Minting a replacement would present as
// a man-in-the-middle to every client that had already connected,
// while the actual fault -- a swapped KEK file -- is recoverable.
func TestUnopenableStoredKeyIsFatalAndNeverReminted(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)

	seeded, err := Resolve(ctx, HostKey, Options{DB: db, Sealer: testSealer(t, 6)})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	var before []byte
	if err := db.QueryRowContext(ctx, `SELECT private_key FROM ssh_gateway_keys WHERE purpose = ?`,
		string(HostKey)).Scan(&before); err != nil {
		t.Fatalf("read before: %v", err)
	}

	// Same database, different KEK -- the operator swapped the file.
	_, err = Resolve(ctx, HostKey, Options{DB: db, Sealer: testSealer(t, 7)})
	if err == nil {
		t.Fatal("resolve succeeded against a key sealed under a different KEK")
	}
	if !strings.Contains(err.Error(), "HTTP_API_KEK_FILE") {
		t.Errorf("error does not name the likely cause: %v", err)
	}
	if n := countRows(t, db, HostKey); n != 1 {
		t.Fatalf("rows = %d, want the original row left in place", n)
	}
	var after []byte
	if err := db.QueryRowContext(ctx, `SELECT private_key FROM ssh_gateway_keys WHERE purpose = ?`,
		string(HostKey)).Scan(&after); err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Error("the stored key was rewritten; it must be left for the original KEK to recover")
	}

	// Restoring the original KEK recovers the original key, which is
	// the whole point of refusing.
	recovered, err := Resolve(ctx, HostKey, Options{DB: db, Sealer: testSealer(t, 6)})
	if err != nil {
		t.Fatalf("resolve with the original KEK: %v", err)
	}
	if recovered.Fingerprint != seeded.Fingerprint {
		t.Errorf("recovered %s, want the original %s", recovered.Fingerprint, seeded.Fingerprint)
	}
}

// With no file and no sealer there is nowhere to keep a stable key.
// The caller has to disable the gateway; an ephemeral in-memory key
// would change on every restart and differ between replicas.
func TestNoFileAndNoSealerIsUnavailableNotEphemeral(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"nothing configured", Options{}},
		{"database but no sealer", Options{DB: testDB(t)}},
		{"sealer but no database", Options{Sealer: testSealer(t, 8)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Resolve(ctx, HostKey, tc.opts)
			if !errors.Is(err, ErrNoKeyStore) {
				t.Fatalf("err = %v, want ErrNoKeyStore", err)
			}
			if !strings.Contains(err.Error(), "HTTP_API_SSH_HOST_KEY_FILE") ||
				!strings.Contains(err.Error(), "HTTP_API_KEK_FILE") {
				t.Errorf("error does not name both ways out: %v", err)
			}
		})
	}
}

func TestUnknownPurposeRefused(t *testing.T) {
	_, err := Resolve(context.Background(), Purpose("shell"), Options{DB: testDB(t), Sealer: testSealer(t, 9)})
	if err == nil {
		t.Fatal("resolve accepted an unknown purpose")
	}
}

// mint is reached only when no row existed a moment ago, so its
// read-back covers the window between that check and the insert: two
// processes sharing a database must converge on ONE key, and the loser
// has to serve the winner's. Calling mint directly against a database
// that already has a row is that window.
//
// Without the read-back this passes silently in a single process and
// gives two replicas two host keys in production, which no test with
// one process would ever see.
func TestMintServesTheStoredKeyWhenItLosesTheRace(t *testing.T) {
	ctx := context.Background()
	opts := Options{DB: testDB(t), Sealer: testSealer(t, 10)}

	winner, err := Resolve(ctx, HostKey, opts)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The row landed after this caller decided to mint.
	loser, err := opts.mint(ctx, HostKey)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if loser.Fingerprint != winner.Fingerprint {
		t.Errorf("mint served its own key %s; the stored %s is the one clients have",
			loser.Fingerprint, winner.Fingerprint)
	}
	if n := countRows(t, opts.DB, HostKey); n != 1 {
		t.Errorf("rows = %d, want the single stored key", n)
	}
}
