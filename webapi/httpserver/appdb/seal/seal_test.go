package seal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestRoundtrip exercises the basic seal/open contract: for any
// plaintext, Open(Seal(plaintext)) == plaintext, and the wrapped DEK
// is unique per call (no key reuse across rows).
func TestRoundtrip(t *testing.T) {
	dbKey := mustRandom32(t)
	s, err := New(dbKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	plaintexts := [][]byte{
		[]byte(""),
		[]byte("hello"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"),
		bytes.Repeat([]byte{0xff}, 4096),
	}
	seenDEKs := map[string]bool{}
	for _, pt := range plaintexts {
		data, dek, err := s.Seal(pt)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if seenDEKs[string(dek)] {
			t.Errorf("Seal reused a wrapped DEK across rows; that defeats per-row isolation")
		}
		seenDEKs[string(dek)] = true

		got, err := s.Open(data, dek)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("Open returned %d bytes, want %d (roundtrip mismatch)", len(got), len(pt))
		}
	}
}

// TestOpenRejectsTampering confirms AES-GCM's authenticator catches
// modification of either the data or the wrapped DEK. The whole
// reason we use AEAD here vs. raw AES is to detect this.
func TestOpenRejectsTampering(t *testing.T) {
	s, _ := New(mustRandom32(t))
	data, dek, err := s.Seal([]byte("the secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flip a bit in the data ciphertext.
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := s.Open(tampered, dek); err == nil {
		t.Errorf("Open accepted tampered data; AEAD broken")
	}

	// Flip a bit in the wrapped DEK.
	tamperedDEK := append([]byte(nil), dek...)
	tamperedDEK[len(tamperedDEK)-1] ^= 0x01
	if _, err := s.Open(data, tamperedDEK); err == nil {
		t.Errorf("Open accepted tampered wrapped DEK; AEAD broken")
	}
}

// TestOpenRejectsWrongKEK confirms that data sealed with one DB KEK
// cannot be opened with a different one. This is the failure mode an
// operator would hit if they swapped the KEK file between deploys —
// we want a clear authentication error, not a silent garbage-out.
func TestOpenRejectsWrongKEK(t *testing.T) {
	s1, _ := New(mustRandom32(t))
	s2, _ := New(mustRandom32(t))
	data, dek, err := s1.Seal([]byte("crown jewels"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := s2.Open(data, dek); err == nil {
		t.Errorf("Open accepted ciphertext under a different KEK; should have failed")
	}
}

// TestDeriveDBKeyDeterministic pins the contract that re-deriving
// from the same master + salt yields the same DB key — that's what
// makes the design recoverable: an operator who restarts the server
// and provides the same master KEK gets back the same DB KEK and
// can read the same encrypted rows.
func TestDeriveDBKeyDeterministic(t *testing.T) {
	master := mustRandom32(t)
	salt := mustRandom32(t)

	a, err := DeriveDBKey(master, salt)
	if err != nil {
		t.Fatalf("DeriveDBKey: %v", err)
	}
	b, err := DeriveDBKey(master, salt)
	if err != nil {
		t.Fatalf("DeriveDBKey (2nd): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("DeriveDBKey is non-deterministic; that breaks restart recovery")
	}
}

// TestDeriveDBKeyDifferentSalts confirms the derived key changes
// with the salt, which is the whole point of having a per-DB salt.
func TestDeriveDBKeyDifferentSalts(t *testing.T) {
	master := mustRandom32(t)
	a, _ := DeriveDBKey(master, mustRandom32(t))
	b, _ := DeriveDBKey(master, mustRandom32(t))
	if bytes.Equal(a, b) {
		t.Errorf("DeriveDBKey returned identical keys for different salts")
	}
}

// TestLoadMasterKEKFromFile covers the three accepted formats: raw
// bytes at exactly the right length, hex-encoded with trailing
// newline (the openssl-rand-hex case), and the rejection path for
// anything else.
func TestLoadMasterKEKFromFile(t *testing.T) {
	dir := t.TempDir()

	// Raw 32 bytes.
	rawPath := filepath.Join(dir, "raw")
	rawBytes := bytes.Repeat([]byte{'a'}, MasterKEKBytes)
	if err := os.WriteFile(rawPath, rawBytes, 0o600); err != nil {
		t.Fatalf("write raw: %v", err)
	}
	got, err := LoadMasterKEKFromFile(rawPath)
	if err != nil {
		t.Errorf("raw: %v", err)
	}
	if !bytes.Equal(got, rawBytes) {
		t.Errorf("raw: roundtrip mismatch")
	}

	// Hex with trailing newline.
	hexPath := filepath.Join(dir, "hex")
	want := mustRandom32(t)
	hexed := hex.EncodeToString(want) + "\n"
	if err := os.WriteFile(hexPath, []byte(hexed), 0o600); err != nil {
		t.Fatalf("write hex: %v", err)
	}
	got, err = LoadMasterKEKFromFile(hexPath)
	if err != nil {
		t.Errorf("hex: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("hex: roundtrip mismatch")
	}

	// Wrong length: 16 bytes, neither raw-32 nor hex-of-32.
	shortPath := filepath.Join(dir, "short")
	if err := os.WriteFile(shortPath, []byte("abcdefgh"), 0o600); err != nil {
		t.Fatalf("write short: %v", err)
	}
	if _, err := LoadMasterKEKFromFile(shortPath); err == nil {
		t.Errorf("short: expected error for wrong-length file")
	}
}

// TestLoadMasterKEKFromFileMissingFileNeverCreates pins the policy
// that a missing KEK file is a fatal error, NEVER an opportunity to
// auto-generate one. This is critical for container deployments: a
// freshly-generated KEK on an unmounted/emptyDir path would silently
// invent a new key on every restart, the DB-instance KEK would no
// longer match what's in kek_metadata, and every wrapped DEK in the
// DB would become un-openable — losing the OAuth2 / IDP signing
// keys + every encrypted secret.
//
// The test asserts: the error mentions "does not exist" (so the
// operator knows to provide a file), AND no file appears at the
// requested path after the call.
func TestLoadMasterKEKFromFileMissingFileNeverCreates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist")

	_, err := LoadMasterKEKFromFile(path)
	if err == nil {
		t.Fatalf("LoadMasterKEKFromFile returned nil error for missing file; should be a hard error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("does not exist")) {
		t.Errorf("error %q does not mention 'does not exist'; operator can't tell what to do", err.Error())
	}
	if !bytes.Contains([]byte(err.Error()), []byte("openssl")) {
		t.Errorf("error %q does not include the openssl generation hint", err.Error())
	}
	// Assert the file was NOT created as a side effect.
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("LoadMasterKEKFromFile created %s as a side effect; never-create policy violated", path)
	}
}

// TestLoadMasterKEKFromFileRejectsLoosePerms guards against an
// operator mistake: a world-readable KEK file effectively isn't a
// secret. We want a hard fail, not a warning, so the misconfiguration
// is caught at startup.
func TestLoadMasterKEKFromFileRejectsLoosePerms(t *testing.T) {
	if os.Getuid() == 0 {
		// Root can read any file; the Stat check is best-effort
		// against operator error, not a security boundary against
		// a privileged attacker. Skip rather than spuriously fail.
		t.Skip("running as root; perm enforcement not meaningful")
	}
	path := filepath.Join(t.TempDir(), "loose")
	// 0o644 is exactly what we want this test to reject — the
	// LoadMasterKEKFromFile call below MUST refuse it. Suppress
	// gosec G306 because the loose mode is the test fixture, not a
	// production path.
	if err := os.WriteFile(path, bytes.Repeat([]byte{'k'}, MasterKEKBytes), 0o644); err != nil { //nolint:gosec // intentional loose perms; test fixture asserts they are rejected
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadMasterKEKFromFile(path); err == nil {
		t.Errorf("LoadMasterKEKFromFile accepted a 0644 KEK file; should refuse")
	}
}

// TestLoadMasterKEKFromFileAcceptsGroupRead pins the policy that
// group-read alone is acceptable. Kubelet applies fsGroup to Secret
// volume mounts and forces group-read on every file (defaultMode
// 0400 ends up as 0440). Rejecting that mode would force every
// operator into init-container workarounds, with no real security
// gain since the "group" there is the pod's own fsgroup.
func TestLoadMasterKEKFromFileAcceptsGroupRead(t *testing.T) {
	if os.Getuid() == 0 {
		// Root can read any file; perm enforcement isn't meaningful.
		t.Skip("running as root; perm enforcement not meaningful")
	}
	path := filepath.Join(t.TempDir(), "group-read")
	// 0o440 is the mode kubelet+fsGroup produces for Secret mounts and
	// is exactly what this test asserts the loader accepts. Suppress
	// gosec G306: the loose-by-policy mode is the fixture, not a leak.
	if err := os.WriteFile(path, bytes.Repeat([]byte{'k'}, MasterKEKBytes), 0o440); err != nil { //nolint:gosec // intentional 0440; test fixture for kubelet+fsGroup case
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadMasterKEKFromFile(path); err != nil {
		t.Errorf("LoadMasterKEKFromFile rejected a 0440 KEK file: %v; should accept (kubelet+fsGroup case)", err)
	}
}

// mustRandom32 returns 32 random bytes — the size used for every
// key-shaped value in this package (master KEK, derived KEK, DEK,
// HKDF salt all happen to be 32). Earlier this function took a
// length but every call site passed 32; unparam flagged the dead
// parameter, so the simpler signature is also more honest.
func mustRandom32(t *testing.T) []byte {
	t.Helper()
	out := make([]byte, 32)
	if _, err := rand.Read(out); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return out
}
