package sqlite

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestSharedStoreSealUnsealRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	var ss SharedStore = openStore(t, path, []SigningKey{sk("POOL", 1)})

	if ss.SharedDB() == nil {
		t.Fatal("SharedDB returned nil")
	}

	plaintext := []byte("ccb-reconnect-cookie: 0011223344556677")
	blob, err := ss.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("sealed blob leaks plaintext")
	}
	got, err := ss.Unseal(blob)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}

	// A tampered blob must fail authentication rather than return garbage.
	blob[len(blob)-1] ^= 0xff
	if _, err := ss.Unseal(blob); err == nil {
		t.Fatal("Unseal accepted a tampered blob")
	}
}
