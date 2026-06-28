package htcondor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialCacheReadsAndCaches(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	if err := os.WriteFile(p, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewCredentialCache()
	b, err := c.ReadCredential(p)
	if err != nil {
		t.Fatalf("ReadCredential: %v", err)
	}
	if string(b) != "v1" {
		t.Errorf("got %q, want v1", b)
	}

	// Mutate the file on disk; a cached read must still return the old bytes.
	if err := os.WriteFile(p, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := c.ReadCredential(p); string(b) != "v1" {
		t.Errorf("expected cached v1, got %q", b)
	}

	// After Reload the cache is dropped and the fresh bytes are returned —
	// the reload-on-SIGHUP path for rotated keys/certs.
	c.Reload()
	if b, _ := c.ReadCredential(p); string(b) != "v2" {
		t.Errorf("after Reload expected v2, got %q", b)
	}
}

func TestCredentialCacheMissingFile(t *testing.T) {
	c := NewCredentialCache()
	if _, err := c.ReadCredential(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("expected an error reading a missing credential")
	}
}
