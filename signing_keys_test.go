package htcondor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

func scramble(b []byte) []byte { return unscrambleSigningKey(b) } // XOR is its own inverse

func TestLoadSigningKeys(t *testing.T) {
	dir := t.TempDir()
	// Write two scrambled key files.
	want := map[string][]byte{
		"POOL":  []byte("pool-key-material-1234"),
		"other": []byte("another-signing-key-00"),
	}
	for name, raw := range want {
		if err := os.WriteFile(filepath.Join(dir, name), scramble(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A subdirectory must be ignored.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewEmpty()
	cfg.Set("SEC_PASSWORD_DIRECTORY", dir)

	got, err := LoadSigningKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 keys, got %d: %v", len(got), keysOf(got))
	}
	for name, raw := range want {
		if string(got[name]) != string(raw) {
			t.Errorf("key %q = %q, want %q", name, got[name], raw)
		}
	}
}

func TestLoadSigningKeysUnset(t *testing.T) {
	cfg := config.NewEmpty()
	got, err := LoadSigningKeys(cfg)
	if err != nil || got != nil {
		t.Errorf("unset SEC_PASSWORD_DIRECTORY should give (nil,nil), got (%v,%v)", got, err)
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
