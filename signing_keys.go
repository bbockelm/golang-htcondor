package htcondor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/droppriv"
)

// deadbeef is the XOR mask HTCondor "scrambles" on-disk signing keys with
// (condor_auth_passwd / token signing). Reading a key back unscrambles it.
var deadbeef = []byte{0xde, 0xad, 0xbe, 0xef}

// LoadSigningKeys reads the HTCondor pool signing keys from SEC_PASSWORD_DIRECTORY,
// returning a map of key name (e.g. "POOL") to its raw (unscrambled) key bytes.
// These keys are used as key-encryption keys for at-rest encryption of derived
// secrets (e.g. the persisted CCB session cache).
//
// It returns (nil, nil) when SEC_PASSWORD_DIRECTORY is unset (no keys available).
// Unreadable individual key files are skipped (a key the daemon cannot read is
// not one it can use); a missing directory is reported as an error so a
// misconfiguration is visible.
//
// SEC_PASSWORD_DIRECTORY and its key files are root-owned (0700/0600), so the
// directory listing and each file are read as root via droppriv — matching
// HTCondor's set_priv(PRIV_ROOT) — letting a daemon that has dropped to the
// condor account still load them (a no-op re-elevation when already root).
func LoadSigningKeys(cfg *config.Config) (map[string][]byte, error) {
	dir, ok := cfg.Get("SEC_PASSWORD_DIRECTORY")
	if !ok || dir == "" {
		return nil, nil
	}
	// Open the directory as root and list it from the open fd (the permission
	// check happens at open, so the subsequent getdents runs fine post-restore).
	df, err := droppriv.OpenAsRoot(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// The directory (often a default path) simply does not exist on a
			// pool that is not using signing keys -> no keys available.
			return nil, nil
		}
		return nil, fmt.Errorf("opening SEC_PASSWORD_DIRECTORY %q: %w", dir, err)
	}
	entries, err := df.ReadDir(-1)
	_ = df.Close()
	if err != nil {
		return nil, fmt.Errorf("reading SEC_PASSWORD_DIRECTORY %q: %w", dir, err)
	}
	keys := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := readFileAsRoot(filepath.Join(dir, e.Name()))
		if err != nil || len(raw) == 0 {
			continue // skip keys we cannot read or that are empty
		}
		keys[e.Name()] = unscrambleSigningKey(raw)
	}
	return keys, nil
}

// readFileAsRoot reads an entire file as root via droppriv.
func readFileAsRoot(path string) ([]byte, error) {
	f, err := droppriv.OpenAsRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// unscrambleSigningKey reverses HTCondor's on-disk scrambling (XOR with the
// repeating 0xDEADBEEF mask).
func unscrambleSigningKey(scrambled []byte) []byte {
	out := make([]byte, len(scrambled))
	for i := range scrambled {
		out[i] = scrambled[i] ^ deadbeef[i%len(deadbeef)]
	}
	return out
}
