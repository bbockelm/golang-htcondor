package htcondor

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bbockelm/golang-htcondor/config"
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
func LoadSigningKeys(cfg *config.Config) (map[string][]byte, error) {
	dir, ok := cfg.Get("SEC_PASSWORD_DIRECTORY")
	if !ok || dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// The directory (often a default path) simply does not exist on a
			// pool that is not using signing keys -> no keys available.
			return nil, nil
		}
		return nil, fmt.Errorf("reading SEC_PASSWORD_DIRECTORY %q: %w", dir, err)
	}
	keys := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// G304: dir is the operator-configured SEC_PASSWORD_DIRECTORY and the
		// name comes from ReadDir of that same directory.
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec
		if err != nil {
			continue // skip keys we cannot read
		}
		if len(raw) == 0 {
			continue
		}
		keys[e.Name()] = unscrambleSigningKey(raw)
	}
	return keys, nil
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
