package htcondor

import (
	"fmt"
	"io"
	"sync"

	"github.com/bbockelm/golang-htcondor/droppriv"
)

// CredentialCache reads credential files (the SSL server key/cert, token signing
// keys) for a daemon that has dropped privileges to a service account. It reads
// through droppriv as root — matching HTCondor's set_priv(PRIV_ROOT) — so
// root-owned 0600 credentials remain readable after the drop, and caches the
// bytes so steady-state handshakes do not pay a privilege transition and file
// read each time.
//
// It satisfies cedar's security.CredentialReader (assign it to
// SecurityConfig.Credentials). Reload clears the cache so the next read picks up
// rotated signing keys or a renewed certificate; wire it to the daemon's SIGHUP
// reconfigure so credential reloads follow HTCondor's reconfig convention.
type CredentialCache struct {
	mu    sync.RWMutex
	cache map[string][]byte
}

// NewCredentialCache returns an empty credential cache.
func NewCredentialCache() *CredentialCache {
	return &CredentialCache{cache: make(map[string][]byte)}
}

// ReadCredential returns the bytes of the credential file at path, reading it as
// root (via droppriv) on a cache miss and caching the result.
func (c *CredentialCache) ReadCredential(path string) ([]byte, error) {
	c.mu.RLock()
	b, ok := c.cache[path]
	c.mu.RUnlock()
	if ok {
		return b, nil
	}

	f, err := droppriv.OpenAsRoot(path)
	if err != nil {
		return nil, fmt.Errorf("reading credential %s: %w", path, err)
	}
	data, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("reading credential %s: %w", path, err)
	}

	c.mu.Lock()
	c.cache[path] = data
	c.mu.Unlock()
	return data, nil
}

// Reload drops all cached credentials so subsequent reads re-fetch the current
// on-disk bytes. Call it on reconfigure (SIGHUP) to honor rotated keys/certs.
func (c *CredentialCache) Reload() {
	c.mu.Lock()
	c.cache = make(map[string][]byte)
	c.mu.Unlock()
}
