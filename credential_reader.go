package htcondor

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/droppriv"
)

// CredentialCache satisfies cedar's credential-reading hooks: ReadCredential for files
// and ListCredentialDir for token directories, both privileged via droppriv.
var (
	_ security.CredentialReader    = (*CredentialCache)(nil)
	_ security.CredentialDirLister = (*CredentialCache)(nil)
)

// condorPrivRunner adapts droppriv to cedar's security.CondorPrivRunner so cedar's FS-auth
// client creates its marker directory as the condor service account -- droppriv switches
// the effective identity for the mkdir, mirroring HTCondor's set_condor_priv(). Stateless.
// On an unprivileged process droppriv runs the mkdir under the current identity, so this is
// safe to wire onto every security config.
type condorPrivRunner struct{}

func (condorPrivRunner) RunAsCondor(fn func() error) error { return droppriv.RunAsCondor(fn) }

// daemonCondorPrivRunner is the shared FS-auth marker runner wired onto security configs.
var daemonCondorPrivRunner security.CondorPrivRunner = condorPrivRunner{}

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

// ListCredentialDir lists the entries of a credential directory as root (via
// droppriv), so a daemon that has dropped privileges can still enumerate a
// root-only, mode-0700 token directory such as SEC_TOKEN_SYSTEM_DIRECTORY
// (/etc/condor/tokens.d). It satisfies cedar's security.CredentialDirLister.
//
// Unlike ReadCredential the listing is not cached: a token directory's contents
// change as tokens are added, rotated, or removed, and the scan happens at most
// once per handshake, so a stale cached listing would cost more than it saves.
func (c *CredentialCache) ListCredentialDir(path string) ([]os.DirEntry, error) {
	f, err := droppriv.OpenAsRoot(path)
	if err != nil {
		return nil, fmt.Errorf("listing credential directory %s: %w", path, err)
	}
	entries, err := f.ReadDir(-1)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("listing credential directory %s: %w", path, err)
	}
	return entries, nil
}

// Reload drops all cached credentials so subsequent reads re-fetch the current
// on-disk bytes. Call it on reconfigure (SIGHUP) to honor rotated keys/certs.
func (c *CredentialCache) Reload() {
	c.mu.Lock()
	c.cache = make(map[string][]byte)
	c.mu.Unlock()
}
