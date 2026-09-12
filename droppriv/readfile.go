package droppriv

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// OpenMaybeAsRoot opens path, re-raising to root only if the ordinary
// open is refused for want of permission.
//
// This is how an HTCondor daemon reads a credential. The convention is
// root-owned and root-readable -- /etc/condor/passwords.d/POOL is
// root:root 0600, and a site's KEK or OAuth2 client secret is normally
// the same -- while the daemon itself runs as the condor account.
// condor_master starts the daemon as root, it drops to condor, and root
// stays in the saved set precisely so a read like this can re-raise for
// the length of one open.
//
// Trying the plain open first keeps the common cases untouched: a
// container running as an unprivileged user with a mounted secret, or a
// developer running the binary by hand, never touches the privilege
// machinery. Only an EACCES/EPERM leads here, and if the process was
// never root the original error is what the caller sees -- re-raising
// is not possible and pretending otherwise would replace a clear
// "permission denied" with a confusing one.
func OpenMaybeAsRoot(path string) (*os.File, error) {
	f, err := os.Open(path) //nolint:gosec // G304: credential path from operator config
	if err == nil {
		return f, nil
	}
	if !errors.Is(err, fs.ErrPermission) {
		// Not-exist, is-a-directory, and the rest are the caller's to
		// report; root would not change the answer.
		return nil, err
	}

	rf, rootErr := OpenAsRoot(path)
	if rootErr != nil {
		// Report the original denial, noting that elevating did not
		// work either, so the message names the real problem.
		return nil, fmt.Errorf("%w (and re-reading as root failed: %w)", err, rootErr)
	}
	return rf, nil
}

// ReadFileMaybeAsRoot reads path with the same rules as
// OpenMaybeAsRoot.
func ReadFileMaybeAsRoot(path string) ([]byte, error) {
	f, err := OpenMaybeAsRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}
