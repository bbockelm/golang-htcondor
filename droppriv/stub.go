//go:build !linux

package droppriv

func runAsUser(_ Identity, _ func() error) error {
	return ErrUnsupported
}

// withRoot runs fn under the current identity: non-Linux platforms have no
// per-thread privilege model, so there is no elevation to perform.
func withRoot(fn func() error) error {
	return fn()
}
