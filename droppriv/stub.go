//go:build !linux

package droppriv

func runAsUser(_ Identity, _ func() error) error {
	return ErrUnsupported
}
