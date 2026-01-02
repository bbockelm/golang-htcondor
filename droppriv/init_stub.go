//go:build !linux

// Package droppriv manages raising/lowering privileges of the running process
package droppriv

func dropPrivileges(_ Identity) error {
	return ErrUnsupported
}

func restorePrivileges(_ Identity) error {
	return ErrUnsupported
}
