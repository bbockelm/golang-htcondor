//go:build linux

package droppriv

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

type threadCredentials struct {
	ruid  int
	euid  int
	suid  int
	rgid  int
	egid  int
	sgid  int
	fsuid int
	fsgid int
}

func runAsUser(target Identity, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	state, err := captureThreadCredentials()
	if err != nil {
		return err
	}

	if credentialsMatch(state, target) {
		return fn()
	}

	if err := elevateToRoot(state); err != nil {
		return err
	}

	if err := applyTargetCredentials(target); err != nil {
		_ = restoreThreadCredentials(state)
		return err
	}

	opErr := fn()
	restoreErr := restoreThreadCredentials(state)
	if opErr != nil {
		return opErr
	}
	return restoreErr
}

func captureThreadCredentials() (threadCredentials, error) {
	var ruid, euid, suid int
	//nolint:gosec // G103 - unsafe.Pointer required for syscall interface
	if _, _, errno := syscall.RawSyscall(syscall.SYS_GETRESUID,
		uintptr(unsafe.Pointer(&ruid)),
		uintptr(unsafe.Pointer(&euid)),
		uintptr(unsafe.Pointer(&suid))); errno != 0 {
		return threadCredentials{}, fmt.Errorf("getresuid failed: %w", errno)
	}

	var rgid, egid, sgid int
	//nolint:gosec // G103 - unsafe.Pointer required for syscall interface
	if _, _, errno := syscall.RawSyscall(syscall.SYS_GETRESGID,
		uintptr(unsafe.Pointer(&rgid)),
		uintptr(unsafe.Pointer(&egid)),
		uintptr(unsafe.Pointer(&sgid))); errno != 0 {
		return threadCredentials{}, fmt.Errorf("getresgid failed: %w", errno)
	}

	fsuid, _, _ := syscall.RawSyscall(syscall.SYS_SETFSUID, ^uintptr(0), 0, 0)
	fsgid, _, _ := syscall.RawSyscall(syscall.SYS_SETFSGID, ^uintptr(0), 0, 0)

	return threadCredentials{
		ruid:  ruid,
		euid:  euid,
		suid:  suid,
		rgid:  rgid,
		egid:  egid,
		sgid:  sgid,
		fsuid: int(fsuid),
		fsgid: int(fsgid),
	}, nil
}

func credentialsMatch(state threadCredentials, target Identity) bool {
	return state.euid == int(target.UID) && state.egid == int(target.GID) && state.fsuid == int(target.UID) && state.fsgid == int(target.GID)
}

func elevateToRoot(state threadCredentials) error {
	if state.euid == 0 && state.egid == 0 {
		return nil
	}

	if err := setResGID(-1, 0, -1); err != nil {
		return err
	}
	if err := setResUID(-1, 0, -1); err != nil {
		return err
	}
	return nil
}

func applyTargetCredentials(target Identity) error {
	if err := setResGID(-1, int(target.GID), -1); err != nil {
		return err
	}
	if err := setFSGID(int(target.GID)); err != nil {
		return err
	}
	if err := setResUID(-1, int(target.UID), -1); err != nil {
		return err
	}
	if err := setFSUID(int(target.UID)); err != nil {
		return err
	}
	return nil
}

func restoreThreadCredentials(state threadCredentials) error {
	var firstErr error

	if err := setResGID(-1, 0, -1); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := setResUID(-1, 0, -1); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := setFSGID(state.fsgid); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := setFSUID(state.fsuid); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := setResGID(state.rgid, state.egid, state.sgid); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := setResUID(state.ruid, state.euid, state.suid); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func setResUID(ruid, euid, suid int) error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETRESUID, toPtr(ruid), toPtr(euid), toPtr(suid)); errno != 0 {
		return fmt.Errorf("setresuid(%d,%d,%d) failed: %w", ruid, euid, suid, errno)
	}
	return nil
}

func setResGID(rgid, egid, sgid int) error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETRESGID, toPtr(rgid), toPtr(egid), toPtr(sgid)); errno != 0 {
		return fmt.Errorf("setresgid(%d,%d,%d) failed: %w", rgid, egid, sgid, errno)
	}
	return nil
}

func setFSUID(uid int) error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETFSUID, uintptr(uid), 0, 0); errno != 0 {
		return fmt.Errorf("setfsuid(%d) failed: %w", uid, errno)
	}
	return nil
}

func setFSGID(gid int) error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETFSGID, uintptr(gid), 0, 0); errno != 0 {
		return fmt.Errorf("setfsgid(%d) failed: %w", gid, errno)
	}
	return nil
}

func toPtr(id int) uintptr {
	if id < 0 {
		return ^uintptr(0)
	}
	return uintptr(id)
}
