//go:build !(darwin || dragonfly || freebsd || netbsd || openbsd)

package htcondor

import "syscall"

// platformSignalEntries is the BSD list without SIGEMT and SIGINFO, which
// Linux does not define and which the C++ table therefore does not carry
// there either. See the BSD file beside this one.
var platformSignalEntries = []signalEntry{
	{int(syscall.SIGSYS), "SIGSYS"},
	{int(syscall.SIGXCPU), "SIGXCPU"},
	{int(syscall.SIGXFSZ), "SIGXFSZ"},
}
