//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package htcondor

import "syscall"

// platformSignalEntries holds the two rows sig_name.cpp guards with
// #if defined(SIGEMT) / #if defined(SIGINFO), which the BSDs have and Linux
// does not. The C++ table also guards SIGSYS, SIGXCPU and SIGXFSZ, but every
// platform this package builds for has those, so they sit in the common
// table.
var platformSignalEntries = []signalEntry{
	{int(syscall.SIGSYS), "SIGSYS"},
	{int(syscall.SIGXCPU), "SIGXCPU"},
	{int(syscall.SIGXFSZ), "SIGXFSZ"},
	{int(syscall.SIGEMT), "SIGEMT"},
	{int(syscall.SIGINFO), "SIGINFO"},
}
