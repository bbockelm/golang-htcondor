package htcondor

import (
	"fmt"
	"math"
	"strings"
	"syscall"
)

// signalEntry is one row of HTCondor's signal translation table
// (src/condor_utils/sig_name.cpp).
type signalEntry struct {
	num  int
	name string
}

// signalTable is HTCondor's SigNameArray, in its order.
//
// The numbers are the *host's* signal numbers, not a portable set: SIGUSR1 is
// 10 on Linux and 30 on macOS, SIGCHLD is 17 and 20, SIGIO is 29 and 23. The
// C++ table is built from the platform's <signal.h> for exactly that reason,
// so this one is built from syscall's, and `kill_sig = 17` therefore means
// SIGCHLD on a Linux submit host and SIGSTOP on a macOS one -- the same thing
// condor_submit means by it on each.
//
// The set of names is fixed by HTCondor, not by the platform: signals the host
// has and this table does not (SIGPWR, SIGSTKFLT, SIGPOLL, SIGRTMIN, and the
// SIGIOT/SIGCLD aliases) are rejected by condor_submit, so they are absent
// here too. The two entries the C++ guards with #if defined() are in the
// per-platform files beside this one.
var signalTable = func() []signalEntry {
	t := []signalEntry{
		{int(syscall.SIGKILL), "SIGKILL"},
		{int(syscall.SIGCONT), "SIGCONT"},
		{int(syscall.SIGTERM), "SIGTERM"},
		{int(syscall.SIGQUIT), "SIGQUIT"},
		{int(syscall.SIGHUP), "SIGHUP"},
		{int(syscall.SIGSTOP), "SIGSTOP"},
		{int(syscall.SIGTSTP), "SIGTSTP"},
		{int(syscall.SIGUSR1), "SIGUSR1"},
		{int(syscall.SIGUSR2), "SIGUSR2"},
		{int(syscall.SIGCHLD), "SIGCHLD"},
		{int(syscall.SIGABRT), "SIGABRT"},
		{int(syscall.SIGALRM), "SIGALRM"},
		{int(syscall.SIGFPE), "SIGFPE"},
		{int(syscall.SIGILL), "SIGILL"},
		{int(syscall.SIGINT), "SIGINT"},
		{int(syscall.SIGPIPE), "SIGPIPE"},
		{int(syscall.SIGSEGV), "SIGSEGV"},
		{int(syscall.SIGTRAP), "SIGTRAP"},
		{int(syscall.SIGTTIN), "SIGTTIN"},
		{int(syscall.SIGTTOU), "SIGTTOU"},
		{int(syscall.SIGFPE), "SIGFPE"},
		{int(syscall.SIGIO), "SIGIO"},
		{int(syscall.SIGBUS), "SIGBUS"},
		{int(syscall.SIGURG), "SIGURG"},
		{int(syscall.SIGPROF), "SIGPROF"},
		{int(syscall.SIGWINCH), "SIGWINCH"},
	}
	return append(t, platformSignalEntries...)
}()

// signalNameByNumber is sig_name.cpp's signalName(): the first table entry
// with this number, or "" for a number the table does not carry.
func signalNameByNumber(num int) string {
	for _, e := range signalTable {
		if e.num == num {
			return e.name
		}
	}
	return ""
}

// signalNumberByName is sig_name.cpp's signalNumber(): a case-insensitive
// match on the whole name, so the SIG prefix is part of it -- condor_submit
// rejects `kill_sig = TERM`. Reports false for a name the table does not
// carry.
func signalNumberByName(name string) (int, bool) {
	for _, e := range signalTable {
		if strings.EqualFold(e.name, name) {
			return e.num, true
		}
	}
	return 0, false
}

// cAtoi is C's atoi() over a submit value: leading space, an optional sign,
// then decimal digits, stopping at the first character that is not one. No
// digits at all is 0, which is how `kill_sig = SIGTERM` reaches the name
// branch of fixupKillSigName below, and why `kill_sig = 0` does not.
//
// The width is C's. glibc's atoi is (int)strtol(), so a 64-bit overflow
// clamps to LONG_MAX/LONG_MIN and the cast then narrows that to -1 or 0 --
// neither of which any signal table holds, so an absurd number is rejected
// rather than wrapping onto a real signal.
func cAtoi(s string) int {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\v' || s[i] == '\f' || s[i] == '\r') {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	var acc int64
	overflow := false
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		d := int64(s[i] - '0')
		if acc > (math.MaxInt64-d)/10 {
			overflow = true
			break
		}
		acc = acc*10 + d
	}
	var v int64
	switch {
	case overflow && neg:
		v = math.MinInt64
	case overflow:
		v = math.MaxInt64
	case neg:
		v = -acc
	default:
		v = acc
	}
	return int(int32(v)) //nolint:gosec // G115: narrowing to a 32-bit int is the point -- it is what (int)strtol() does on the C++ side.
}

// fixupKillSigName is SubmitHash::fixupKillSigName
// (src/condor_utils/submit_utils.cpp): what condor_submit stores in KillSig,
// RemoveKillSig and HoldKillSig for a `kill_sig`-family value.
//
// The stored value is always a signal NAME, never a number: a job ad carries
// `KillSig = "SIGTERM"`, and the starter looks the name up again when it
// signals the job. Storing the number instead left an ad whose KillSig was an
// integer where every reader expects a string, so the signal the submitter
// asked for was not the one the job got.
//
// A value that is not a signal is an error rather than something stored
// as-is, which is condor_submit's behavior too -- it refuses the submit file.
func fixupKillSigName(command, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if signo := cAtoi(value); signo != 0 {
		// A number: store the name it maps to.
		name := signalNameByNumber(signo)
		if name == "" {
			return "", fmt.Errorf("%s: invalid signal %s", command, value)
		}
		return name, nil
	}
	// Not a number, so it has to be a name. The C++ stores the
	// submitter's own text upper-cased rather than the table's spelling;
	// every table name is upper-case ASCII already, so the two agree.
	if _, ok := signalNumberByName(value); !ok {
		return "", fmt.Errorf("%s: invalid signal %s", command, value)
	}
	return strings.ToUpper(value), nil
}
