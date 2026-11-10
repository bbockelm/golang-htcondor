//go:build libcondor_utils

package fuzzsubmit

import (
	"fmt"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// The kill-signal and periodic-policy families are compared attribute by
// attribute here rather than left to the sweep, for two reasons the sweep
// cannot cover.
//
// The signal numbers are the HOST's. SIGUSR1 is 10 on Linux and 30 on macOS,
// SIGCHLD 17 and 20, SIGIO 29 and 23, and SIGEMT/SIGINFO exist only on the
// BSDs -- so `kill_sig = 17` means a different signal on each, and a table
// that merely looks plausible passes on one platform and is wrong on the
// other. Driving every number past the end of the table against the linked
// SubmitHash is the only check that holds on both.
//
// The second is accept-versus-reject: condor_submit REFUSES a submit file
// naming a signal it does not know, and the sweep skips a file one side
// rejects rather than comparing it. Agreeing about which files are legal is
// as much a part of parity as agreeing about the ads.

// compareAttr runs one submit file through both parsers and compares a single
// attribute, failing first if the two disagree about whether the file is
// legal at all.
func compareAttr(t *testing.T, label, src, attr string) {
	t.Helper()
	cpp := oracle.MakeAds(src, oracle.ModeAds, MaxProcs)
	goRes := GoMakeAds(src)
	if cpp.OK != goRes.OK {
		t.Errorf("%s: cpp accepted=%v, go accepted=%v (go: %s) (cpp: %s)", label,
			cpp.OK, goRes.OK,
			strings.ReplaceAll(goRes.Err, "\n", " | "),
			strings.ReplaceAll(cpp.Err, "\n", " | "))
		return
	}
	if !cpp.OK {
		return
	}
	cppAds, err := ParseCanon(cpp.Ads)
	if err != nil {
		t.Fatalf("%s: malformed oracle output: %v", label, err)
	}
	for _, key := range cppAds.Keys() {
		cppVal, cppHas := lookupFold(cppAds.ByKey[key], attr)
		goAttrs, ok := goRes.Ads.ByKey[key]
		if !ok {
			t.Errorf("%s: Go produced no ad %s", label, key)
			continue
		}
		goVal, goHas := lookupFold(goAttrs, attr)
		switch {
		case cppHas != goHas:
			t.Errorf("%s: %s present cpp=%v (%s) go=%v (%s)", label, attr, cppHas, cppVal, goHas, goVal)
		case cppHas && !sameValue(cppVal, goVal):
			t.Errorf("%s: %s cpp=%s go=%s", label, attr, cppVal, goVal)
		}
	}
}

// TestKillSigNumberMatchesOracle walks past both ends of the signal table.
// Every accepted number has to come back as the same NAME the C++ gives it,
// and every number the table does not hold has to be refused by both sides.
func TestKillSigNumberMatchesOracle(t *testing.T) {
	requireOracle(t)
	for n := -5; n <= 70; n++ {
		src := fmt.Sprintf("executable = /bin/true\nkill_sig = %d\nqueue\n", n)
		compareAttr(t, fmt.Sprintf("kill_sig = %d", n), src, "KillSig")
	}
	// atoi()'s width, not Go's: a value past a 32-bit int must not wrap
	// onto a signal that happens to live at the truncated number.
	for _, big := range []string{"2147483647", "2147483648", "2147483663", "4294967311",
		"99999999999999999999", "-99999999999999999999"} {
		src := "executable = /bin/true\nkill_sig = " + big + "\nqueue\n"
		compareAttr(t, "kill_sig = "+big, src, "KillSig")
	}
}

// killSigNames covers every name HTCondor's table carries on either platform,
// the aliases and near-misses it does NOT carry (a job asking for SIGPWR is
// refused, not silently given something else), the case folding, and the
// shapes that decide whether a value is read as a number or a name at all.
var killSigNames = []string{
	"SIGKILL", "SIGCONT", "SIGTERM", "SIGQUIT", "SIGHUP", "SIGSTOP", "SIGTSTP",
	"SIGUSR1", "SIGUSR2", "SIGCHLD", "SIGABRT", "SIGALRM", "SIGFPE", "SIGILL",
	"SIGINT", "SIGPIPE", "SIGSEGV", "SIGTRAP", "SIGTTIN", "SIGTTOU", "SIGIO",
	"SIGBUS", "SIGURG", "SIGPROF", "SIGWINCH", "SIGEMT", "SIGSYS", "SIGXCPU",
	"SIGXFSZ", "SIGINFO",
	// Real signals on some host, absent from HTCondor's table.
	"SIGPWR", "SIGSTKFLT", "SIGPOLL", "SIGIOT", "SIGCLD", "SIGUNUSED", "SIGRTMIN", "SIGRTMAX",
	// The SIG prefix is part of the name.
	"TERM", "KILL", "SIG",
	// Case folds on the way in, upper-cases on the way out.
	"sigterm", "SiGtErM", "sigemt", "siginfo", "sigsys",
	// Number-or-name is decided by atoi(), so these are not what they look like.
	"0x9", "09", "+9", "9junk", "SIGTERM;", "SIGTERM ", "", " ",
}

func TestKillSigNameMatchesOracle(t *testing.T) {
	requireOracle(t)
	for _, sig := range killSigNames {
		for _, cmd := range []struct{ command, attr string }{
			{"kill_sig", "KillSig"},
			{"remove_kill_sig", "RemoveKillSig"},
			{"hold_kill_sig", "HoldKillSig"},
		} {
			src := "executable = /bin/true\n" + cmd.command + " = " + sig + "\nqueue\n"
			compareAttr(t, cmd.command+" = "+sig, src, cmd.attr)
		}
	}
}

// TestKillSigUniverseDefaultMatchesOracle pins the one default in the family.
// SetKillSig gives every universe but vanilla a KillSig of "SIGTERM" and
// gives vanilla none, leaving the starter to pick -- which for a docker or
// container job means the image's own stop signal. remove_kill_sig and
// hold_kill_sig get no default at all.
//
// `universe = standard` is left out: the C++ refuses it outright and the Go
// parser does not, which is a divergence of its own and not this one.
func TestKillSigUniverseDefaultMatchesOracle(t *testing.T) {
	requireOracle(t)
	for _, u := range []string{"vanilla", "scheduler", "local", "grid", "vm", "docker", "container"} {
		src := "executable = /bin/true\nuniverse = " + u + "\n"
		switch u {
		case "grid":
			src += "grid_resource = batch slurm\n"
		case "vm":
			src += "vm_type = kvm\nvm_memory = 128\nvm_disk = d.img:hda:w\n"
		case "docker":
			src += "docker_image = busybox\n"
		case "container":
			src += "container_image = docker://busybox\n"
		}
		src += "queue\n"
		for _, attr := range []string{"KillSig", "RemoveKillSig", "HoldKillSig"} {
			compareAttr(t, "universe = "+u+" ["+attr+"]", src, attr)
		}
		// A universe default must not overwrite what the file asked for.
		compareAttr(t, "universe = "+u+" + kill_sig",
			strings.Replace(src, "queue\n", "kill_sig = SIGINT\nqueue\n", 1), "KillSig")
	}
}

// TestKillSigTimeoutMatchesOracle: the timeout is read with atoi() rather
// than parsed, so a value that is not a number is zero and still written,
// where the Go parser used to write nothing at all.
func TestKillSigTimeoutMatchesOracle(t *testing.T) {
	requireOracle(t)
	for _, v := range []string{"30", "0", "-1", "abc", "1+2", "3.9", "99999999999999999999", "2147483648"} {
		src := "executable = /bin/true\nkill_sig_timeout = " + v + "\nqueue\n"
		compareAttr(t, "kill_sig_timeout = "+v, src, "KillSigTimeout")
	}
}

// TestPeriodicPolicyMatchesOracle drives every command SetPeriodicExpressions
// reads through the same set of values. The reasons and the subcodes are
// assigned as EXPRESSIONS exactly like the checks are, which is what makes a
// quoted reason a ClassAd string rather than a string containing quotes, a
// subcode an integer rather than text, and a value that is not an expression
// at all a rejected submit file rather than a stored one.
func TestPeriodicPolicyMatchesOracle(t *testing.T) {
	requireOracle(t)
	commands := []struct{ command, attr string }{
		{"periodic_hold", "PeriodicHold"},
		{"periodic_hold_reason", "PeriodicHoldReason"},
		{"periodic_hold_subcode", "PeriodicHoldSubCode"},
		{"periodic_release", "PeriodicRelease"},
		{"periodic_remove", "PeriodicRemove"},
		{"periodic_vacate", "PeriodicVacate"},
		{"on_exit_hold_reason", "OnExitHoldReason"},
		{"on_exit_hold_subcode", "OnExitHoldSubCode"},
	}
	values := []string{`"quoted"`, `"a b"`, `""`, `42`, `-1`, `0.5`, `1+2`, `true`, `false`,
		`ExitCode`, `undefined`, `time() > 100`, `strcat("a","b")`, `JobStatus == 5`,
		`[a=1]`, `{1,2}`, `)(`, `"unterminated`, ``, ` `}
	for _, c := range commands {
		for _, v := range values {
			src := "executable = /bin/true\n" + c.command + " = " + v + "\nqueue\n"
			compareAttr(t, c.command+" = "+v, src, c.attr)
			// Each command's alternate spelling is its own attribute
			// name, which submit_param accepts as a second key.
			alt := "executable = /bin/true\n" + c.attr + " = " + v + "\nqueue\n"
			compareAttr(t, c.attr+" = "+v, alt, c.attr)
		}
	}
}
