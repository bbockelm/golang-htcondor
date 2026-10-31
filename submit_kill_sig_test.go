package htcondor

import (
	"strings"
	"testing"
)

// adFor parses one submit file and returns proc 0's job ad.
func adFor(t *testing.T, src string) map[string]string {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd %q: %v", src, err)
	}
	out := map[string]string{}
	for _, name := range ad.GetAttributes() {
		if expr, ok := ad.Lookup(name); ok && expr != nil {
			out[name] = expr.String()
		}
	}
	return out
}

func mustReject(t *testing.T, src string) {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		return
	}
	if _, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil); err == nil {
		t.Errorf("%q was accepted; condor_submit refuses it", strings.TrimSpace(src))
	}
}

// TestKillSigIsAlwaysAName pins what the kill-signal family stores.
//
// KillSig, RemoveKillSig and HoldKillSig hold a signal NAME. The starter
// reads the attribute as a string and looks the name up again, so an ad
// carrying `KillSig = 15` -- which is what this parser used to write for
// `kill_sig = SIGTERM` -- does not name a signal the starter can find, and the
// job is killed with the default instead of the one the submitter chose.
//
// Only numbers that are the same signal on every platform this builds for are
// asserted; the per-platform table is checked against HTCondor's own in
// fuzz/submit/killsig_periodic_test.go.
func TestKillSigIsAlwaysAName(t *testing.T) {
	for value, want := range map[string]string{
		"SIGTERM": `"SIGTERM"`,
		"SIGKILL": `"SIGKILL"`,
		// The lookup folds case; the stored name is upper-cased.
		"sigterm": `"SIGTERM"`,
		"SiGkIlL": `"SIGKILL"`,
		// A number is translated to the name it stands for.
		"1":  `"SIGHUP"`,
		"2":  `"SIGINT"`,
		"3":  `"SIGQUIT"`,
		"6":  `"SIGABRT"`,
		"9":  `"SIGKILL"`,
		"13": `"SIGPIPE"`,
		"14": `"SIGALRM"`,
		"15": `"SIGTERM"`,
		// atoi() reads the leading digits and stops, so this is 15.
		"15junk": `"SIGTERM"`,
		// ...and is decimal, so this is 15 rather than 13.
		"015": `"SIGTERM"`,
	} {
		ad := adFor(t, "executable = /bin/true\nkill_sig = "+value+"\nqueue\n")
		if got := ad["KillSig"]; got != want {
			t.Errorf("kill_sig = %s: KillSig = %s, want %s", value, got, want)
		}
	}
}

// TestKillSigRejectsWhatCondorSubmitRejects: an unknown signal makes
// condor_submit refuse the file. Storing it as a string instead would leave a
// job whose KillSig names nothing.
func TestKillSigRejectsWhatCondorSubmitRejects(t *testing.T) {
	for _, value := range []string{
		"TERM",      // the SIG prefix is part of the name
		"SIGPWR",    // a real signal HTCondor's table does not carry
		"SIGPOLL",   // ditto, and an alias of one it does
		"SIGRTMIN",  // ditto
		"abc",       // not a signal at all
		"0",         // atoi()'s zero falls to the name lookup, which fails
		"999",       // past the end of every table
		"-9",        // signalName() has no negative entries
		"0x9",       // atoi() does not read hex
		"SIGTERM;",  // the name has to match exactly
		"999999999", // ...
	} {
		mustReject(t, "executable = /bin/true\nkill_sig = "+value+"\nqueue\n")
		mustReject(t, "executable = /bin/true\nremove_kill_sig = "+value+"\nqueue\n")
		mustReject(t, "executable = /bin/true\nhold_kill_sig = "+value+"\nqueue\n")
	}
}

// TestKillSigUniverseDefault pins SetKillSig's one default and its one
// exception. A vanilla job gets no KillSig, so the starter picks -- for a
// docker or container job, the image's own stop signal. Every other universe
// gets "SIGTERM", without which the shadow has no signal to send on
// condor_rm. remove_kill_sig and hold_kill_sig have no default.
func TestKillSigUniverseDefault(t *testing.T) {
	for universe, want := range map[string]string{
		"vanilla":   "",
		"docker":    "",
		"container": "",
		"scheduler": `"SIGTERM"`,
		"local":     `"SIGTERM"`,
		"grid":      `"SIGTERM"`,
		"vm":        `"SIGTERM"`,
	} {
		src := "executable = /bin/true\nuniverse = " + universe + "\n"
		switch universe {
		case "grid":
			src += "grid_resource = batch slurm\n"
		case "vm":
			src += "vm_type = kvm\nvm_memory = 128\nvm_disk = d.img:hda:w\n"
		case "docker":
			src += "docker_image = busybox\n"
		case "container":
			src += "container_image = docker://busybox\n"
		}
		ad := adFor(t, src+"queue\n")
		if got := ad["KillSig"]; got != want {
			t.Errorf("universe = %s: KillSig = %q, want %q", universe, got, want)
		}
		if got, ok := ad["RemoveKillSig"]; ok {
			t.Errorf("universe = %s: RemoveKillSig = %s, want it unset", universe, got)
		}
		if got, ok := ad["HoldKillSig"]; ok {
			t.Errorf("universe = %s: HoldKillSig = %s, want it unset", universe, got)
		}

		// The default must not overwrite what the file asked for.
		ad = adFor(t, src+"kill_sig = SIGINT\nqueue\n")
		if got := ad["KillSig"]; got != `"SIGINT"` {
			t.Errorf("universe = %s with kill_sig = SIGINT: KillSig = %s", universe, got)
		}
	}
}

// TestKillSigFamilyAlternateSpellings: each command's second accepted key is
// its own job attribute name, which is what submit_param(key, attr) means.
func TestKillSigFamilyAlternateSpellings(t *testing.T) {
	ad := adFor(t, "executable = /bin/true\n"+
		"KillSig = SIGQUIT\nRemoveKillSig = SIGUSR1\nHoldKillSig = SIGUSR2\nKillSigTimeout = 7\nqueue\n")
	for attr, want := range map[string]string{
		"KillSig":        `"SIGQUIT"`,
		"RemoveKillSig":  `"SIGUSR1"`,
		"HoldKillSig":    `"SIGUSR2"`,
		"KillSigTimeout": "7",
	} {
		if got := ad[attr]; got != want {
			t.Errorf("%s = %s, want %s", attr, got, want)
		}
	}
}

// TestKillSigTimeoutIsAtoi: SetKillSig reads the timeout with atoi() and
// writes it whenever the command is present, so a value that is not a number
// is a zero timeout rather than no attribute.
func TestKillSigTimeoutIsAtoi(t *testing.T) {
	for value, want := range map[string]string{
		"30":  "30",
		"0":   "0",
		"-1":  "-1",
		"abc": "0",
		"3.9": "3",
		"1+2": "1",
	} {
		ad := adFor(t, "executable = /bin/true\nkill_sig_timeout = "+value+"\nqueue\n")
		if got := ad["KillSigTimeout"]; got != want {
			t.Errorf("kill_sig_timeout = %s: KillSigTimeout = %q, want %s", value, got, want)
		}
	}
}

// TestPeriodicReasonsAndSubcodesAreExpressions pins the other half of
// SetPeriodicExpressions. The reasons and subcodes are assigned as
// expressions, like the checks beside them, so a quoted reason is a ClassAd
// string and not a string whose own text begins and ends with a quote -- the
// quotes used to reach condor_q -hold and the HoldReason the schedd copies
// onto the job -- and a subcode is the number a policy expression comparing
// against it needs.
func TestPeriodicReasonsAndSubcodesAreExpressions(t *testing.T) {
	ad := adFor(t, "executable = /bin/true\n"+
		"periodic_hold_reason = \"too slow\"\n"+
		"periodic_hold_subcode = 42\n"+
		"on_exit_hold_reason = strcat(\"exit \", ExitCode)\n"+
		"on_exit_hold_subcode = ExitCode\n"+
		"periodic_vacate = time() - EnteredCurrentStatus > 600\n"+
		"queue\n")
	for attr, want := range map[string]string{
		"PeriodicHoldReason":  `"too slow"`,
		"PeriodicHoldSubCode": "42",
		"OnExitHoldReason":    `strcat("exit ", ExitCode)`,
		"OnExitHoldSubCode":   "ExitCode",
		"PeriodicVacate":      "((time() - EnteredCurrentStatus) > 600)",
	} {
		if got := ad[attr]; got != want {
			t.Errorf("%s = %s, want %s", attr, got, want)
		}
	}
}

// TestPeriodicFamilyAlternateSpellings covers the attribute-name spelling of
// every command SetPeriodicExpressions reads.
func TestPeriodicFamilyAlternateSpellings(t *testing.T) {
	ad := adFor(t, "executable = /bin/true\n"+
		"PeriodicHold = JobStatus == 1\n"+
		"PeriodicHoldReason = \"r\"\n"+
		"PeriodicHoldSubCode = 3\n"+
		"PeriodicRelease = false\n"+
		"PeriodicRemove = false\n"+
		"PeriodicVacate = false\n"+
		"OnExitHoldReason = \"e\"\n"+
		"OnExitHoldSubCode = 4\n"+
		"queue\n")
	for attr, want := range map[string]string{
		"PeriodicHold":        "(JobStatus == 1)",
		"PeriodicHoldReason":  `"r"`,
		"PeriodicHoldSubCode": "3",
		"PeriodicRelease":     "false",
		"PeriodicRemove":      "false",
		"PeriodicVacate":      "false",
		"OnExitHoldReason":    `"e"`,
		"OnExitHoldSubCode":   "4",
	} {
		if got := ad[attr]; got != want {
			t.Errorf("%s = %s, want %s", attr, got, want)
		}
	}
}

// TestPeriodicPolicyRejectsNonExpressions: a periodic value that is not a
// ClassAd expression makes condor_submit refuse the file rather than store
// the text.
func TestPeriodicPolicyRejectsNonExpressions(t *testing.T) {
	for _, command := range []string{"periodic_hold", "periodic_hold_reason",
		"periodic_hold_subcode", "periodic_release", "periodic_remove",
		"periodic_vacate", "on_exit_hold_reason", "on_exit_hold_subcode"} {
		mustReject(t, "executable = /bin/true\n"+command+" = )(\nqueue\n")
		mustReject(t, "executable = /bin/true\n"+command+" = \"unterminated\nqueue\n")
	}
}

func TestCAtoiMatchesC(t *testing.T) {
	for in, want := range map[string]int{
		"":                      0,
		"  ":                    0,
		"abc":                   0,
		"15":                    15,
		" 15 ":                  15,
		"+15":                   15,
		"-15":                   -15,
		"015":                   15,
		"15abc":                 15,
		"0x9":                   0,
		"3.9":                   3,
		"1+2":                   1,
		"2147483647":            2147483647,
		"2147483648":            -2147483648, // (int) of a value past INT_MAX
		"4294967311":            15,          // ...which can land on a real signal
		"99999999999999999999":  -1,          // strtol clamps to LONG_MAX, (int) of which is -1
		"-99999999999999999999": 0,           // ...and to LONG_MIN, (int) of which is 0
		"9223372036854775807":   -1,
		"-9223372036854775808":  0,
		"000000000000000000015": 15,
	} {
		if got := cAtoi(in); got != want {
			t.Errorf("cAtoi(%q) = %d, want %d", in, got, want)
		}
	}
}
