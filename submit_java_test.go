package htcondor

import (
	"strings"
	"testing"
)

// TestJavaUniverseRunsTheJVM pins the rewrite that makes a java job runnable.
//
// A java job's `executable` is the entry CLASS, not a program, and the class
// to run is named in `arguments`. condor_submit turns that into something the
// starter can execute: the class goes on the transfer list, Cmd becomes the
// literal string "java" -- which the execute machine resolves against its own
// JAVA configuration -- and TransferExecutable goes false, because the file
// transfer renames executables and a renamed class file is not the class the
// JVM was asked for.
//
// Without it the ad says to EXECUTE the class file, and nothing puts the file
// in the sandbox either.
func TestJavaUniverseRunsTheJVM(t *testing.T) {
	ad := adFor(t, "universe = java\nexecutable = Hello.class\narguments = Hello\ntransfer_input_files = c.txt\nqueue\n")

	if got := ad["Cmd"]; got != `"java"` {
		t.Errorf("Cmd = %s, want \"java\"", got)
	}
	if got := ad["TransferExecutable"]; got != "false" {
		t.Errorf("TransferExecutable = %s, want false", got)
	}
	if got := ad["TransferInput"]; !strings.Contains(got, "Hello.class") || !strings.Contains(got, "c.txt") {
		t.Errorf("TransferInput = %s, want the submitted file and the entry class", got)
	}

	// jar_files ride along on the same list.
	ad = adFor(t, "universe = java\nexecutable = Hello.class\narguments = Hello\njar_files = a.jar\ntransfer_input_files = c.txt\nqueue\n")
	if got := ad["TransferInput"]; !strings.Contains(got, "a.jar") {
		t.Errorf("TransferInput = %s, want the jar file", got)
	}

	// Like the tool daemon, they ride on a list the submit file asked for:
	// a java job that names no transfer_input_files carries no TransferInput.
	ad = adFor(t, "universe = java\nexecutable = Hello.class\narguments = Hello\nqueue\n")
	if got, ok := ad["TransferInput"]; ok {
		t.Errorf("TransferInput = %s on a job that named no files, want it absent", got)
	}

	// A job that transfers nothing keeps its own Cmd: the class is expected
	// to be on the execute machine already.
	ad = adFor(t, "universe = java\nexecutable = Hello.class\narguments = Hello\nshould_transfer_files = NO\nqueue\n")
	if got := ad["Cmd"]; got == `"java"` {
		t.Error("Cmd = \"java\" with should_transfer_files = NO, want the class path")
	}
	if got, ok := ad["TransferExecutable"]; ok {
		t.Errorf("TransferExecutable = %s with should_transfer_files = NO, want it absent", got)
	}

	// The class to run has to be named.
	mustReject(t, "universe = java\nexecutable = Hello.class\nqueue\n")
	mustReject(t, "universe = java\nexecutable = Hello.class\narguments = \nqueue\n")
}

// TestTransferExecutableIsWrittenOnlyToTurnItOff pins a rule that reads as an
// accident and is not: SetExecutable assigns TransferExecutable only when the
// keyword's FIRST CHARACTER is `f` or `F`.
//
// So `transfer_executable = true` writes no attribute, and an absent one
// means the executable IS transferred. Go wrote `true` for every job: the
// same behaviour spelled differently, but a different ad, and a transform or
// a constraint asking whether the attribute is there gets a different answer.
func TestTransferExecutableIsWrittenOnlyToTurnItOff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		src     string
		want    string
		present bool
	}{
		{name: "nothing said", src: "", present: false},
		{name: "true writes nothing", src: "transfer_executable = true", present: false},
		{name: "false is written", src: "transfer_executable = false", want: "false", present: true},
		{name: "under the attribute name", src: "TransferExecutable = false", want: "false", present: true},
		// The first-character test, quirks and all.
		{name: "F", src: "transfer_executable = F", want: "false", present: true},
		{name: "fnord", src: "transfer_executable = fnord", want: "false", present: true},
		{name: "0 is not f", src: "transfer_executable = 0", present: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := adFor(t, "executable = /bin/true\n"+tc.src+"\nqueue\n")
			got, ok := ad["TransferExecutable"]
			if ok != tc.present {
				t.Fatalf("TransferExecutable present=%v (%s), want present=%v", ok, got, tc.present)
			}
			if tc.present && got != tc.want {
				t.Errorf("TransferExecutable = %s, want %s", got, tc.want)
			}
		})
	}

	// The universes where the executable is only the job's NAME force the
	// transfer off, whatever the submit file says: SetExecutable marks them
	// ignore_it, and the seeds caught this when the attribute stopped being
	// written for every job.
	for _, tc := range []struct{ name, src string }{
		{"vm universe", "universe = vm\nvm_type = kvm\nvm_memory = 128\nvm_disk = d.img:hda:w\n"},
		{"ec2 grid", "universe = grid\ngrid_resource = ec2 https://x\nec2_ami_id = ami-1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := adFor(t, "executable = MyJob\n"+tc.src+"queue\n")
			if got, ok := ad["TransferExecutable"]; !ok || got != "false" {
				t.Errorf("TransferExecutable = %s (present=%v), want false", got, ok)
			}
		})
	}
}
