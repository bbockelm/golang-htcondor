package htcondor

import (
	"strings"
	"testing"
)

// TestTransferOutputRemapsAreVerbatim pins that the remap string reaches the
// job ad as the submitter wrote it.
//
// SetTransferFiles does not parse it: it trims the value, takes one layer of
// quotes off, appends it to any remaps condor_submit generated itself, and
// stores the text. The shadow is what splits it, on `;` and `=`, when the job
// finishes.
//
// Rebuilding it here dropped the spaces around the separators, and -- worse
// -- went through a Go map, so a file with two or more remaps produced a
// different attribute value run to run.
func TestTransferOutputRemapsAreVerbatim(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{`transfer_output_remaps = "out.txt = final.txt ; err.txt = final.err"`, "out.txt = final.txt ; err.txt = final.err"},
		{`transfer_output_remaps = out.txt=final.txt`, "out.txt=final.txt"},
		{`transfer_output_remaps = "a=b;c=d;e=f"`, "a=b;c=d;e=f"},
		{`TransferOutputRemaps = "a = b"`, "a = b"},
		{`transfer_output_remaps = "out.txt = s3://bucket/key"`, "out.txt = s3://bucket/key"},
	} {
		ad := adFor(t, "executable = /bin/true\n"+tc.src+"\nqueue\n")
		if got := ad["TransferOutputRemaps"]; got != `"`+tc.want+`"` {
			t.Errorf("%s\n got %s\nwant %q", tc.src, got, tc.want)
		}
	}

	// The same file twice gives the same answer. A map-ordered rebuild
	// failed this about half the time with three remaps.
	const src = "executable = /bin/true\ntransfer_output_remaps = \"a=b;c=d;e=f;g=h\"\nqueue\n"
	first := adFor(t, src)["TransferOutputRemaps"]
	for i := 0; i < 20; i++ {
		if got := adFor(t, src)["TransferOutputRemaps"]; got != first {
			t.Fatalf("TransferOutputRemaps is not stable: %s then %s", first, got)
		}
	}
}

// TestToolDaemonIsTransferred pins that a job asking to run under a tool
// daemon gets the daemon into its sandbox.
//
// SetTransferFiles adds ToolDaemonCmd, and ToolDaemonInput if there is one,
// to the transfer list. Without them the starter has a ToolDaemonCmd naming
// a path that is not in the sandbox.
func TestToolDaemonIsTransferred(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{
			name: "the daemon's binary",
			src:  "executable = /bin/true\ntool_daemon_cmd = /usr/bin/strace\ntransfer_input_files = c.txt\nqueue\n",
			want: "c.txt,/usr/bin/strace",
		},
		{
			name: "and the file it reads",
			src:  "executable = /bin/true\ntool_daemon_cmd = /usr/bin/strace\ntool_daemon_input = in.txt\ntransfer_input_files = c.txt\nqueue\n",
			want: "c.txt,/usr/bin/strace,in.txt",
		},
		{
			name: "under the attribute's own name",
			src:  "executable = /bin/true\nToolDaemonCmd = /usr/bin/strace\ntransfer_input_files = c.txt\nqueue\n",
			want: "c.txt,/usr/bin/strace",
		},
		{
			name: "a path already on the list is not repeated",
			src:  "executable = /bin/true\ntool_daemon_cmd = c.txt\ntransfer_input_files = c.txt\nqueue\n",
			want: "c.txt",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := adFor(t, tc.src)
			if got := ad["TransferInput"]; got != `"`+tc.want+`"` {
				t.Errorf("TransferInput = %s, want %q", got, tc.want)
			}
		})
	}

	// A job that transfers nothing gets nothing added -- and a tool daemon
	// on its own does not create a transfer list, which is condor_submit's
	// behaviour (verified against the oracle) rather than this parser's
	// choice.
	ad := adFor(t, "executable = /bin/true\ntool_daemon_cmd = /usr/bin/strace\nqueue\n")
	if got, ok := ad["TransferInput"]; ok {
		t.Errorf("TransferInput = %s on a job that named no files, want it absent", got)
	}
	ad = adFor(t, "executable = /bin/true\nshould_transfer_files = NO\ntool_daemon_cmd = /usr/bin/strace\nqueue\n")
	if got, ok := ad["TransferInput"]; ok && strings.Contains(got, "strace") {
		t.Errorf("TransferInput = %s with should_transfer_files = NO, want no tool daemon in it", got)
	}
}
