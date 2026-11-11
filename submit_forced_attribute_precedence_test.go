package htcondor

import (
	"strings"
	"testing"
)

// TestForcedAttributeBeatsTheSubmitCommand pins the precedence between a
// submit command and a `+Attr` naming the attribute that command writes.
//
// condor_submit resolves it by ordering: SetForcedAttributes runs last, with
// the comment "SetForcedAttributes should be last so that it trumps values"
// in submit_utils.cpp, so the forced value wins however early in the file it
// appears. Here the passes read the job ad rather than the submit macro set,
// so a forced attribute is written onto the ad twice -- once early, to be
// visible to the passes that read it, and once at the end, to win.
//
// Only the second write is what this test is about. Each case names an
// attribute written by a pass that runs AFTER the first write, which is where
// the forced value used to be overwritten: `batch_name` beat
// `+JobBatchName`, and so did every other row here. Both orders are checked
// because the file order is exactly what must NOT matter.
func TestForcedAttributeBeatsTheSubmitCommand(t *testing.T) {
	cases := []struct {
		attr    string // job attribute both lines write
		command string // the submit command's line
		forced  string // the `+Attr` line
		want    string // the forced value, as the ad renders it
	}{
		{"JobBatchName", `batch_name = fromkeyword`, `+JobBatchName = "forced"`, `"forced"`},
		{"DockerNetworkType", `docker_network_type = host`, `+DockerNetworkType = "forced"`, `"forced"`},
		{"OutputDestination", `output_destination = url://a`, `+OutputDestination = "forced"`, `"forced"`},
		{"WantGracefulRemoval", `want_graceful_removal = false`, `+WantGracefulRemoval = true`, `true`},
		{"PeriodicHold", `periodic_hold = false`, `+PeriodicHold = true`, `true`},
		{"OnExitRemove", `on_exit_remove = true`, `+OnExitRemove = false`, `false`},
		{"KillSig", `kill_sig = 9`, `+KillSig = 15`, `15`},
		{"WantRemoteIO", `want_remote_io = false`, `+WantRemoteIO = true`, `true`},
		{"WantCheckpoint", `want_checkpoint = false`, `+WantCheckpoint = true`, `true`},
		{"KeystoreFile", `keystore_file = fromkeyword`, `+KeystoreFile = "forced"`, `"forced"`},
		{"JobNotification", `notification = never`, `+JobNotification = 3`, `3`},
	}

	for _, tc := range cases {
		for _, order := range []struct {
			name  string
			lines [2]string
		}{
			{"command first", [2]string{tc.command, tc.forced}},
			{"forced first", [2]string{tc.forced, tc.command}},
		} {
			t.Run(tc.attr+"/"+order.name, func(t *testing.T) {
				src := "executable = /bin/sleep\n" +
					order.lines[0] + "\n" + order.lines[1] + "\nqueue\n"
				sf, err := ParseSubmitFile(strings.NewReader(src))
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
				if err != nil {
					t.Fatalf("MakeJobAd: %v", err)
				}
				v, ok := ad.Lookup(tc.attr)
				if !ok {
					t.Fatalf("%s is not on the ad", tc.attr)
				}
				if got := v.String(); got != tc.want {
					t.Errorf("%s = %s, want %s (the forced value)", tc.attr, got, tc.want)
				}
			})
		}
	}
}
