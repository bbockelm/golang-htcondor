package htcondor

import (
	"strings"
	"testing"
)

// adAttrs renders a job ad and returns attribute -> value.
func adAttrs(t *testing.T, submitFile string) map[string]string {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(submitFile))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	out := map[string]string{}
	for _, part := range strings.Split(strings.Trim(ad.String(), "[]"), ";") {
		if i := strings.Index(part, "="); i > 0 {
			out[strings.TrimSpace(part[:i])] = strings.TrimSpace(part[i+1:])
		}
	}
	return out
}

// TestSubmitDoesNotInheritConfigDefaults is the regression. The submit
// file's namespace is seeded with HTCondor's param_info defaults and
// lookups are case-insensitive, so a submit command sharing a name with
// a config knob picked up that knob's default. Job ads gained attributes
// the submit file never mentioned, and a schedd that protects one of
// them rejects the submission outright:
//
//	CommitTransaction failed: You are not allowed to change
//	MAX_TRANSFER_INPUT_MB. (error code 22)
func TestSubmitDoesNotInheritConfigDefaults(t *testing.T) {
	attrs := adAttrs(t, "executable = /bin/sleep\narguments = 60\nqueue 1\n")

	// Each of these has a same-named entry in param_defaults.go and was
	// leaking its value into every job ad.
	for _, attr := range []string{
		"MaxTransferInputMB",  // MAX_TRANSFER_INPUT_MB = -1
		"MaxTransferOutputMB", // MAX_TRANSFER_OUTPUT_MB = -1
		"MountUnderScratch",   // MOUNT_UNDER_SCRATCH = "/tmp,/var/tmp"
		"UserLog",             // LOG = $(LOCAL_DIR)/log
	} {
		if v, ok := attrs[attr]; ok {
			t.Errorf("%s = %s, but the submit file never set it", attr, v)
		}
	}
}

// TestSubmitHonorsExplicitValues is the other half: gating on "the file
// assigned this" must not stop the file from actually setting them.
func TestSubmitHonorsExplicitValues(t *testing.T) {
	attrs := adAttrs(t, `executable = /bin/sleep
max_transfer_input_mb = 512
max_transfer_output_mb = 256
log = /tmp/job.log
queue 1
`)
	for attr, want := range map[string]string{
		"MaxTransferInputMB":  "512",
		"MaxTransferOutputMB": "256",
	} {
		if got := attrs[attr]; got != want {
			t.Errorf("%s = %q, want %q", attr, got, want)
		}
	}
	if got := attrs["UserLog"]; !strings.Contains(got, "/tmp/job.log") {
		t.Errorf("UserLog = %q, want /tmp/job.log", got)
	}
}

// TestSubmitCommandIsCaseInsensitive keeps HTCondor's behavior: submit
// commands are matched without regard to case, so the gate must fold too
// or a MaxTransferInputMB written in mixed case would be dropped.
func TestSubmitCommandIsCaseInsensitive(t *testing.T) {
	attrs := adAttrs(t, "executable = /bin/sleep\nMax_Transfer_Input_MB = 128\nqueue 1\n")
	if got := attrs["MaxTransferInputMB"]; got != "128" {
		t.Errorf("MaxTransferInputMB = %q, want 128", got)
	}
}

// TestSubmitAssignmentInsideConditionalCounts covers a name assigned
// only inside an if/else. It must still read as submit-file-provided,
// or the config default silently returns.
func TestSubmitAssignmentInsideConditionalCounts(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(`executable = /bin/sleep
if defined FOO
  max_transfer_input_mb = 64
endif
queue 1
`))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	if !sf.assigned["MAX_TRANSFER_INPUT_MB"] {
		t.Error("a name assigned inside a conditional was not recorded")
	}
}
