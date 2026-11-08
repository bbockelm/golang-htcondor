package reservation

import (
	"strings"
	"testing"
	"time"
)

const gpuSeat = `
executable = /usr/bin/jupyter
arguments  = lab --no-browser
request_cpus   = 4
request_gpus   = 1
request_memory = 16384
request_disk   = 10GB
queue
`

func seatSpec(submit string) *Spec {
	return &Spec{
		ID: "cs301", Owner: "prof-moriarty", Project: "cs301-f26", Submit: submit,
		Seats: 35, Standing: 4,
		Duration: time.Hour, Lead: 6 * time.Hour, Hold: 15 * time.Minute,
		Enabled: true,
	}
}

func TestSeatAdRendersTheSubmitFile(t *testing.T) {
	ad, err := seatSpec(gpuSeat).SeatAd()
	if err != nil {
		t.Fatalf("SeatAd: %v", err)
	}
	if cmd, ok := ad.EvaluateAttrString("Cmd"); !ok || cmd != "/usr/bin/jupyter" {
		t.Errorf("Cmd = %q (ok=%v), want /usr/bin/jupyter", cmd, ok)
	}
	for attr, want := range map[string]int64{
		"RequestCpus": 4, "RequestGpus": 1, "RequestMemory": 16384,
	} {
		got, ok := ad.EvaluateAttrInt(attr)
		if !ok || got != want {
			t.Errorf("%s = %d (ok=%v), want %d", attr, got, ok, want)
		}
	}
}

// TestSeatAdComposesRequirements is why the real submit machinery is used
// rather than a hand parse: Requirements is built clause by clause at
// submit time, so a seat rendered any other way would match a different
// set of machines than the jobs do.
func TestSeatAdComposesRequirements(t *testing.T) {
	ad, err := seatSpec(gpuSeat).SeatAd()
	if err != nil {
		t.Fatalf("SeatAd: %v", err)
	}
	expr, ok := ad.Lookup("Requirements")
	if !ok {
		t.Fatal("the rendered seat has no Requirements")
	}
	got := expr.String()
	// The GPU request has to reach Requirements, or the seat would be
	// planned against machines that cannot host it.
	if !strings.Contains(strings.ToLower(got), "gpus") {
		t.Errorf("Requirements %q does not constrain GPUs", got)
	}
}

// TestSeatAdStampsTheProject: the reservation owns which jobs may take its
// seats, so the project is not left to whoever wrote the submit file.
func TestSeatAdStampsTheProject(t *testing.T) {
	ad, err := seatSpec(gpuSeat).SeatAd()
	if err != nil {
		t.Fatalf("SeatAd: %v", err)
	}
	if got, ok := ad.EvaluateAttrString("ProjectName"); !ok || got != "cs301-f26" {
		t.Errorf("ProjectName = %q (ok=%v), want cs301-f26", got, ok)
	}
	// Even when the submit file names a different one.
	s := seatSpec("executable = /bin/true\nProjectName = someone-else\nqueue\n")
	ad, err = s.SeatAd()
	if err != nil {
		t.Fatalf("SeatAd: %v", err)
	}
	if got, _ := ad.EvaluateAttrString("ProjectName"); got != "cs301-f26" {
		t.Errorf("ProjectName = %q, want the reservation's own cs301-f26", got)
	}
}

func TestSeatAdRejectsBadSubmit(t *testing.T) {
	for _, tc := range []struct{ name, submit string }{
		{"empty", ""},
		{"whitespace", "   \n\t\n"},
		{"no executable", "request_cpus = 1\nqueue\n"},
	} {
		s := seatSpec(tc.submit)
		if err := s.CheckSubmit(); err == nil {
			t.Errorf("%s: CheckSubmit accepted it", tc.name)
		}
	}
}

func TestCheckSubmitAcceptsAGoodOne(t *testing.T) {
	if err := seatSpec(gpuSeat).CheckSubmit(); err != nil {
		t.Errorf("CheckSubmit rejected a good submit file: %v", err)
	}
}
