package mcpserver

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

func TestParseUploadTargetAcceptsBothForms(t *testing.T) {
	tests := []struct {
		in       string
		cluster  int
		proc     int
		allProcs bool
	}{
		{"123.0", 123, 0, false},
		{"123.4", 123, 4, false},
		// A bare cluster id was an error before, so this adds a meaning
		// rather than changing one.
		{"123", 123, 0, true},
		{"  123  ", 123, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseUploadTarget(tt.in)
			if err != nil {
				t.Fatalf("parseUploadTarget(%q): %v", tt.in, err)
			}
			if got.cluster != tt.cluster || got.allProcs != tt.allProcs {
				t.Errorf("got %+v, want cluster=%d allProcs=%v", got, tt.cluster, tt.allProcs)
			}
			if !tt.allProcs && got.proc != tt.proc {
				t.Errorf("proc = %d, want %d", got.proc, tt.proc)
			}
		})
	}
}

func TestParseUploadTargetRejectsNonsense(t *testing.T) {
	// The message has to distinguish the two accepted shapes, because
	// "invalid job_id" alone does not tell a caller which one it meant.
	for _, in := range []string{"", "   ", "abc", "0", "-1", "1.x", "x.1", "1.2.3"} {
		t.Run(in, func(t *testing.T) {
			if _, err := parseUploadTarget(in); err == nil {
				t.Errorf("parseUploadTarget(%q) accepted a value it should not", in)
			}
		})
	}
}

func TestUploadNothingToDoIsNotAnError(t *testing.T) {
	// A cluster with nothing held for spooling is the state the caller
	// wanted. Returning an error would make a satisfied request look
	// failed, and an agent would retry it.
	res := uploadNothingToDo(42)
	meta := res["metadata"].(map[string]interface{})
	if meta["procs_spooled"] != 0 || meta["procs_remaining"] != 0 {
		t.Errorf("unexpected counts: %+v", meta)
	}
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	// It has to say why nothing happened, or the caller cannot tell this
	// from a silent failure.
	if !strings.Contains(text, "HoldReasonCode 16") {
		t.Errorf("the reason nothing was uploaded should be stated: %q", text)
	}
}

func TestSortedKeysIsDeterministic(t *testing.T) {
	// Failure lists go into a tool result an agent reads; unstable order
	// makes two identical outcomes look different.
	m := map[string]string{"9.2": "c", "9.10": "a", "9.1": "b"}
	got := sortedKeys(m)
	want := []string{"9.1", "9.10", "9.2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedKeys = %v, want %v", got, want)
		}
	}
}

// adsForProcs builds proc ads for one cluster.
func adsForProcs(t *testing.T, cluster, n int) []*classad.ClassAd {
	t.Helper()
	out := make([]*classad.ClassAd, n)
	for i := 0; i < n; i++ {
		ad, err := classad.Parse(fmt.Sprintf("[ClusterId = %d; ProcId = %d]", cluster, i))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = ad
	}
	return out
}

// More procs than the concurrency limit, so the fan-out has to run in
// waves. The integration test cannot see this: through a real schedd,
// "all 25 spooled" looks the same whether 10 or 25 were in flight, and a
// fan-out that ignored its bound would pass it.
func TestFanOutRunsInWavesAndRespectsItsBound(t *testing.T) {
	const (
		procs       = 25
		concurrency = 10
	)
	ads := adsForProcs(t, 7, procs)

	var mu sync.Mutex
	inFlight, maxInFlight, attempted := 0, 0, 0

	res := fanOutSpool(context.Background(), ads, []byte("tar"), concurrency,
		func(ctx context.Context, ads []*classad.ClassAd, r io.Reader) error {
			mu.Lock()
			inFlight++
			attempted++
			if inFlight > maxInFlight {
				maxInFlight = inFlight
			}
			mu.Unlock()

			// Hold the slot long enough that a bound violation shows up
			// as overlap rather than being hidden by fast returns.
			time.Sleep(20 * time.Millisecond)

			mu.Lock()
			inFlight--
			mu.Unlock()
			return nil
		})

	if attempted != procs {
		t.Errorf("attempted %d procs, want %d", attempted, procs)
	}
	if len(res.Spooled) != procs {
		t.Errorf("reported %d spooled, want %d", len(res.Spooled), procs)
	}
	if maxInFlight > concurrency {
		t.Errorf("had %d uploads in flight, bound is %d", maxInFlight, concurrency)
	}
	// And it must actually use the concurrency it has: a serial
	// implementation would pass every check above.
	if maxInFlight < 2 {
		t.Errorf("never had more than %d upload in flight; the fan-out is serial", maxInFlight)
	}
}

// A proc that fails must not take the others with it, and must be named.
func TestFanOutReportsPerProcFailures(t *testing.T) {
	ads := adsForProcs(t, 7, 5)
	res := fanOutSpool(context.Background(), ads, []byte("tar"), 3,
		func(ctx context.Context, ads []*classad.ClassAd, r io.Reader) error {
			p, _ := ads[0].EvaluateAttrInt("ProcId")
			if p == 2 {
				return fmt.Errorf("boom")
			}
			return nil
		})

	if len(res.Spooled) != 4 {
		t.Errorf("spooled %d, want 4: %v", len(res.Spooled), res.Spooled)
	}
	if got, ok := res.Failed["7.2"]; !ok || !strings.Contains(got, "boom") {
		t.Errorf("expected 7.2 to be reported failed with its reason, got %+v", res.Failed)
	}
	for _, id := range res.Spooled {
		if id == "7.2" {
			t.Error("a failed proc must not also be reported spooled")
		}
	}
}

// Each proc gets the whole tar, not a shared reader that the first proc
// drains. A shared reader would leave every later proc with zero bytes,
// and the schedd would accept an empty tar without complaint.
func TestFanOutGivesEveryProcTheWholeTar(t *testing.T) {
	ads := adsForProcs(t, 7, 6)
	payload := []byte("the whole tar")

	var mu sync.Mutex
	sizes := map[string]int{}

	fanOutSpool(context.Background(), ads, payload, 4,
		func(ctx context.Context, ads []*classad.ClassAd, r io.Reader) error {
			b, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			p, _ := ads[0].EvaluateAttrInt("ProcId")
			mu.Lock()
			sizes[fmt.Sprintf("7.%d", p)] = len(b)
			mu.Unlock()
			return nil
		})

	if len(sizes) != 6 {
		t.Fatalf("saw %d procs, want 6", len(sizes))
	}
	for id, n := range sizes {
		if n != len(payload) {
			t.Errorf("proc %s received %d bytes, want %d", id, n, len(payload))
		}
	}
}
