package toolstats

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestTheStoreItselfIsBounded is the finding this change exists for.
//
// The per-label ceiling applies at RENDER time, so it bounded the
// Prometheus exposition while leaving the in-memory map -- and
// therefore the SQLite table, which is written from it -- to grow one
// entry per distinct key forever. An unknown tool is recorded under the
// name the CALLER sent, so an authenticated client looping tools/call
// with random names grew both without limit.
func TestTheStoreItselfIsBounded(t *testing.T) {
	s := New()
	s.SetMaxSeries(100)
	for i := 0; i < 20000; i++ {
		s.Record(randomName(i), "alice", "cc", OutcomeUnknownTool, time.Millisecond)
	}
	// maxSeries ordinary series plus the one overflow bucket.
	if n := len(s.Snapshot()); n > 101 {
		t.Errorf("store holds %d series, want at most 101", n)
	}
}

// Folding must not lose calls: only the detail goes.
func TestFoldingKeepsTheTotals(t *testing.T) {
	s := New()
	s.SetMaxSeries(10)
	for i := 0; i < 500; i++ {
		s.Record(randomName(i), "alice", "cc", OutcomeUnknownTool, time.Millisecond)
	}
	var total uint64
	for _, e := range s.Snapshot() {
		total += e.Calls
	}
	if total != 500 {
		t.Errorf("counted %d calls, want 500 -- folding dropped calls instead of detail", total)
	}
}

// The overflow bucket must not itself mint combinations, or the cap
// leaks one series per distinct user or client that arrives after it.
func TestTheOverflowBucketIsASingleSeries(t *testing.T) {
	s := New()
	s.SetMaxSeries(5)
	for i := 0; i < 200; i++ {
		s.Record(randomName(i), randomName(i+1000), randomName(i+2000), OutcomeOK, time.Millisecond)
	}
	n := 0
	for k := range s.Snapshot() {
		if k.Tool == OtherLabel {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the overflow produced %d series, want exactly 1", n)
	}
}

// The tool name is caller-supplied with a 16 MB body limit behind it,
// and lands in a map key, a primary key and two indexes.
func TestALongToolNameIsClamped(t *testing.T) {
	s := New()
	s.Record(strings.Repeat("a", 100000), "alice", "cc", OutcomeUnknownTool, time.Millisecond)
	for k := range s.Snapshot() {
		if len(k.Tool) > MaxToolNameLength {
			t.Errorf("stored a %d-character tool name", len(k.Tool))
		}
	}
}

func TestSetMaxSeriesRefusesToRemoveTheBound(t *testing.T) {
	s := New()
	for _, n := range []int{0, -5} {
		s.SetMaxSeries(n)
		if s.maxSeries != DefaultMaxSeries {
			t.Errorf("SetMaxSeries(%d) left the bound at %d", n, s.maxSeries)
		}
	}
}

// TestOneInvalidUTF8ValueDoesNotEmptyTheEndpoint: MustNewConstMetric
// panics on a label value that is not valid UTF-8. client_golang
// recovers it, so Collect dies partway through and the scrape returns
// 200 with a silently truncated body -- a different subset each time,
// which Prometheus reads as repeated counter resets.
func TestOneInvalidUTF8ValueDoesNotEmptyTheEndpoint(t *testing.T) {
	s := New()
	for i := 0; i < 5; i++ {
		s.Record("query_jobs", "alice", "cc", OutcomeOK, time.Millisecond)
	}
	s.Record("query_jobs", "bad\xffuser", "cc", OutcomeOK, time.Millisecond)

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(s))

	// Repeated, because the damage depends on map iteration order.
	for i := 0; i < 20; i++ {
		families, err := reg.Gather()
		if err != nil {
			t.Fatalf("Gather: %v", err)
		}
		n := 0
		for _, f := range families {
			if f.GetName() == "htcondor_api_mcp_tool_calls_total" {
				n = len(f.Metric)
			}
		}
		if n != 2 {
			t.Fatalf("scrape %d produced %d call series, want 2 (alice and the invalid one)", i, n)
		}
	}
}

func TestTheInvalidValueIsLabelledAsSuch(t *testing.T) {
	s := New()
	s.Record("t", "bad\xffuser", "cc", OutcomeOK, time.Millisecond)
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(s))
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "htcondor_api_mcp_tool_calls_total" {
			continue
		}
		if got := labelValue(f.Metric[0], "user"); got != InvalidLabel {
			t.Errorf("user = %q, want %q", got, InvalidLabel)
		}
	}
}

// A site that does not want usernames on a potentially public endpoint
// can turn the label off and keep every other number.
func TestTheUserLabelCanBeTurnedOff(t *testing.T) {
	s := New()
	s.Record("query_jobs", "alice", "cc", OutcomeOK, time.Millisecond)
	s.Record("query_jobs", "bob", "cc", OutcomeOK, time.Millisecond)

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollectorWithOptions(s, true))
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "htcondor_api_mcp_tool_calls_total" {
			continue
		}
		// One series, both users summed into it, no name visible.
		if len(f.Metric) != 1 {
			t.Fatalf("got %d series, want 1", len(f.Metric))
		}
		if got := labelValue(f.Metric[0], "user"); got != OmittedLabel {
			t.Errorf("user = %q, want %q", got, OmittedLabel)
		}
		if v := f.Metric[0].GetCounter().GetValue(); v != 2 {
			t.Errorf("calls = %v, want 2; suppressing the label must not lose counts", v)
		}
	}

	// The store still knows who, for the admin view and for SQL.
	names := map[string]bool{}
	for k := range s.Snapshot() {
		names[k.User] = true
	}
	if !names["alice"] || !names["bob"] {
		t.Errorf("the stored identities were suppressed too: %v", names)
	}
}

func randomName(i int) string {
	return "n" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('0'+i%10)) +
		strings.Repeat("y", i%5) + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
