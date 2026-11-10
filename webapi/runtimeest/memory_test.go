package runtimeest

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// memJob is a completed job with a peak memory, in MiB.
type memJob struct {
	f       Features
	runtime float64
	mem     float64
}

// ingestMem files jobs a second apart, in order.
func ingestMem(e *Estimator, jobs ...memJob) {
	b := NewBatch()
	for i, j := range jobs {
		b.Add(Completion{Features: j.f, ProcID: int64(i), Runtime: j.runtime, PeakMemoryMiB: j.mem,
			Completed: t0.Add(time.Duration(i) * time.Second)})
	}
	e.Ingest(b)
}

// sameMem is n runs of alice's "sim 1" with peak mem each.
func sameMem(n int, mem float64) []memJob {
	out := make([]memJob, n)
	for i := range out {
		out[i] = memJob{simArgs("1"), 100, mem}
	}
	return out
}

func simArgs(args ...string) Features {
	return Features{Owner: "alice", Cmd: "/home/alice/sim", Args: args}
}

// exactMemory is GroupMemory for f's exact group.
func exactMemory(e *Estimator, f Features) []float64 {
	return e.GroupMemory(DeriveKeys(f), LevelExact)
}

// A run whose peak is unknown still counts for its runtime, and is left
// out of the memory figures: zero, negative and non-finite are unknown,
// not small.
func TestMemoryIngestSkipsUnknown(t *testing.T) {
	e := New(Config{})
	f := simArgs("1")
	ingestMem(e,
		memJob{f, 100, 500}, memJob{f, 110, 0}, memJob{f, 120, -3}, memJob{f, 130, math.NaN()},
		memJob{f, 140, math.Inf(1)}, memJob{f, 150, 300}, memJob{f, 160, 700})
	if got := e.GroupRuntimes(DeriveKeys(f), LevelExact); len(got) != 7 {
		t.Errorf("runtimes = %v; every run should count", got)
	}
	if got := exactMemory(e, f); !slices.Equal(got, []float64{300, 500, 700}) {
		t.Errorf("memory = %v; want only the known peaks", got)
	}
	r := e.Estimate(Query{Features: f})
	if r.Memory == nil || r.Memory.SampleCount != 3 || r.Memory.P50MiB != 500 {
		t.Errorf("memory estimate = %+v; want 3 samples, median 500", r.Memory)
	}
}

// The memory figures describe exactly the runs the runtime figures do:
// as a run leaves a group's window its peak leaves with it, and a run
// with no known peak leaving takes nothing.
func TestMemoryFollowsTheRuntimeWindow(t *testing.T) {
	e := New(Config{Window: 4})
	f := simArgs("1")
	ingestMem(e, memJob{f, 10, 100}, memJob{f, 20, 0}, memJob{f, 30, 300}, memJob{f, 40, 300}, memJob{f, 50, 500})
	// Answered from the newest four: 20 (unknown), 30, 40, 50.
	if got := e.GroupRuntimes(DeriveKeys(f), LevelExact); !slices.Equal(got, []float64{20, 30, 40, 50}) {
		t.Fatalf("runtimes = %v", got)
	}
	if got := exactMemory(e, f); !slices.Equal(got, []float64{300, 300, 500}) {
		t.Errorf("memory = %v; want the peaks of the same four runs", got)
	}
	ingestMem(e, memJob{f, 60, 0})
	// 20 left, and it had no peak; 60 has none either.
	if got := exactMemory(e, f); !slices.Equal(got, []float64{300, 300, 500}) {
		t.Errorf("after an unknown run replaced an unknown one: %v", got)
	}
	ingestMem(e, memJob{f, 70, 900})
	// 30 left with one of the two 300s.
	if got := exactMemory(e, f); !slices.Equal(got, []float64{300, 500, 900}) {
		t.Errorf("after a known run left: %v", got)
	}
}

// Evicting a group drops its memory with its runtimes.
func TestMemoryEvict(t *testing.T) {
	e := New(Config{})
	f := simArgs("1")
	ingestMem(e, sameMem(3, 800)...)
	e.Evict(t0.Add(time.Hour))
	if got := exactMemory(e, f); got != nil {
		t.Errorf("memory after eviction = %v", got)
	}
	if r := e.Estimate(Query{Features: f}); r.Memory != nil {
		t.Errorf("memory estimate after eviction = %+v", r.Memory)
	}
}

// A group none of whose runs has a known peak gives no memory figure;
// the runtime estimate is unaffected.
func TestMemoryAbsentWithoutPeaks(t *testing.T) {
	e := New(Config{})
	f := simArgs("1")
	ingestMem(e, sameMem(6, 0)...)
	r := e.Estimate(Query{Features: f, Running: true, PeakMemoryMiB: 50_000})
	if !r.Available || r.Memory != nil {
		t.Errorf("estimate = %+v, memory %+v; want a runtime estimate and no memory", r, r.Memory)
	}
	if exactMemory(e, f) != nil {
		t.Error("GroupMemory returned peaks for a group with none")
	}
	got, _ := json.Marshal(r)
	if strings.Contains(string(got), `"memory"`) {
		t.Errorf("memory in %s", got)
	}
}

// The memory figure comes from the group that answered the runtime
// estimate, and carries its roughness and the job's own figures.
func TestMemoryFromTheAnsweringGroup(t *testing.T) {
	e := New(Config{})
	var jobs []memJob
	// Five runs of "sim 1" at 1000 MiB, five of "sim 2" at 4000 MiB.
	for range 5 {
		jobs = append(jobs, memJob{simArgs("1"), 100, 1000}, memJob{simArgs("2"), 100, 4000})
	}
	ingestMem(e, jobs...)

	r := e.Estimate(Query{Features: simArgs("2"), PeakMemoryMiB: 10.4, RequestMemoryMiB: 2048})
	if r.Basis == nil || r.Basis.Level != "exact" || r.Memory == nil {
		t.Fatalf("estimate = %+v", r)
	}
	m := r.Memory
	if m.SampleCount != 5 || m.P10MiB != 4000 || m.P90MiB != 4000 || m.Rough {
		t.Errorf("memory = %+v; want sim 2's five runs, not rough", m)
	}
	if m.PeakMiB == nil || *m.PeakMiB != 10 {
		t.Errorf("peak = %v; want the job's own, rounded", m.PeakMiB)
	}
	if m.RequestedMiB == nil || *m.RequestedMiB != 2048 || m.AboveRequested == nil || *m.AboveRequested != 5 {
		t.Errorf("requested %v above %v; want 2048 and all five", m.RequestedMiB, m.AboveRequested)
	}

	// Other arguments: the program's runs answer, all ten, roughly.
	r = e.Estimate(Query{Features: simArgs("other"), RequestMemoryMiB: 4000})
	if r.Basis == nil || r.Basis.Level != "cmd" || r.Memory == nil {
		t.Fatalf("estimate = %+v", r)
	}
	if m := r.Memory; m.SampleCount != 10 || !m.Rough || m.PeakMiB != nil || *m.AboveRequested != 0 {
		t.Errorf("memory = %+v; want ten rough samples, no peak, none above a request equal to the largest", m)
	}

	// No request, no request figures.
	if m := e.Estimate(Query{Features: simArgs("1")}).Memory; m.RequestedMiB != nil || m.AboveRequested != nil {
		t.Errorf("request figures with no request: %+v", m)
	}
}

// above_usual: running, a specific group, at least minMemorySamples
// known peaks, and a peak past the group's 90th percentile by both the
// factor and the margin. Each case fails exactly one of those.
func TestAboveUsual(t *testing.T) {
	// p90 2000: the factor binds (2500 > 2256). p90 400: the margin
	// binds (656 > 500).
	big, small := New(Config{}), New(Config{})
	ingestMem(big, sameMem(10, 2000)...)
	ingestMem(small, sameMem(10, 400)...)
	few := New(Config{})
	ingestMem(few, sameMem(minMemorySamples-1, 400)...)
	enough := New(Config{})
	ingestMem(enough, sameMem(minMemorySamples, 400)...)

	cases := []struct {
		name    string
		e       *Estimator
		f       Features
		running bool
		peak    float64
		want    bool
	}{
		{"factor: at 1.25x", big, simArgs("1"), true, 2500, true},
		{"factor: under 1.25x, over the margin", big, simArgs("1"), true, 2499, false},
		{"margin: at +256", small, simArgs("1"), true, 656, true},
		{"margin: under +256, over 1.25x", small, simArgs("1"), true, 655, false},
		{"not running", big, simArgs("1"), false, 10_000, false},
		{"rough group", big, simArgs("other"), true, 10_000, false},
		{"too few samples", few, simArgs("1"), true, 10_000, false},
		{"just enough samples", enough, simArgs("1"), true, 10_000, true},
		{"no peak", big, simArgs("1"), true, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.e.Estimate(Query{Features: c.f, Running: c.running, Elapsed: 10, PeakMemoryMiB: c.peak})
			if r.Memory == nil {
				t.Fatalf("no memory figure: %+v", r)
			}
			if r.Memory.AboveUsual != c.want {
				t.Errorf("above_usual = %v, want %v (level %s, %d samples, p90 %v, peak %v)",
					r.Memory.AboveUsual, c.want, r.Basis.Level, r.Memory.SampleCount, r.Memory.P90MiB, c.peak)
			}
		})
	}
}

// EstimateMany shares a cluster's group between its procs, and still
// judges each proc's own peak.
func TestEstimateManyMemoryPerJob(t *testing.T) {
	e := New(Config{})
	ingestMem(e, sameMem(10, 1000)...)
	f := simArgs("1")
	qs := []Query{
		{Features: f, Running: true, Elapsed: 5, PeakMemoryMiB: 900},
		{Features: f, Running: true, Elapsed: 5, PeakMemoryMiB: 5000},
	}
	got := e.EstimateMany(qs)
	for i, q := range qs {
		if want := e.Estimate(q); got[i].Memory == nil || *got[i].Memory.PeakMiB != *want.Memory.PeakMiB ||
			got[i].Memory.AboveUsual != want.Memory.AboveUsual {
			t.Errorf("job %d: many %+v, single %+v", i, got[i].Memory, want.Memory)
		}
	}
	if got[0].Memory.AboveUsual || !got[1].Memory.AboveUsual {
		t.Errorf("above_usual = %v, %v; want false, true", got[0].Memory.AboveUsual, got[1].Memory.AboveUsual)
	}
}

// The peak is read as the Utilization page reads it: the unrounded _RAW
// KiB when present, else MemoryUsage evaluated -- normally an expression
// over ResidentSetSize.
func TestPeakMemoryMiB(t *testing.T) {
	cases := []struct {
		name string
		ad   string
		want float64
		ok   bool
	}{
		{"raw wins", "ResidentSetSize_RAW = 1048576\nResidentSetSize = 1250000\nMemoryUsage = ((ResidentSetSize + 1023) / 1024)", 1024, true},
		{"expression", "ResidentSetSize = 2097152\nMemoryUsage = ((ResidentSetSize + 1023) / 1024)", 2048, true},
		{"literal", "MemoryUsage = 300", 300, true},
		{"expression without its input", "MemoryUsage = ((ResidentSetSize + 1023) / 1024)", 0, false},
		{"zero", "MemoryUsage = 0", 0, false},
		{"absent", "Owner = \"a\"", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := PeakMemoryMiB(adFrom(t, c.ad))
			if got != c.want || ok != c.ok {
				t.Errorf("got %v %v, want %v %v", got, ok, c.want, c.ok)
			}
		})
	}
	for _, attrs := range [][]string{HistoryAttrs, QueryAttrs} {
		for _, a := range PeakMemoryAttrs {
			if !slices.Contains(attrs, a) {
				t.Errorf("%s missing from a projection", a)
			}
		}
	}
	if !slices.Contains(QueryAttrs, "RequestMemory") {
		t.Error("RequestMemory missing from QueryAttrs")
	}
}

// A history record's peak reaches its groups, and a queue ad's peak and
// request reach its query.
func TestMemoryFromAds(t *testing.T) {
	b := NewBatch()
	for i, rss := range []string{"ResidentSetSize_RAW = 524288", "MemoryUsage = 0", ""} {
		b.AddAd(adFrom(t, `Owner = "a"
Cmd = "x"
ProcId = `+strconv.Itoa(i)+`
JobStatus = 4
ExitCode = 0
RemoteWallClockTime = 60
CompletionDate = 1000
`+rss))
	}
	e := New(Config{})
	e.Ingest(b)
	f := Features{Owner: "a", Cmd: "x"}
	if got := exactMemory(e, f); !slices.Equal(got, []float64{512}) {
		t.Errorf("memory = %v; want the one known peak", got)
	}

	q := QueryFromAd(adFrom(t, `Owner = "a"
Cmd = "x"
JobStatus = 2
JobCurrentStartDate = 900
ServerTime = 1000
ResidentSetSize = 3145728
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
RequestMemory = ifThenElse(MemoryUsage =!= undefined, MAX({2048, 2 * MemoryUsage}), 2048)`), time.Unix(1000, 0))
	if q.PeakMemoryMiB != 3072 || q.RequestMemoryMiB != 6144 || !q.Running {
		t.Errorf("query = %+v; want peak 3072, request 6144", q)
	}
	q = QueryFromAd(adFrom(t, "Owner = \"a\"\nJobStatus = 1\nRequestMemory = 1024"), time.Unix(1000, 0))
	if q.PeakMemoryMiB != 0 || q.RequestMemoryMiB != 1024 {
		t.Errorf("waiting query = %+v", q)
	}
}

func TestMemoryEstimateJSON(t *testing.T) {
	peak, req, above := 6200.0, 2048.0, 3
	got, err := json.Marshal(Result{Available: true, Memory: &MemoryEstimate{
		SampleCount: 9, P10MiB: 900, P25MiB: 1000, P50MiB: 1200, P75MiB: 1500, P90MiB: 2000,
		PeakMiB: &peak, RequestedMiB: &req, AboveRequested: &above, AboveUsual: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"available":true,"rough":false,"exceeded_history":false,"memory":{"sample_count":9,` +
		`"p10_mib":900,"p25_mib":1000,"p50_mib":1200,"p75_mib":1500,"p90_mib":2000,` +
		`"peak_mib":6200,"requested_mib":2048,"above_requested":3,"rough":false,"above_usual":true},"model":{"jobs_ingested":0}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
