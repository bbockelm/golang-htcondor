package utilization

import (
	"strings"
	"testing"
)

const chtcFormula = `ifThenElse((MemoryUsage isnt undefined), max({ 2048,((3 * MemoryUsage) / 2) }), 2048)`

// A formula request is read at its STARTING value -- usage undefined --
// and kept, in force, for the time-weighted hours.
func TestFromAdAdaptiveRequest(t *testing.T) {
	ad := parseAd(t, `JobStatus = 4
RequestMemory = `+chtcFormula+`
RequestDisk = 1048576
RequestCpus = 1
ResidentSetSize = 1750000
ResidentSetSize_RAW = 1747200
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
DiskUsage = 1000000
DiskUsage_RAW = 966340`)
	j := FromAd(ad, "")
	if !j.isAdaptive(AdaptiveMemory) || j.isAdaptive(AdaptiveDisk) || j.isAdaptive(AdaptiveCpus) {
		t.Errorf("adaptive bits = %b", j.Adaptive)
	}
	if j.RequestMemoryStart.V() != 2048 || j.startMemory().V() != 2048 {
		t.Errorf("start = %v, want 2048", j.RequestMemoryStart.V())
	}
	// It never outgrew the start, so its one run held the start -- not
	// the 1.5 x 1709 = 2563 the formula gives against the finished job.
	if j.RequestMemory.V() != 2048 {
		t.Errorf("in force = %v, want 2048", j.RequestMemory.V())
	}
	// Peaks from the _RAW values: 1747200 KiB is 1706.25 MiB, not the
	// 1709 the rounded ResidentSetSize gives; disk 966340 KiB, not 1e6.
	if j.MemoryUsage.V() != 1706.25 || j.DiskUsage.V() != 966340 {
		t.Errorf("peaks = %v MiB, %v KiB", j.MemoryUsage.V(), j.DiskUsage.V())
	}
	if !strings.Contains(j.MemoryFormula, "MemoryUsage") {
		t.Errorf("formula = %q", j.MemoryFormula)
	}
	// The ad is the caller's and is left as it was.
	if _, ok := ad.Lookup("MemoryUsage"); !ok {
		t.Error("FromAd removed MemoryUsage from the caller's ad")
	}
}

// A job that outgrew the start was rerun at the grown request: 1.5 x
// its 2442 MiB MemoryUsage.
func TestFromAdAdaptiveOutgrown(t *testing.T) {
	j := FromAd(parseAd(t, "JobStatus = 4\nRequestMemory = "+chtcFormula+
		"\nResidentSetSize = 2500000\nResidentSetSize_RAW = 2500000\nMemoryUsage = ((ResidentSetSize + 1023) / 1024)"), "")
	if j.startMemory().V() != 2048 || j.RequestMemory.V() != 3663 {
		t.Errorf("start %v, in force %v; want 2048 and 3663", j.startMemory().V(), j.RequestMemory.V())
	}
}

// Without _RAW, the rounded value is all there is.
func TestFromAdWithoutRaw(t *testing.T) {
	j := FromAd(parseAd(t, "JobStatus = 4\nResidentSetSize = 2048000\nMemoryUsage = ((ResidentSetSize + 1023) / 1024)\nDiskUsage = 5000"), "")
	if j.MemoryUsage.V() != 2000 || j.DiskUsage.V() != 5000 {
		t.Errorf("peaks = %v, %v", j.MemoryUsage.V(), j.DiskUsage.V())
	}
}

// adaptiveJobs is n one-hour jobs whose request starts at 2 GB and was
// 1.5x their peak in force.
func adaptiveJobs(n int, startCluster int64, peak float64) []Job {
	inForce := 2048.0
	if peak > 2048 {
		inForce = 1.5 * peak
	}
	jobs := jobsAt(n, startCluster, peak, inForce)
	for i := range jobs {
		jobs[i].Adaptive = AdaptiveMemory
		jobs[i].RequestMemoryStart = f(2048)
		jobs[i].MemoryFormula = chtcFormula
	}
	return jobs
}

// The advice is sized against where the request starts, not the 1.5x
// peak a finished job's formula evaluates to, and the cost of today's
// formula counts the hold-and-rerun of every job that outgrew the start.
//
// 25 jobs, an hour each: 15 peak at 1500 MiB (fit 2 GB), 10 at 2600 MiB
// (outgrow it, rerun at 3900). Today: 25*2048 + 10*3900 = 90,200 MiB-h.
// One request fitting everything is nice(2600*1.1 = 2860) = 3072 MiB:
// 76,800 MiB-h -- cheaper than the formula, so "start at 3 GB".
func TestAdaptiveRequestSizedFromStart(t *testing.T) {
	jobs := append(adaptiveJobs(15, 1, 1500), adaptiveJobs(10, 100, 2600)...)
	w := onlyWorkflow(t, jobs)
	r := w.Memory.Request
	if r == nil || !r.Adaptive || r.Typical != 2048 || r.Expression != chtcFormula {
		t.Fatalf("request = %+v, want adaptive, starting at 2048", r)
	}
	var current *MemoryCurvePoint
	for i := range w.MemoryCurve {
		if w.MemoryCurve[i].IsCurrent {
			current = &w.MemoryCurve[i]
		}
	}
	if current == nil || current.RequestMiB != 2048 {
		t.Errorf("current point = %+v, want the 2048 start", current)
	}
	a := adviceByResource(w, ResourceMemory)
	if a == nil || a.Severity != SeverityWarn {
		t.Fatalf("advice = %+v", a)
	}
	if !strings.HasPrefix(a.Detail, "Your request starts at 2 GB and grows after a memory hold; 10 of 25 jobs outgrew the start and were held once.") {
		t.Errorf("detail = %q", a.Detail)
	}
	if a.Saves == nil || a.Saves.Amount != round((90200-76800)/1024.0, 1) {
		t.Errorf("saves = %+v, want (90200-76800)/1024 GiB-h", a.Saves)
	}
	// Allocated hours count the request in force for the run that
	// finished: 15*2048 + 10*3900.
	for _, s := range w.Resources {
		if s.Resource == ResourceMemory && s.AllocatedHours != 15*2048+10*3900 {
			t.Errorf("allocated = %v", s.AllocatedHours)
		}
	}
}

// A JobReader remembers what it learned about a request expression, and
// reads every job as FromAd alone would: a formula over nothing but
// usage starts at the same value in every job, however it is spelled; a
// formula that also refers to the job's own attributes is evaluated in
// each job; and a literal request is not a formula.
func TestJobReaderRemembersRequests(t *testing.T) {
	ads := []string{
		"RequestMemory = " + chtcFormula,
		// The same formula, spelled differently.
		"RequestMemory = ifthenelse(memoryusage isnt undefined, max({2048, 3 * memoryusage / 2}), 2048)",
		"RequestMemory = ifThenElse(MemoryUsage isnt undefined, 2 * MemoryUsage, BaseMemory)\nBaseMemory = 1000",
		"RequestMemory = ifThenElse(MemoryUsage isnt undefined, 2 * MemoryUsage, BaseMemory)\nBaseMemory = 3000",
		"RequestMemory = 512",
		"RequestMemory = " + chtcFormula,
		"RequestMemory = ifThenElse(MemoryUsage isnt undefined, 2 * MemoryUsage, BaseMemory)\nBaseMemory = 5000",
		"RequestMemory = 768",
	}
	var r JobReader
	for i, text := range ads {
		ad := parseAd(t, "JobStatus = 4\nResidentSetSize = 400000\nMemoryUsage = ((ResidentSetSize + 1023) / 1024)\n"+text)
		want := FromAd(ad, "")
		got := r.FromAd(ad, "")
		if got.Adaptive != want.Adaptive || got.RequestMemoryStart != want.RequestMemoryStart || got.RequestMemory != want.RequestMemory {
			t.Errorf("ad %d: reader read adaptive %b start %v in force %v; FromAd %b %v %v",
				i, got.Adaptive, got.RequestMemoryStart.V(), got.RequestMemory.V(),
				want.Adaptive, want.RequestMemoryStart.V(), want.RequestMemory.V())
		}
	}
	if len(r.requests) != 4 {
		t.Errorf("reader knows %d expressions, want 4 (two spellings of one formula are one)", len(r.requests))
	}
}
