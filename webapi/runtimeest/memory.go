package runtimeest

import (
	"math"
	"sort"

	"github.com/PelicanPlatform/classad/classad"
)

// Memory rides along with runtime. Each finished job's group also keeps
// how much memory it peaked at, and an estimate says what the runs of
// the group that answered it peaked at: the same runs its runtime figures
// come from, so a page that shows both describes one group. There is no
// separate choice of group for memory, and no scoring of it: the figures
// are what similar jobs did, not a prediction.

const (
	// minMemorySamples is the fewest known peaks a group needs before a
	// job may be called above its usual memory. With fewer, the 90th
	// percentile is one or two runs and says little about what is usual.
	minMemorySamples = 5
	// aboveUsualFactor and aboveUsualMarginMiB are how far past the
	// group's 90th percentile a running job's peak must be to be called
	// above usual: both a quarter more and 256 MiB more. The factor keeps
	// ordinary run-to-run spread in a large job from flagging; the margin
	// keeps a small job, whose peak can double on a few hundred MiB of
	// libraries or buffers, from flagging over an amount nobody would
	// act on.
	aboveUsualFactor    = 1.25
	aboveUsualMarginMiB = 256
)

// MemoryEstimate is what the runs of an estimate's group peaked at, and
// how the job compares. Figures are MiB.
type MemoryEstimate struct {
	// SampleCount is how many of the group's runs have a known peak;
	// the quantiles are over those.
	SampleCount int     `json:"sample_count"`
	P10MiB      float64 `json:"p10_mib"`
	P25MiB      float64 `json:"p25_mib"`
	P50MiB      float64 `json:"p50_mib"`
	P75MiB      float64 `json:"p75_mib"`
	P90MiB      float64 `json:"p90_mib"`
	// PeakMiB is the job's own peak so far, or for a finished job its
	// peak. Absent when the job has none recorded. HTCondor only ever
	// raises it, so a running job's figure is a floor on its final peak.
	PeakMiB *float64 `json:"peak_mib,omitempty"`
	// RequestedMiB is the job's RequestMemory, and AboveRequested how
	// many of the group's runs peaked above it. Both absent when the job
	// requests none that evaluates.
	RequestedMiB   *float64 `json:"requested_mib,omitempty"`
	AboveRequested *int     `json:"above_requested,omitempty"`
	// Rough is the runtime estimate's Rough: the group is one of the
	// broad ones.
	Rough bool `json:"rough"`
	// AboveUsual is true when a running job has already peaked well past
	// what nearly every run of a specific group did (see aboveUsual).
	AboveUsual bool `json:"above_usual"`
}

// MemorySummary is a group's peak memory in MiB, in the shape
// RuntimeSummary gives its runtimes.
type MemorySummary = RuntimeSummary

// memoryOf is the MemoryEstimate for a job answered from window w at
// level lvl, or nil when the group has no known peak. The caller holds
// the read lock.
func memoryOf(q *Query, w *window, lvl Level) *MemoryEstimate {
	if w == nil || len(w.mem) == 0 {
		return nil
	}
	mib := func(p float64) float64 { return math.Round(quantileOf(w.mem, p)) }
	m := &MemoryEstimate{
		SampleCount: len(w.mem),
		P10MiB:      mib(0.1),
		P25MiB:      mib(0.25),
		P50MiB:      mib(0.5),
		P75MiB:      mib(0.75),
		P90MiB:      mib(0.9),
		Rough:       lvl.rough(),
	}
	if q.PeakMemoryMiB > 0 {
		peak := math.Round(q.PeakMemoryMiB)
		m.PeakMiB = &peak
	}
	if q.RequestMemoryMiB > 0 {
		req := q.RequestMemoryMiB
		m.RequestedMiB = &req
		n := len(w.mem) - sort.Search(len(w.mem), func(i int) bool { return float64(w.mem[i]) > req })
		m.AboveRequested = &n
	}
	m.AboveUsual = aboveUsual(q, w.mem, lvl)
	return m
}

// aboveUsual is whether a running job's peak so far is well past what its
// group's runs peaked at: the job is running, the group is a specific one
// (a broad group mixes unlike jobs, and its spread says nothing about
// this one), the group has at least minMemorySamples known peaks, and the
// peak is past the 90th percentile by both aboveUsualFactor and
// aboveUsualMarginMiB. HTCondor's figure for a running job only ever
// rises, so once it is past the group's runs it stays past: this is an
// excess the job has already had, not a sample that may come back down.
func aboveUsual(q *Query, mem []float32, lvl Level) bool {
	if !q.Running || lvl.rough() || len(mem) < minMemorySamples || !(q.PeakMemoryMiB > 0) {
		return false
	}
	p90 := quantileOf(mem, 0.9)
	return q.PeakMemoryMiB >= aboveUsualFactor*p90 && q.PeakMemoryMiB >= p90+aboveUsualMarginMiB
}

// PeakMemoryAttrs are the attributes PeakMemoryMiB reads.
var PeakMemoryAttrs = []string{"MemoryUsage", "ResidentSetSize", "ResidentSetSize_RAW"}

// PeakMemoryMiB is the most memory a job has used, in MiB, read as the
// Utilization page reads it: ResidentSetSize_RAW (KiB) when the ad has
// it, else MemoryUsage evaluated. A schedd that rounds ResidentSetSize
// for display keeps the measured value in the _RAW attribute, and rounded
// peaks pile up on a few round figures that every percentile then lands
// on. MemoryUsage is normally an expression over ResidentSetSize, which is
// why that rides along in PeakMemoryAttrs. ok is false when neither gives
// a positive, finite figure: the peak is unknown, which is not zero.
//
// For a finished job this is its peak over the run; for a running one,
// its peak so far.
func PeakMemoryMiB(ad *classad.ClassAd) (float64, bool) {
	v, ok := ad.EvaluateAttrNumber("ResidentSetSize_RAW")
	if ok {
		v /= 1024
	} else {
		v, ok = ad.EvaluateAttrNumber("MemoryUsage")
	}
	if !ok || !(v > 0) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

// requestMemoryMiB is the job's RequestMemory in MiB, when it evaluates
// to a positive figure. It can be an expression (a request that grows
// after a hold), which is why it is evaluated, on the same ad as the
// peak it may refer to.
func requestMemoryMiB(ad *classad.ClassAd) float64 {
	v, ok := ad.EvaluateAttrNumber("RequestMemory")
	if !ok || !(v > 0) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

// GroupMemory is the known peaks, in MiB and ascending, of the runs
// GroupRuntimes returns for the same group: what a memory figure answered
// from l uses. Nil when none of them has a known peak, or nothing has
// been read yet.
func (e *Estimator) GroupMemory(k Keys, l Level) []float64 {
	return e.groupValues(k, l, func(w *window) []float32 { return w.mem })
}
