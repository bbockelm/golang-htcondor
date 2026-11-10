package runtimeest

import (
	"math"

	"github.com/PelicanPlatform/classad/classad"
)

// What a person needs to see the group behind an estimate: what the
// group is, in words; the runtimes the estimator holds for it; and how to
// tell which finished jobs are in it -- by this package's own features
// and keys, so the jobs listed are the ones the estimate was built from,
// not a second account of what "similar" means.

// ParseLevel is the Level named s (see Level.String).
func ParseLevel(s string) (Level, bool) {
	for i, name := range levelNames {
		if name == s {
			return Level(i), true
		}
	}
	return 0, false
}

// levelDescriptions say what each level groups, in a job owner's words.
var levelDescriptions = [numLevels]string{
	"same cluster",
	"same command and arguments, directories and hashes ignored",
	"same command, numbers ignored",
	"same batch name, run number ignored",
	"same submit directory, numbers ignored",
	"same program, any arguments",
	"all your jobs of this kind",
}

// Description is what the level groups, in plain words.
func (l Level) Description() string {
	if l < 0 || l >= numLevels {
		return ""
	}
	return levelDescriptions[l]
}

// WindowSize is how many recent runtimes a group answers from:
// Config.Window.
func (e *Estimator) WindowSize() int {
	return e.cfg.Window
}

// GroupRuntimes is the runtimes the estimator holds for k's group at l
// right now, ascending: exactly what an estimate answered from l uses.
// Nil when the group holds nothing or nothing has been read yet.
func (e *Estimator) GroupRuntimes(k Keys, l Level) []float64 {
	return e.groupValues(k, l, func(w *window) []float32 { return w.sorted })
}

// groupValues is a copy of what of reads from k's group at l, nil when
// that is empty or nothing has been read yet.
func (e *Estimator) groupValues(k Keys, l Level, of func(*window) []float32) []float64 {
	if l < 0 || l >= numLevels {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := e.st
	if !s.loaded {
		return nil
	}
	var w *window
	if key := k.k[l]; key != "" {
		w = s.groups[l][key]
	}
	if w.len() == 0 {
		return nil
	}
	vals := of(w)
	if len(vals) == 0 {
		return nil
	}
	out := make([]float64, len(vals))
	for i, v := range vals {
		out[i] = float64(v)
	}
	return out
}

// RuntimeSummary is a group's runtimes, in seconds. A MemorySummary is
// the same quantiles of its peak memory, in MiB.
type RuntimeSummary struct {
	Count int     `json:"count"`
	P10   float64 `json:"p10"`
	P25   float64 `json:"p25"`
	P50   float64 `json:"p50"`
	P75   float64 `json:"p75"`
	P90   float64 `json:"p90"`
}

// Summarize describes ascending runtimes with the quantiles an estimate
// is read from (interpolated, as the estimator does: P50 is the median an
// estimate answers with). Nil for none. It describes GroupMemory's peaks
// the same way, as a MemorySummary.
func Summarize(sorted []float64) *RuntimeSummary {
	if len(sorted) == 0 {
		return nil
	}
	f := make([]float32, len(sorted))
	for i, v := range sorted {
		f[i] = float32(v)
	}
	q := func(p float64) float64 { return math.Round(quantileOf(f, p)) }
	return &RuntimeSummary{Count: len(sorted), P10: q(0.1), P25: q(0.25), P50: q(0.5), P75: q(0.75), P90: q(0.9)}
}

// HistoryRecord is how the estimator reads a finished job: its runtime
// (see CompletedRuntime) and when it completed (CompletionDate, else
// EnteredHistoryTime). ok is false for a record it would not ingest.
func HistoryRecord(ad *classad.ClassAd) (runtime float64, completed int64, ok bool) {
	runtime, ok = CompletedRuntime(ad)
	if !ok {
		return 0, 0, false
	}
	completed, _ = intAttr(ad, "CompletionDate")
	if completed <= 0 {
		completed, _ = intAttr(ad, "EnteredHistoryTime")
	}
	if completed <= 0 {
		return 0, 0, false
	}
	return runtime, completed, true
}

// InGroup reports whether a history record falls in k's group at l: the
// same features and keys the estimator files it under.
func InGroup(ad *classad.ClassAd, k Keys, l Level) bool {
	key := k.Key(l)
	return key != "" && DeriveKeys(FeaturesFromAd(ad)).Key(l) == key
}
