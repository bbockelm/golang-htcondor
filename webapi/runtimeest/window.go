package runtimeest

import (
	"math"
	"slices"
)

// window holds the most recent values of something -- a group's
// runtimes, an owner's residuals -- oldest dropped first. Recency beats
// volume: a workload drifts, and the last few dozen runs of a job say
// more about the next one than the last few thousand.
//
// It answers from its newest size values, and keeps a sorted copy of
// those so that the median and quantiles cost nothing to read. Each
// value carries the time it was recorded (a runtime's completion time),
// so the window can also answer as of an earlier moment (before). For
// that it may retain more values than it answers from: by the time a
// long job finishes, the runs that had finished when it started may
// already have been pushed out of the newest size by its siblings.
//
// Both slices grow on demand: most groups (a one-job cluster, an exact
// argument list run once) never hold more than a value or two, and
// should not pay for the capacity.
type window struct {
	ring   []entry // insertion order; circular once full
	sorted []float32
	// mem is the peak memory, ascending, of the same values sorted holds,
	// leaving out those whose memory is unknown. A group's memory figures
	// then describe exactly the runs its runtime figures do. Nil in a
	// window that never records memory (an owner's errors, say).
	mem  []float32
	next int   // where the next value goes once the ring is full
	at   int64 // the newest value's time, unix seconds
}

// entry is one value. Its time is unsigned 32-bit seconds, which lasts
// until 2106 and, with the two float32s, keeps an entry at 12 bytes
// rather than 16. mem is a run's peak memory in MiB, 0 when unknown;
// float32 is ample for a figure HTCondor reports in whole MiB.
type entry struct {
	v   float32
	mem float32
	at  uint32
}

// add records a value from time at. The window answers from its newest
// size values and retains at most retain (>= size) of them.
func (w *window) add(x float32, at int64, size, retain int) {
	w.addRun(x, 0, at, size, retain)
}

// addRun is add for a run that also carries its peak memory in MiB, 0
// when that is unknown.
func (w *window) addRun(x, mem float32, at int64, size, retain int) {
	w.at = max(w.at, at)
	if len(w.sorted) >= size {
		// The oldest value answered from leaves the answer, and its
		// memory with it.
		old := w.newest(size - 1)
		w.sorted = deleteSorted(w.sorted, old.v)
		if old.mem > 0 {
			w.mem = deleteSorted(w.mem, old.mem)
		}
	}
	e := entry{v: x, mem: mem, at: clampUnix32(at)}
	if len(w.ring) < retain {
		w.ring = append(w.ring, e)
	} else {
		w.ring[w.next] = e
		w.next = (w.next + 1) % len(w.ring)
	}
	w.sorted = insertSorted(w.sorted, x)
	if mem > 0 {
		w.mem = insertSorted(w.mem, mem)
	}
}

// insertSorted adds x to ascending s.
func insertSorted(s []float32, x float32) []float32 {
	i, _ := slices.BinarySearch(s, x)
	return slices.Insert(s, i, x)
}

// deleteSorted removes one x from ascending s, if it is there.
func deleteSorted(s []float32, x float32) []float32 {
	if i, ok := slices.BinarySearch(s, x); ok {
		return slices.Delete(s, i, i+1)
	}
	return s
}

// newest is the k-th newest retained value, 0 being the newest.
func (w *window) newest(k int) entry {
	n := len(w.ring)
	return w.ring[((w.next-1-k)%n+n)%n]
}

func (w *window) len() int {
	if w == nil {
		return 0
	}
	return len(w.sorted)
}

// median of the window; NaN when empty.
func (w *window) median() float64 {
	return quantileOf(w.sorted, 0.5)
}

// quantile of the window, interpolated between order statistics; NaN
// when empty.
func (w *window) quantile(q float64) float64 {
	return quantileOf(w.sorted, q)
}

// before returns the newest size values recorded strictly before t,
// ascending. When those are exactly the values the window answers from,
// it is the window's own sorted slice; otherwise they are gathered into
// *scratch, which grows as needed and is kept for the next call. Either
// way the caller must not keep or modify the result.
func (w *window) before(t int64, size int, scratch *[]float32) []float32 {
	if w.at < t {
		return w.sorted
	}
	buf := (*scratch)[:0]
	for k := 0; k < len(w.ring) && len(buf) < size; k++ {
		if e := w.newest(k); int64(e.at) < t {
			buf = append(buf, e.v)
		}
	}
	slices.Sort(buf)
	*scratch = buf
	return buf
}

// above returns the window's values greater than x, ascending.
func (w *window) above(x float64) []float32 {
	return aboveIn(w.sorted, x)
}

// aboveIn returns the values of ascending sorted greater than x.
func aboveIn(sorted []float32, x float64) []float32 {
	i := len(sorted)
	for i > 0 && float64(sorted[i-1]) > x {
		i--
	}
	return sorted[i:]
}

// answersFrom reports whether one of the values the window answers from
// was recorded exactly as e.
func (w *window) answersFrom(e entry) bool {
	for k := range len(w.sorted) {
		if w.newest(k) == e {
			return true
		}
	}
	return false
}

// atLeast returns the values of ascending sorted at or above x.
func atLeast(sorted []float32, x float64) []float32 {
	i := len(sorted)
	for i > 0 && float64(sorted[i-1]) >= x {
		i--
	}
	return sorted[i:]
}

// without is the runtimes and known peaks the window answers from, each
// ascending, less one run recorded exactly as own, if it answers from
// such a run: a finished job's own, so that it is not compared with
// itself. Both slices are new.
func (w *window) without(own entry) (runtimes, peaks []float32) {
	n := len(w.sorted)
	runtimes = make([]float32, 0, n)
	peaks = make([]float32, 0, len(w.mem))
	skipped := false
	for k := range n {
		e := w.newest(k)
		if !skipped && e == own {
			skipped = true
			continue
		}
		runtimes = append(runtimes, e.v)
		if e.mem > 0 {
			peaks = append(peaks, e.mem)
		}
	}
	slices.Sort(runtimes)
	slices.Sort(peaks)
	return runtimes, peaks
}

// quantileOf interpolates the q-quantile of sorted values (the R-7
// definition, so the 0.5-quantile is the median).
func quantileOf(sorted []float32, q float64) float64 {
	n := len(sorted)
	if n == 0 {
		return math.NaN()
	}
	pos := q * float64(n-1)
	lo := int(math.Floor(pos))
	if lo >= n-1 {
		return float64(sorted[n-1])
	}
	if lo < 0 {
		return float64(sorted[0])
	}
	frac := pos - float64(lo)
	return float64(sorted[lo]) + frac*float64(sorted[lo+1]-sorted[lo])
}

// clampUnix32 stores a unix time in an entry, clamped to what fits.
func clampUnix32(t int64) uint32 {
	if t <= 0 {
		return 0
	}
	if t > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(t)
}
