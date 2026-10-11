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
	next   int   // where the next value goes once the ring is full
	at     int64 // the newest value's time, unix seconds
}

// entry is one value. Its time is unsigned 32-bit seconds, which halves
// the entry and lasts until 2106.
type entry struct {
	v  float32
	at uint32
}

// add records a value from time at. The window answers from its newest
// size values and retains at most retain (>= size) of them.
func (w *window) add(x float32, at int64, size, retain int) {
	w.at = max(w.at, at)
	if len(w.sorted) >= size {
		// The oldest value answered from leaves the answer.
		old := w.newest(size - 1).v
		if i, ok := slices.BinarySearch(w.sorted, old); ok {
			w.sorted = slices.Delete(w.sorted, i, i+1)
		}
	}
	if len(w.ring) < retain {
		w.ring = append(w.ring, entry{x, clampUnix32(at)})
	} else {
		w.ring[w.next] = entry{x, clampUnix32(at)}
		w.next = (w.next + 1) % len(w.ring)
	}
	i, _ := slices.BinarySearch(w.sorted, x)
	w.sorted = slices.Insert(w.sorted, i, x)
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
	i := len(w.sorted)
	for i > 0 && float64(w.sorted[i-1]) > x {
		i--
	}
	return w.sorted[i:]
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
