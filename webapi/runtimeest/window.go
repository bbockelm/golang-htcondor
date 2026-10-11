package runtimeest

import (
	"math"
	"slices"
)

// window holds the most recent values of something -- a group's
// runtimes, an owner's residuals -- up to a fixed capacity, oldest
// dropped first. Recency beats volume: a workload drifts, and the last
// few dozen runs of a job say more about the next one than the last few
// thousand.
//
// It keeps a sorted copy beside the insertion-order ring so that the
// median and quantiles cost nothing to read. Both slices grow on demand:
// most groups (a one-job cluster, an exact argument list run once) never
// hold more than a value or two, and should not pay for the capacity.
type window struct {
	ring   []float32 // insertion order; circular once full
	sorted []float32
	next   int   // where the next value goes once the ring is full
	at     int64 // when the window was last added to, unix seconds
}

// add records a value, dropping the oldest when the window is at
// capacity.
func (w *window) add(x float32, capacity int) {
	if len(w.ring) < capacity {
		w.ring = append(w.ring, x)
	} else {
		old := w.ring[w.next]
		w.ring[w.next] = x
		w.next = (w.next + 1) % len(w.ring)
		if i, ok := slices.BinarySearch(w.sorted, old); ok {
			w.sorted = slices.Delete(w.sorted, i, i+1)
		}
	}
	i, _ := slices.BinarySearch(w.sorted, x)
	w.sorted = slices.Insert(w.sorted, i, x)
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
