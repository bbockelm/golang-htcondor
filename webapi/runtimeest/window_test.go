package runtimeest

import (
	"slices"
	"testing"
)

// A window answers from its newest size values, keeps up to retain, and
// can answer as of an earlier moment from what it kept.
func TestWindowAsOf(t *testing.T) {
	var w window
	for i := 1; i <= 10; i++ {
		w.add(float32(i), int64(i), 4, 8)
	}
	if !slices.Equal(w.sorted, []float32{7, 8, 9, 10}) {
		t.Errorf("answers from %v, want the newest four", w.sorted)
	}
	var scratch []float32
	if got := w.before(9, 4, &scratch); !slices.Equal(got, []float32{5, 6, 7, 8}) {
		t.Errorf("before(9) = %v", got)
	}
	// Values 1 and 2 were not retained.
	if got := w.before(5, 4, &scratch); !slices.Equal(got, []float32{3, 4}) {
		t.Errorf("before(5) = %v", got)
	}
	if got := w.before(100, 4, &scratch); !slices.Equal(got, w.sorted) {
		t.Errorf("before(100) = %v", got)
	}
	if got := w.before(1, 4, &scratch); len(got) != 0 {
		t.Errorf("before(1) = %v", got)
	}
}

// Values arriving out of time order are still answered newest-first by
// insertion, and the as-of filter goes by time.
func TestWindowAsOfOutOfOrder(t *testing.T) {
	var w window
	w.add(1, 30, 2, 4)
	w.add(2, 10, 2, 4)
	w.add(3, 20, 2, 4)
	var scratch []float32
	if got := w.before(25, 2, &scratch); !slices.Equal(got, []float32{2, 3}) {
		t.Errorf("before(25) = %v", got)
	}
}
