package utilization

import (
	"math"
	"slices"
)

// percentile is the exact nearest-rank percentile of an ascending slice:
// the smallest value with at least p percent of the values at or below
// it. Nearest-rank rather than interpolated so that every percentile is
// a value some job actually had -- "95% peaked under 1.7 GB" should name
// a peak that happened, not a blend of two neighbours.
func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	k := int(math.Ceil(p / 100 * float64(n)))
	if k < 1 {
		k = 1
	}
	if k > n {
		k = n
	}
	return sorted[k-1]
}

// distribution summarizes values; nil when there are none. values is
// sorted in place.
func distribution(values []float64) *Distribution {
	if len(values) == 0 {
		return nil
	}
	slices.Sort(values)
	return &Distribution{
		N:         len(values),
		Min:       values[0],
		P10:       percentile(values, 10),
		P25:       percentile(values, 25),
		P50:       percentile(values, 50),
		P75:       percentile(values, 75),
		P90:       percentile(values, 90),
		P95:       percentile(values, 95),
		P99:       percentile(values, 99),
		Max:       values[len(values)-1],
		Histogram: histogram(values),
	}
}

// Histogram bounds. Fewer than a dozen bars cannot show a shape; more
// than thirty are too thin to read in a card-sized chart.
const (
	minBins    = 12
	targetBins = 20
	maxBins    = 30
)

// histogram bins an ascending slice into contiguous bins on round
// boundaries -- a width of 1, 2, 2.5 or 5 times a power of ten -- so the
// axis labels are numbers a person would have picked.
//
// The width is the smallest round number that fits the range in about
// twenty bins, which lands between ten and twenty-one; a short result is
// padded with empty bins above the data rather than narrowed, so a tight
// distribution still reads as tight.
func histogram(sorted []float64) []Bin {
	if len(sorted) == 0 {
		return []Bin{}
	}
	lo, hi := sorted[0], sorted[len(sorted)-1]
	span := hi - lo
	if span <= 0 {
		// Every value the same. Any width shows that; one scaled to the
		// value keeps the bins from being absurdly fine.
		span = math.Max(math.Abs(hi), 1)
	}
	width := niceStep(span / targetBins)
	start := math.Floor(lo/width) * width
	n := int(math.Floor((hi-start)/width)) + 1
	n = max(n, minBins)
	n = min(n, maxBins)

	bins := make([]Bin, n)
	for i := range bins {
		bins[i] = Bin{Lo: cleanEdge(start + float64(i)*width), Hi: cleanEdge(start + float64(i+1)*width)}
	}
	for _, v := range sorted {
		i := int(math.Floor((v - start) / width))
		i = max(i, 0)
		i = min(i, n-1)
		bins[i].Count++
	}
	return bins
}

// niceStep is the smallest of 1, 2, 2.5, 5 times a power of ten that is
// at least x.
func niceStep(x float64) float64 {
	if x <= 0 {
		return 1
	}
	exp := math.Floor(math.Log10(x))
	base := math.Pow(10, exp)
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if m*base >= x*(1-1e-12) {
			return m * base
		}
	}
	return 10 * base
}

// cleanEdge removes the floating-point dust that start+i*width collects,
// so a bin edge of 0.3 is not sent as 0.30000000000000004.
func cleanEdge(x float64) float64 {
	return math.Round(x*1e9) / 1e9
}

// niceMiB rounds a memory amount UP to a value a person would type: 128
// MiB steps under 1 GiB, 256 under 4 GiB, 512 under 16 GiB, whole GiB
// above. Rounding up, never down: these become requests, and a request
// rounded below what the job needs is a hold.
func niceMiB(x float64) float64 {
	if x <= 0 {
		return 128
	}
	var step float64
	switch {
	case x < 1024:
		step = 128
	case x < 4*1024:
		step = 256
	case x < 16*1024:
		step = 512
	default:
		step = 1024
	}
	return math.Ceil(x/step-1e-9) * step
}

// summarizeRequest describes a set of requested values: the most common
// one, the range and how many different values were asked for. A tie for
// most common goes to the larger value, the one fewer jobs would outgrow.
func summarizeRequest(values []float64) *Request {
	if len(values) == 0 {
		return nil
	}
	counts := make(map[float64]int, 4)
	r := &Request{Min: values[0], Max: values[0]}
	for _, v := range values {
		counts[v]++
		r.Min = math.Min(r.Min, v)
		r.Max = math.Max(r.Max, v)
	}
	best := 0
	for v, c := range counts {
		if c > best || (c == best && v > r.Typical) {
			best, r.Typical = c, v
		}
	}
	r.Distinct = len(counts)
	return r
}

// round keeps a figure to a sensible number of decimal places for JSON.
func round(x float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(x*p) / p
}

// ptr returns a pointer to a rounded copy of x.
func ptr(x float64, places int) *float64 {
	v := round(x, places)
	return &v
}

// confidence grades advice by how many jobs it rests on.
func confidence(n int) string {
	switch {
	case n < 50:
		return "low"
	case n < 200:
		return "medium"
	default:
		return "high"
	}
}
