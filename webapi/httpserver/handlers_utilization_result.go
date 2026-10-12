package httpserver

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// utilizationResult is one cached analysis: the compact list the list
// endpoint sends, and each workflow's full detail for the detail
// endpoint.
//
// The details are kept as gzip-compressed JSON. Held as structs they are
// the bulk of an analysis -- 246 MB of JSON for a million synthetic jobs
// in eleven thousand workflows, nearly all of which nobody will open --
// and compressed they are 44 MB, decompressed in well under a
// millisecond for the one that is.
type utilizationResult struct {
	summary *utilization.Summary
	details map[string][]byte
	// size is the summary's encoded size plus every compressed detail,
	// for the cache's bound.
	size int
	// timing is how long each phase of producing it took.
	timing utilizationTiming
}

// utilizationTiming is where an analysis spent its time, for the log, the
// utilization_phase_seconds histogram, and the Server-Timing header.
type utilizationTiming struct {
	source string
	rows   int
	// read is the wall time from the query to the last record.
	read time.Duration
	// decode is the time spent parsing records and building Jobs,
	// summed across the decoding goroutines: it runs alongside read, so
	// it can exceed it.
	decode time.Duration
	// decodeWait is the wall time after the last record until the last
	// one was decoded; with decoding keeping up with the read, near zero.
	decodeWait time.Duration
	analyze    time.Duration
	summary    time.Duration
	compress   time.Duration
	// done is when the result was finished.
	done time.Time
}

// phases lists the timed phases, by name, in the order they run.
func (t utilizationTiming) phases() []struct {
	name string
	d    time.Duration
} {
	return []struct {
		name string
		d    time.Duration
	}{
		{"read", t.read},
		{"decode", t.decode},
		{"decode_wait", t.decodeWait},
		{"analyze", t.analyze},
		{"summary", t.summary},
		{"compress", t.compress},
	}
}

// logArgs is the timing as key/value pairs for a log line.
func (t utilizationTiming) logArgs() []any {
	args := []any{"source", t.source, "rows", t.rows}
	for _, p := range t.phases() {
		args = append(args, p.name+"_ms", p.d.Milliseconds())
	}
	return args
}

// serverTiming is the Server-Timing header value for a response served
// to a request that began at begin: the phases of the computation that
// produced the result, and whether that computation was this request's
// or an earlier one's ("cache;desc=hit").
func (t utilizationTiming) serverTiming(begin time.Time) string {
	var b strings.Builder
	hit := "miss"
	if t.done.Before(begin) {
		hit = "hit"
	}
	fmt.Fprintf(&b, "cache;desc=%s", hit)
	for _, p := range t.phases() {
		fmt.Fprintf(&b, ", %s;dur=%.1f", p.name, float64(p.d.Microseconds())/1000)
	}
	return b.String()
}

// observeUtilizationPhases records a computation's phases in the
// utilization_phase_seconds histogram.
func (s *Handler) observeUtilizationPhases(t utilizationTiming) {
	if s.httpMetricsState == nil {
		return
	}
	for _, p := range t.phases() {
		s.httpMetricsState.utilizationPhase.WithLabelValues(p.name).Observe(p.d.Seconds())
	}
}

func newUtilizationResult(resp *utilization.Response, timing utilizationTiming) (*utilizationResult, error) {
	start := time.Now()
	res := &utilizationResult{
		summary: utilization.Summarize(resp),
		details: make(map[string][]byte, len(resp.Workflows)),
		timing:  timing,
	}
	encoded, err := json.Marshal(res.summary)
	if err != nil {
		return nil, err
	}
	res.size = len(encoded)
	res.timing.summary = time.Since(start)
	start = time.Now()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	for i := range resp.Workflows {
		raw, err := json.Marshal(&resp.Workflows[i])
		if err != nil {
			return nil, err
		}
		buf.Reset()
		zw.Reset(&buf)
		if _, err := zw.Write(raw); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		gz := bytes.Clone(buf.Bytes())
		res.details[resp.Workflows[i].Key] = gz
		res.size += len(gz)
	}
	res.timing.compress = time.Since(start)
	res.timing.done = time.Now()
	return res, nil
}

// workflow is one workflow's full detail as JSON; ok is false for a key
// the analysis does not have.
func (r *utilizationResult) workflow(key string) (json.RawMessage, bool, error) {
	gz, ok := r.details[key]
	if !ok {
		return nil, false, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, true, fmt.Errorf("reading a cached workflow: %w", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, true, fmt.Errorf("reading a cached workflow: %w", err)
	}
	return raw, true, nil
}

// workflowSummary is a workflow's list row, by key.
func (r *utilizationResult) workflowSummary(key string) (utilization.WorkflowSummary, bool) {
	for _, w := range r.summary.Workflows {
		if w.Key == key {
			return w, true
		}
	}
	return utilization.WorkflowSummary{}, false
}
