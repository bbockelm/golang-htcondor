package httpserver

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

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
}

func newUtilizationResult(resp *utilization.Response) (*utilizationResult, error) {
	res := &utilizationResult{
		summary: utilization.Summarize(resp),
		details: make(map[string][]byte, len(resp.Workflows)),
	}
	encoded, err := json.Marshal(res.summary)
	if err != nil {
		return nil, err
	}
	res.size = len(encoded)
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
