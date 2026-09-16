package jobwatch

import (
	"encoding/json"
	"fmt"
	"sort"
)

// The tracked set is every job a watch has ever selected, and it is
// rewritten on each pass that does not fire. Stored one entry per job it
// costs about 3.3 MB of JSON for a 100,000-job cluster, written every
// thirty seconds for as long as the work runs -- to record something
// that usually has not changed.
//
// Two things fix that. HTCondor numbers procs consecutively within a
// cluster, so the set is nearly always a handful of contiguous runs:
// range-encoding turns that 3.3 MB into a few dozen bytes. And a set
// that has not changed since it was loaded is not written at all, which
// removes the steady-state write entirely -- the interesting passes are
// the ones where a job appeared or finished, and those are rare compared
// with the passes that just confirm nothing moved.

// jobRange is an inclusive run of procs in one cluster.
type jobRange struct {
	Cluster int64 `json:"c"`
	From    int64 `json:"f"`
	To      int64 `json:"t"`
}

// encodeTracked renders a job set as coalesced ranges.
func encodeTracked(ids []JobID) (string, error) {
	sorted := append([]JobID(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Cluster != sorted[j].Cluster {
			return sorted[i].Cluster < sorted[j].Cluster
		}
		return sorted[i].Proc < sorted[j].Proc
	})

	ranges := make([]jobRange, 0, 8)
	for _, id := range sorted {
		if n := len(ranges); n > 0 {
			last := &ranges[n-1]
			switch {
			case last.Cluster == id.Cluster && id.Proc == last.To:
				continue // duplicate
			case last.Cluster == id.Cluster && id.Proc == last.To+1:
				last.To = id.Proc
				continue
			}
		}
		ranges = append(ranges, jobRange{Cluster: id.Cluster, From: id.Proc, To: id.Proc})
	}
	blob, err := json.Marshal(ranges)
	if err != nil {
		return "", fmt.Errorf("encoding the tracked set: %w", err)
	}
	return string(blob), nil
}

// decodeTracked expands the stored form. It accepts the older
// one-entry-per-job encoding as well, so a watch registered before this
// change keeps its memory across the upgrade -- losing it would mean
// forgetting jobs whose disappearance is the evidence a terminal event
// depends on.
func decodeTracked(blob string) ([]JobID, error) {
	if blob == "" || blob == "[]" {
		return nil, nil
	}
	var ranges []jobRange
	if err := json.Unmarshal([]byte(blob), &ranges); err == nil && looksLikeRanges(blob) {
		out := make([]JobID, 0, 16)
		for _, r := range ranges {
			if r.To < r.From {
				return nil, fmt.Errorf("decoding the tracked set: range %d.%d-%d is inverted", r.Cluster, r.From, r.To)
			}
			for proc := r.From; proc <= r.To; proc++ {
				out = append(out, JobID{Cluster: r.Cluster, Proc: proc})
			}
		}
		return out, nil
	}
	var ids []JobID
	if err := json.Unmarshal([]byte(blob), &ids); err != nil {
		return nil, fmt.Errorf("decoding the tracked set: %w", err)
	}
	return ids, nil
}

// looksLikeRanges distinguishes the two encodings by KEY, not by the
// values the keys decode to.
//
// The values cannot tell them apart. Both are JSON arrays of objects,
// and unmarshalling old-format rows (cluster_id/proc_id) into a
// jobRange leaves every field zero -- but so does a perfectly ordinary
// new-format row for a single job at proc 0, which is what
// `[{"c":N,"f":0,"t":0}]` is. Deciding on zeroes therefore misread the
// commonest submission there is (one job, proc 0) as the old format,
// and decoding it as JobIDs -- whose keys do not match either -- turned
// the tracked job into the ghost 0.0. The watch then tracked a job that
// does not exist and can never satisfy anything, so an "all" watch over
// an outcome that absence cannot resolve never fired.
//
// The key sets are disjoint, so the key is the honest discriminator.
func looksLikeRanges(blob string) bool {
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(blob), &rows); err != nil {
		return false
	}
	if len(rows) == 0 {
		// An empty array means the same thing either way.
		return true
	}
	for _, row := range rows {
		if _, ok := row["cluster_id"]; ok {
			return false
		}
	}
	return true
}
