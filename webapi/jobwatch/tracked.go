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
	if err := json.Unmarshal([]byte(blob), &ranges); err == nil && looksLikeRanges(ranges) {
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

// looksLikeRanges distinguishes the two encodings. They are both JSON
// arrays of objects, so the discriminator is the key set: a range has
// "t", a bare JobID does not, and json.Unmarshal leaves it zero.
//
// An empty array is ambiguous and means the same thing either way.
func looksLikeRanges(ranges []jobRange) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, r := range ranges {
		if r.To != 0 || r.From != 0 {
			return true
		}
	}
	// Every range decoded to zeroes, which is what the old encoding
	// produces: its keys are cluster_id/proc_id, and none of them match.
	return false
}
