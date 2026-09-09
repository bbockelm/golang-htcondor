package spool

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/PelicanPlatform/classad/classad"
)

// SpoolingHoldCode is the hold a job sits in between submit and the end
// of input spooling. It is the only state a cluster-wide upload acts on:
// a proc that is running, finished, or held for a real reason is not
// waiting for this tar.
const SpoolingHoldCode = 16

// Limits bound one fan-out.
//
// The work is the same work a caller would do with N separate uploads;
// what these prevent is one call quietly becoming an unbounded amount of
// it. A fan-out that cannot finish reports what remains rather than doing
// a fraction silently.
type Limits struct {
	// MaxProcs is how many procs one call will spool. Past this the
	// answer is not a bigger upload but HTTP/HTTPS URLs in
	// transfer_input_files, which the execute nodes fetch themselves.
	MaxProcs int
	// MaxVolume bounds tar size x procs for one call.
	MaxVolume int64
	// Concurrency is how many uploads are in flight at once. Each is its
	// own schedd session, so this bounds load rather than chasing speed:
	// serial would be needlessly slow, unbounded would be a way to hurt
	// the schedd.
	Concurrency int
}

// DefaultLimits are what both the MCP tool and the REST endpoints use.
func DefaultLimits() Limits {
	return Limits{MaxProcs: 1000, MaxVolume: 1000 << 20, Concurrency: 10}
}

// SpoolFunc is one proc's spool -- htcondor.Schedd.SpoolJobFilesFromTar,
// or a stand-in. Taking it as an argument keeps this package independent
// of either server, and makes the properties that matter about a fan-out
// testable: that every proc is attempted, and that no more than the
// intended number are in flight, neither of which is observable through
// a real schedd.
type SpoolFunc func(ctx context.Context, ads []*classad.ClassAd, r io.Reader) error

// Result is the outcome of one fan-out.
type Result struct {
	// Spooled are the procs that took the tar, sorted.
	Spooled []string
	// Failed maps a proc to why its spool failed.
	Failed map[string]string
	// NotAttempted is how many procs were still awaiting input but fell
	// outside this call's limits. Non-zero means "call again".
	NotAttempted int
	// Capped says the limits, not the cluster, decided where this call
	// stopped.
	Capped bool
}

// Remaining is how many procs of the cluster still need input.
func (r Result) Remaining() int { return r.NotAttempted + len(r.Failed) }

// Plan trims ads to what one call may attempt, and says what was left.
//
// Trimming rather than refusing: partial progress plus an accurate count
// of the remainder is more useful than an error, and the caller can call
// again. A single proc that alone exceeds MaxVolume is an error, because
// there is no progress to make.
func Plan(ads []*classad.ClassAd, size int64, lim Limits) ([]*classad.ClassAd, Result, error) {
	res := Result{Failed: map[string]string{}}
	awaiting := len(ads)

	if lim.MaxProcs > 0 && len(ads) > lim.MaxProcs {
		ads = ads[:lim.MaxProcs]
		res.Capped = true
	}
	if size > 0 && lim.MaxVolume > 0 {
		affordable := int(lim.MaxVolume / size)
		if affordable < 1 {
			return nil, res, fmt.Errorf(
				"one proc's upload is %d bytes, over the %d byte limit for a single call; "+
					"use HTTP/HTTPS URLs in transfer_input_files instead", size, lim.MaxVolume)
		}
		if affordable < len(ads) {
			ads = ads[:affordable]
			res.Capped = true
		}
	}
	res.NotAttempted = awaiting - len(ads)
	return ads, res, nil
}

// FanOut spools src to each proc in ads, at most lim.Concurrency at once.
//
// Each proc gets its own reader from src. Sharing one reader would leave
// the first proc with the tar and the rest with nothing -- and the schedd
// accepts a short tar without complaint, so those procs would leave their
// hold and fail at run time on a missing file.
func FanOut(ctx context.Context, ads []*classad.ClassAd, src Source, lim Limits, spool SpoolFunc) Result {
	res := Result{Failed: map[string]string{}}
	conc := lim.Concurrency
	if conc < 1 {
		conc = 1
	}

	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for _, ad := range ads {
		wg.Add(1)
		go func(ad *classad.ClassAd) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			id := ProcID(ad)

			r, err := src.Reader()
			if err != nil {
				mu.Lock()
				res.Failed[id] = err.Error()
				mu.Unlock()
				return
			}
			defer func() { _ = r.Close() }()

			err = spool(ctx, []*classad.ClassAd{ad}, r)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Failed[id] = err.Error()
				return
			}
			res.Spooled = append(res.Spooled, id)
		}(ad)
	}
	wg.Wait()

	sort.Strings(res.Spooled)
	return res
}

// ProcID renders a proc ad's cluster.proc.
func ProcID(ad *classad.ClassAd) string {
	c, _ := ad.EvaluateAttrInt("ClusterId")
	p, _ := ad.EvaluateAttrInt("ProcId")
	return fmt.Sprintf("%d.%d", c, p)
}

// AwaitingInputConstraint matches the procs of a cluster that are held
// for input spooling.
func AwaitingInputConstraint(cluster int) string {
	return fmt.Sprintf("ClusterId == %d && JobStatus == 5 && HoldReasonCode == %d",
		cluster, SpoolingHoldCode)
}

// SortByProc orders ads oldest proc first, so partial progress is
// predictable rather than whatever order the schedd answered in.
func SortByProc(ads []*classad.ClassAd) {
	sort.SliceStable(ads, func(i, j int) bool {
		pi, _ := ads[i].EvaluateAttrInt("ProcId")
		pj, _ := ads[j].EvaluateAttrInt("ProcId")
		return pi < pj
	})
}
