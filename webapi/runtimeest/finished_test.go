package runtimeest

import (
	"testing"
	"time"
)

// A finished job is judged unusual or not by the rules a running one is,
// applied to its final runtime and peak, and never against its own run.

// finishedCase ingests others (each a second apart) and then, when own is
// set, the finished job itself, and returns the query that job's history
// record makes.
func finishedCase(t *testing.T, others []memJob, own *memJob) (*Estimator, Query) {
	t.Helper()
	e := New(Config{})
	b := NewBatch()
	for i, j := range others {
		b.Add(Completion{Features: j.f, ProcID: int64(i), Runtime: j.runtime, PeakMemoryMiB: j.mem,
			Completed: t0.Add(time.Duration(i) * time.Second)})
	}
	done := t0.Add(time.Hour)
	f := simArgs("1")
	q := Query{Features: f, Finished: true, Completed: done.Unix()}
	if own != nil {
		b.Add(Completion{Features: own.f, ProcID: 999, Runtime: own.runtime, PeakMemoryMiB: own.mem, Completed: done})
		q.Features, q.Runtime, q.PeakMemoryMiB = own.f, own.runtime, own.mem
	}
	e.Ingest(b)
	return e, q
}

func TestFinishedAboveUsualMemory(t *testing.T) {
	cases := []struct {
		name   string
		others []memJob
		own    memJob
		want   bool
	}{
		// p90 2000: the factor binds (2500 > 2256).
		{"factor: at 1.25x", sameMem(10, 2000), memJob{simArgs("1"), 100, 2500}, true},
		{"factor: under 1.25x, over the margin", sameMem(10, 2000), memJob{simArgs("1"), 100, 2499}, false},
		// p90 400: the margin binds (656 > 500).
		{"margin: at +256", sameMem(10, 400), memJob{simArgs("1"), 100, 656}, true},
		{"margin: under +256, over 1.25x", sameMem(10, 400), memJob{simArgs("1"), 100, 655}, false},
		// Four others: five peaks with its own, four without -- too few.
		{"too few once its own run is left out", sameMem(minMemorySamples-1, 400), memJob{simArgs("1"), 100, 10_000}, false},
		{"just enough besides its own run", sameMem(minMemorySamples, 400), memJob{simArgs("1"), 100, 10_000}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, q := finishedCase(t, c.others, &c.own)
			r := e.Estimate(q)
			if r.Memory == nil || r.Basis.Level != "exact" {
				t.Fatalf("estimate = %+v, memory %+v", r, r.Memory)
			}
			if r.Memory.AboveUsual != c.want {
				t.Errorf("above_usual = %v, want %v (p90 shown %v, %d samples)", r.Memory.AboveUsual, c.want, r.Memory.P90MiB, r.Memory.SampleCount)
			}
		})
	}

	// A rough group never calls a job unusual: here a finished job whose
	// arguments nothing else ran, so only the program's runs answer.
	e, _ := finishedCase(t, sameMem(10, 400), nil)
	r := e.Estimate(Query{Features: simArgs("other"), Finished: true, Runtime: 100, Completed: t0.Unix() + 3600, PeakMemoryMiB: 10_000})
	if r.Basis == nil || r.Basis.Level != "cmd" || r.Memory == nil || r.Memory.AboveUsual {
		t.Errorf("rough group: %+v, memory %+v", r.Basis, r.Memory)
	}
	// Nor is a job that neither runs nor has finished.
	r = e.Estimate(Query{Features: simArgs("1"), PeakMemoryMiB: 10_000})
	if r.Memory == nil || r.Memory.AboveUsual {
		t.Errorf("waiting job: %+v", r.Memory)
	}
}

// The figures a finished job's Result shows still include its own run,
// as the similar-jobs view of the group does.
func TestFinishedFiguresIncludeItsOwnRun(t *testing.T) {
	e, q := finishedCase(t, sameMem(4, 400), &memJob{simArgs("1"), 100, 10_000})
	r := e.Estimate(q)
	if r.Memory == nil || r.Memory.SampleCount != 5 || r.Basis.SampleCount != 5 {
		t.Errorf("shown figures: basis %+v memory %+v; want all five runs", r.Basis, r.Memory)
	}
	if got := exactMemory(e, simArgs("1")); len(got) != 5 {
		t.Errorf("group memory = %v", got)
	}
}

// Ran longer than usual: longer than the median of the group's other
// runs, and fewer than minLonger of them lasted at least as long.
func TestFinishedExceededHistory(t *testing.T) {
	var spread []memJob
	for i := 1; i <= 10; i++ {
		spread = append(spread, memJob{simArgs("1"), float64(100 * i), 0})
	}
	cases := []struct {
		name    string
		others  []memJob
		runtime float64
		want    bool
	}{
		// 100..1000: two runs at or past 900, three at or past 800.
		{"two runs at least as long", spread, 900, true},
		{"three runs at least as long", spread, 800, false},
		{"between them", spread, 850, true},
		{"under the median", spread, 500, false},
		// A run as long as every other is not longer than usual; one
		// second more is.
		{"as long as all the others", sameMem(10, 0), 100, false},
		{"just longer than all the others", sameMem(10, 0), 101, true},
		// Exactly the median of two is typical, though only one ran as long.
		{"at the median", []memJob{{simArgs("1"), 50, 0}, {simArgs("1"), 150, 0}}, 100, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, q := finishedCase(t, c.others, &memJob{simArgs("1"), c.runtime, 0})
			r := e.Estimate(q)
			if !r.Available || r.ExceededHistory != c.want {
				t.Errorf("exceeded_history = %v, want %v (%+v)", r.ExceededHistory, c.want, r)
			}
		})
	}

	// Its own run is not one of the runs it is compared with: a job that
	// is alone in all its groups has nothing to be compared with.
	e, q := finishedCase(t, nil, &memJob{simArgs("1"), 5000, 0})
	if r := e.Estimate(q); r.Available || r.ExceededHistory {
		t.Errorf("a job alone in its group: %+v", r)
	}
	// Two others at 100 and its own 5000: compared with the two, not
	// with a median its own run pulled up.
	e, q = finishedCase(t, sameMem(2, 0), &memJob{simArgs("1"), 5000, 0})
	if r := e.Estimate(q); !r.ExceededHistory {
		t.Errorf("a job far past its two siblings: %+v", r)
	}
}

// A finished history record reads as a finished query, with the runtime
// and completion the estimator ingested it with; a removed one does not.
func TestQueryFromAdFinished(t *testing.T) {
	q := QueryFromAd(adFrom(t, `Owner = "a"
Cmd = "x"
JobStatus = 4
ExitCode = 0
JobUniverse = 5
RemoteWallClockTime = 300
CommittedTime = 250
CompletionDate = 5000
ResidentSetSize_RAW = 2097152`), time.Unix(9000, 0))
	if !q.Finished || q.Runtime != 250 || q.Completed != 5000 || q.PeakMemoryMiB != 2048 || q.Running {
		t.Errorf("finished query = %+v", q)
	}
	q = QueryFromAd(adFrom(t, "Owner = \"a\"\nJobStatus = 3\nRemoteWallClockTime = 300\nCompletionDate = 5000"), time.Unix(9000, 0))
	if q.Finished {
		t.Errorf("a removed job read as finished: %+v", q)
	}
}

// A group holding only the finished job itself does not answer for it:
// the one job of its cluster is compared with its other runs of the same
// command, not with itself.
func TestFinishedSkipsGroupsOfItself(t *testing.T) {
	// Ten runs of one earlier cluster predict each other as well at the
	// cluster level as at the exact one, so the more specific cluster
	// level is the one alice's jobs are answered from.
	others := sameMem(10, 1000)
	for i := range others {
		others[i].f.ClusterID = 5
	}
	own := memJob{Features{Owner: "alice", Cmd: "/home/alice/sim", Args: []string{"1"}, ClusterID: 77}, 5000, 6000}
	e, q := finishedCase(t, others, &own)
	r := e.Estimate(q)
	if r.Basis == nil || r.Basis.Level != "exact" || !r.ExceededHistory || r.Memory == nil || !r.Memory.AboveUsual {
		t.Errorf("estimate = %+v, basis %+v, memory %+v; want the exact group, both flags", r, r.Basis, r.Memory)
	}
	// Its cluster group holds it, and only it.
	if got := e.GroupRuntimes(DeriveKeys(own.f), LevelCluster); len(got) != 1 {
		t.Errorf("cluster group = %v", got)
	}
}
