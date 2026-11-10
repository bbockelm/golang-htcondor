package batches

import "testing"

func p64(v int64) *int64 { return &v }

// job is a queue or history ad of cluster c with status s.
func job(c, s int64) Fields {
	return Fields{ClusterID: p64(c), ProcID: p64(0), JobStatus: p64(s)}
}

func withTotal(f Fields, total int64) Fields { f.TotalProcs = p64(total); return f }

func part(p Progress, name string) int64 {
	for _, x := range p.Parts {
		if x.Part == name {
			return x.Count
		}
	}
	return -1
}

// The cases of lib/batchProgress.test.ts, and the server's own: a
// finished batch, known only from history, is all done.
func TestProgressOf(t *testing.T) {
	var running []Fields
	for range 5 {
		running = append(running, withTotal(job(1, 2), 100))
	}
	for range 4 {
		running = append(running, withTotal(job(1, 1), 100))
	}
	for range 3 {
		running = append(running, withTotal(job(1, 5), 100))
	}
	p := ProgressOf(running, true)
	if !p.Known || p.Unit != "jobs" || p.Total != 100 || p.Done != 88 ||
		part(p, "running") != 5 || part(p, "idle") != 4 || part(p, "held") != 3 {
		t.Errorf("88 of 100: %+v", p)
	}

	// Completed and removed jobs still in the queue are done.
	if p := ProgressOf([]Fields{withTotal(job(2, 4), 3), withTotal(job(2, 3), 3), withTotal(job(2, 1), 3)}, true); p.Done != 2 {
		t.Errorf("finished in the queue: %+v", p)
	}
	// A cluster without a total: no number.
	if p := ProgressOf([]Fields{withTotal(job(3, 1), 10), job(4, 1)}, true); p.Known || p.Why != WhyNoTotal {
		t.Errorf("no total: %+v", p)
	}
	// An incomplete read: no number.
	if p := ProgressOf([]Fields{withTotal(job(3, 1), 10)}, false); p.Known || p.Why != WhyPartial {
		t.Errorf("partial: %+v", p)
	}
	// A factory: procs not yet queued are not done.
	f := withTotal(job(5, 1), 1000)
	f.NextProcID = p64(10)
	idle := []Fields{f, f, f, f, f}
	if p := ProgressOf(idle, true); p.Done != 5 || p.Total != 1000 || p.NotQueued != 990 || part(p, "idle") != 995 {
		t.Errorf("factory: %+v", p)
	}
	// The spooling hold is not "held".
	spool := withTotal(job(6, 5), 1)
	spool.HoldReasonCode = p64(16)
	if p := ProgressOf([]Fields{spool}, true); part(p, "held") != 0 || part(p, "other") != 1 {
		t.Errorf("spooling: %+v", p)
	}
	// A batch that has left the queue entirely, read from history: done.
	var finished []Fields
	for range 7 {
		finished = append(finished, withTotal(job(7, 4), 8))
	}
	finished = append(finished, withTotal(job(7, 3), 8))
	if p := ProgressOf(finished, true); !p.Known || p.Done != 8 || p.Total != 8 {
		t.Errorf("finished batch: %+v", p)
	}
}

func TestProgressOfDAG(t *testing.T) {
	root := Fields{ClusterID: p64(1), JobStatus: p64(2), Cmd: "condor_dagman",
		DAGNodesTotal: p64(40), DAGNodesDone: p64(17), DAGNodesFailed: p64(3), DAGNodesQueued: p64(5)}
	node := Fields{ClusterID: p64(2), JobStatus: p64(2), DAGManJobID: p64(1)}
	p := ProgressOf([]Fields{root, node}, false)
	if !p.Known || p.Unit != "nodes" || p.Total != 40 || p.Done != 17 || p.Failed != 3 ||
		part(p, "queued") != 5 || part(p, "other") != 15 {
		t.Errorf("dag: %+v", p)
	}
	if p := ProgressOf([]Fields{root, node, job(9, 1)}, true); p.Known || p.Why != WhyMixed {
		t.Errorf("mixed: %+v", p)
	}
	if p := ProgressOf([]Fields{node}, true); p.Known || p.Why != WhyDagMissing {
		t.Errorf("no root: %+v", p)
	}
	silent := Fields{ClusterID: p64(1), JobStatus: p64(1), Cmd: "/usr/bin/condor_dagman"}
	if p := ProgressOf([]Fields{silent, node}, true); p.Known || p.Why != WhyDagNotReporting {
		t.Errorf("not reporting: %+v", p)
	}
}
