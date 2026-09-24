package httpserver

import (
	"context"
	"fmt"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Universes that matter to remote access. The full list lives in
// HTCondor's condor_attributes.h; only the two the schedd refuses are
// named here.
const (
	jobUniverseScheduler = 7
	jobUniverseGrid      = 9
)

// jobUniverseRefusesRemoteAccess reports whether the schedd will refuse
// GET_JOB_CONNECT_INFO for a job in this universe.
//
// Both condor_tail (STARTER_PEEK) and condor_ssh_to_job get at a job
// through the schedd's GET_JOB_CONNECT_INFO command, whose universe
// switch (condor_schedd.V6/schedd.cpp:18673) answers "Job N.M does not
// support remote access." for SCHEDULER (7) and GRID (9) and nothing
// else. Both are structural rather than transient: a scheduler-universe
// job runs on the access point as a child of the schedd, and a grid
// job runs on somebody else's batch system -- in neither case is there
// a starter to connect to, so retrying never helps.
//
// Every other universe the switch handles is reachable, LOCAL (12)
// included: a local-universe job does run under a starter, on the
// access point, and tail and ssh both work against it.
func jobUniverseRefusesRemoteAccess(universe int64) bool {
	return universe == jobUniverseScheduler || universe == jobUniverseGrid
}

// remoteAccessRefusalMessage explains the refusal above for one job.
// op is the thing the caller was trying to do -- "peek" or "ssh" --
// because the alternative differs: a scheduler-universe job's files are
// sitting in the spool and can simply be fetched, whereas there is no
// substitute for a shell.
//
// Callers must only use this for universes jobUniverseRefusesRemoteAccess
// accepts; anything else would be describing a refusal that did not
// happen.
func remoteAccessRefusalMessage(op string, cluster, proc int, universe int64) string {
	job := fmt.Sprintf("%d.%d", cluster, proc)
	scheduler := universe == jobUniverseScheduler

	var what string
	if scheduler {
		what = fmt.Sprintf("Job %s is a scheduler-universe job (JobUniverse=7)", job)
	} else {
		what = fmt.Sprintf("Job %s is a grid-universe job (JobUniverse=9)", job)
	}

	if op == "ssh" {
		if scheduler {
			return what + "; condor_ssh_to_job needs a starter and there is none."
		}
		return what + "; the job runs on a remote batch system, and condor_ssh_to_job needs a starter and there is none."
	}

	if scheduler {
		// The spool sentence is the useful half: a scheduler-universe
		// job (a DAGMan manager, typically) writes its stdout/stderr
		// and everything else IN PLACE in its spool directory while it
		// runs, and the schedd serves those files for a running job.
		return what + ". It runs on the access point under the schedd, not under a starter, so there is " +
			"nothing to tail. Its stdout/stderr and other files are written in place in the job's spool " +
			"directory: fetch them with GET /api/v1/jobs/" + job + "/stdout, /stderr, or /files/{name}."
	}
	return what + ". The job runs on a remote batch system; HTCondor has no starter to reach, so there is nothing to tail."
}

// jobUniverseLookupTimeout bounds the one-ad query below. It is a
// single schedd round trip on the fast path of an interactive request,
// so it gets a short leash: failing open costs a worse error message,
// while hanging here costs the whole request.
const jobUniverseLookupTimeout = 10 * time.Second

// jobUniverse reads JobUniverse for one job out of the queue.
//
// The second return is false when the answer is unknown -- no schedd
// configured, query failed, job not in the queue, or an ad without the
// attribute. Callers must treat that as "do not refuse": this lookup
// exists to improve an error message, and a queue hiccup must not
// become a refusal of an operation that would have worked.
func (s *Handler) jobUniverse(ctx context.Context, cluster, proc int) (int64, bool) {
	schedd := s.getSchedd()
	if schedd == nil {
		return 0, false
	}
	lookupCtx, cancel := context.WithTimeout(ctx, jobUniverseLookupTimeout)
	defer cancel()

	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	ads, _, err := schedd.QueryWithOptions(lookupCtx, constraint, &htcondor.QueryOptions{
		Projection: []string{"ClusterId", "ProcId", "JobStatus", "JobUniverse"},
		Limit:      1,
	})
	if err != nil || len(ads) == 0 {
		return 0, false
	}
	universe, found := ads[0].EvaluateAttrInt("JobUniverse")
	if !found {
		return 0, false
	}
	return universe, true
}

// refuseRemoteAccessByUniverse is the shared gate for the tail and
// shell endpoints: it reports whether the job's universe makes the
// operation impossible, and if so with what explanation. Both callers
// turn a non-empty message into a 409.
func (s *Handler) refuseRemoteAccessByUniverse(ctx context.Context, op string, cluster, proc int) (string, bool) {
	universe, known := s.jobUniverse(ctx, cluster, proc)
	if !known || !jobUniverseRefusesRemoteAccess(universe) {
		return "", false
	}
	return remoteAccessRefusalMessage(op, cluster, proc, universe), true
}
