// Making a job reachable before somebody needs it to be.
//
// Opening a transport into a job is a schedd query, a CEDAR connection
// to the execute node and an SSH handshake inside it. That is seconds,
// and sometimes many of them on a busy pool. An editor opening a
// remote window through the SSH gateway has its own deadline for the
// whole connection, and when the transport has to be built inside that
// deadline the connection is what gives way -- the user sees a timeout
// and no explanation, and the retry works because the first attempt
// left the transport behind.
//
// This endpoint is that first attempt, made deliberately: a client
// about to connect asks for the transport to exist, with a timeout it
// chooses, and then connects to something already warm.

package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
)

// warmResponse says what happened, in terms a client can act on.
type warmResponse struct {
	// Ready is true when there is now a transport to the job.
	Ready bool `json:"ready"`
	// Reused is true when there already was one, so nothing was paid
	// for. A client that sees this can skip warming next time.
	Reused bool `json:"reused"`
	// ElapsedMS is how long it took, which is the number worth logging
	// on the client: it is the cost the connection would otherwise
	// have carried.
	ElapsedMS int64 `json:"elapsed_ms"`
	// IdleTimeoutSeconds is how long the transport stays warm with
	// nothing using it, so a client knows how long it has to follow up.
	IdleTimeoutSeconds int `json:"idle_timeout_seconds"`
}

// handleJobWarm opens the transport into a job and leaves it cached.
// Path: POST /api/v1/jobs/{cluster}.{proc}/warm
func (s *Handler) handleJobWarm(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)

	// Same refusal as ssh-to-job, and for the same reason: a universe
	// with no starter has nothing to connect to, and saying so here is
	// better than a transport error later.
	if msg, refuse := s.refuseRemoteAccessByUniverse(ctx, "warm", cluster, proc); refuse {
		s.writeError(w, http.StatusConflict, msg)
		return
	}

	ctx, imp, err := s.superuserActionContext(ctx, r, cluster, proc)
	if err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}

	cache, err := s.getOrCreateJobSSHCache()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "job transport cache unavailable")
		return
	}

	// The same key the job proxy will use (jobTransportKey). Warming
	// under any other would warm a transport the connection that
	// follows cannot use, which is worse than not warming at all: it
	// pays the cost twice and looks like it worked.
	key := jobTransportKey(ctx, imp, username, cluster, proc)

	started := time.Now()
	reused, err := cache.Warm(ctx, key)
	elapsed := time.Since(started)
	if err != nil {
		s.logger.Info(logging.DestinationHTTP, "Could not warm a job transport",
			"user", username, "cluster", cluster, "proc", proc, "error", err)
		label, detail := describeShellOpenError(err)
		// 502: the access point is fine, the execute node could not be
		// reached. A client treats this as "connect anyway and see",
		// because warming is an optimisation and its failure is not a
		// reason to refuse the connection.
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("%s: %s", label, detail))
		return
	}
	if imp != nil {
		s.auditSuperuserAction(r, imp, "warm", fmt.Sprintf("%d.%d", cluster, proc), nil)
	}

	s.logger.Info(logging.DestinationHTTP, "Warmed a job transport",
		"user", username, "cluster", cluster, "proc", proc,
		"reused", reused, "elapsed_ms", elapsed.Milliseconds())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(warmResponse{
		Ready:              true,
		Reused:             reused,
		ElapsedMS:          elapsed.Milliseconds(),
		IdleTimeoutSeconds: int(jobssh.DefaultIdleTimeout / time.Second),
	})
}
