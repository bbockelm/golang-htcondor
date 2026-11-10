package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Bulk constraint actions in multi-AP mode: POST /api/v1/jobs/hold and
// /release, DELETE /api/v1/jobs and PATCH /api/v1/jobs fan out to every
// member (multiap.Service.FanOut) and report per AP.
//
// Each AP's leg is scoped exactly as the single-AP handler scopes its one
// schedd -- jobsOwnerScope on a context routed to that AP -- so the owner
// clause is the same parse-and-reserialize AND, and the cross-user
// exemption is the one that AP grants (its QUEUE_SUPER_USERS).

// bulkLeg is one AP's action: the scoped constraint, on a context routed
// to the AP.
type bulkLeg func(ctx context.Context, schedd *htcondor.Schedd, constraint string) (multiap.BulkOutcome, error)

// MultiAPBulkResponse is the body of a multi-AP bulk action.
type MultiAPBulkResponse struct {
	Message    string `json:"message"`
	Constraint string `json:"constraint"`
	multiap.BulkReport
}

// runMultiBulk authenticates, fans leg out over the AP set, and writes
// the report.
//
// members, when non-nil, is the AP set a caller vetted (see
// handleMultiBulkEdit); nil fans out over the registry.
func (h *Handler) runMultiBulk(w http.ResponseWriter, r *http.Request, rawConstraint, verb string,
	members []apregistry.Member, leg bulkLeg) {
	ctx, needsRedirect, err := h.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			h.redirectToLogin(w, r)
			return
		}
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		h.writeError(w, http.StatusUnauthorized, "Authentication required: the caller's identity could not be established")
		return
	}
	user, err := h.multi.svc.UserFor(actor)
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	routed := func(m apregistry.Member) context.Context {
		return multiap.WithTarget(ctx, multiap.Target{Member: m})
	}
	rep, err := h.multi.svc.FanOut(ctx, multiap.BulkRequest{
		User: user, Owner: ownerFromActor(actor), Constraint: rawConstraint,
		AllUsers: func(ap string) bool {
			m, ok := h.multi.svc.Registry.Get(ap)
			return ok && h.seesAllJobs(routed(m), r, jobScopeMutate)
		},
		FreshWithin: h.multi.bulkFresh,
		Members:     members,
	}, func(legCtx context.Context, m apregistry.Member) (multiap.BulkOutcome, error) {
		apCtx := multiap.WithTarget(legCtx, multiap.Target{Member: m})
		constraint, err := h.jobsOwnerScope(apCtx, r, rawConstraint, jobScopeMutate)
		if err != nil {
			return multiap.BulkOutcome{}, err
		}
		if h.multi.observeBulkLeg != nil {
			h.multi.observeBulkLeg(m.Name, constraint)
		}
		return leg(apCtx, h.scheddFor(apCtx), constraint)
	})
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	// Recorded here as well as answered: the fan-out runs to the end even
	// when the client has gone, and this is then the only account of it.
	h.logger.Info(logging.DestinationHTTP, "Multi-AP bulk action",
		"action", verb, "actor", actor, "constraint", rawConstraint, "complete", rep.Complete,
		"total", rep.Totals.Total, "success", rep.Totals.Success, "edited", rep.Edited, "access_points", rep.BulkSummary())
	h.writeMultiBulk(w, rawConstraint, verb, rep)
}

// writeMultiBulk answers a fan-out: 404 when every AP was accounted for
// and nothing matched anywhere, 502 when no AP could be acted on and
// some failed, 200 otherwise -- with "complete" false when some AP was
// not acted on, which the per-AP list explains.
func (h *Handler) writeMultiBulk(w http.ResponseWriter, constraint, verb string, rep *multiap.BulkReport) {
	body := MultiAPBulkResponse{
		Message:    fmt.Sprintf("Bulk job %s completed on every access point", verb),
		Constraint: constraint,
		BulkReport: *rep,
	}
	ok, failed := rep.Contacted()
	status := http.StatusOK
	switch {
	case rep.Complete && !rep.Matched():
		status = http.StatusNotFound
		body.Message = "No jobs matched the constraint on any access point"
	case ok == 0 && failed > 0:
		status = http.StatusBadGateway
		body.Message = fmt.Sprintf("Bulk job %s failed on every access point it reached", verb)
	case !rep.Complete:
		body.Message = fmt.Sprintf("Bulk job %s did not reach every access point; see aps", verb)
	}
	h.writeJSON(w, status, body)
}

// actionOutcome turns a schedd job action's answer into a leg outcome:
// nothing matched and every match refused are outcomes, not failures.
func actionOutcome(res *htcondor.JobActionResults, err error) (multiap.BulkOutcome, error) {
	if refused, ok := refusedResults(err); ok {
		res, err = refused, nil
	}
	if errors.Is(err, htcondor.ErrNoJobsMatched) {
		return multiap.BulkOutcome{}, nil
	}
	if err != nil {
		return multiap.BulkOutcome{}, err
	}
	return multiap.BulkOutcome{Counts: multiap.CountsOf(res)}, nil
}

// handleMultiBulkAction serves POST /api/v1/jobs/hold and /release.
func (h *Handler) handleMultiBulkAction(w http.ResponseWriter, r *http.Request, verb string) {
	actionName := "Held"
	if verb == "release" {
		actionName = "Released"
	}
	constraint, reason, err := h.parseBulkActionRequest(r, actionName)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.runMultiBulk(w, r, constraint, verb, nil, func(ctx context.Context, sch *htcondor.Schedd, c string) (multiap.BulkOutcome, error) {
		if verb == "release" {
			return actionOutcome(sch.ReleaseJobs(ctx, c, reason))
		}
		return actionOutcome(sch.HoldJobs(ctx, c, reason))
	})
}

// handleMultiBulkDelete serves DELETE /api/v1/jobs.
func (h *Handler) handleMultiBulkDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Constraint string `json:"constraint"`
		Reason     string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	if req.Constraint == "" {
		h.writeError(w, http.StatusBadRequest, "Constraint is required for bulk delete")
		return
	}
	if req.Reason == "" {
		req.Reason = "Removed via HTTP API bulk operation"
	}
	h.runMultiBulk(w, r, req.Constraint, "removal", nil, func(ctx context.Context, sch *htcondor.Schedd, c string) (multiap.BulkOutcome, error) {
		return actionOutcome(sch.RemoveJobs(ctx, c, req.Reason))
	})
}

// handleMultiBulkEdit serves PATCH /api/v1/jobs.
func (h *Handler) handleMultiBulkEdit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Constraint string                 `json:"constraint"`
		Attributes map[string]interface{} `json:"attributes"`
		Options    *struct {
			AllowProtectedAttrs bool `json:"allow_protected_attrs,omitempty"`
			Force               bool `json:"force,omitempty"`
		} `json:"options,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	if req.Constraint == "" {
		h.writeError(w, http.StatusBadRequest, "Constraint is required for bulk edit")
		return
	}
	if len(req.Attributes) == 0 {
		h.writeError(w, http.StatusBadRequest, "No attributes to update")
		return
	}
	attributes := make(map[string]string, len(req.Attributes))
	for key, value := range req.Attributes {
		encoded, err := encodeJobAttributeValue(key, value)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		attributes[key] = encoded
	}
	opts := &htcondor.EditJobOptions{}
	var vetted []apregistry.Member
	if req.Options != nil && (req.Options.AllowProtectedAttrs || req.Options.Force) {
		// An administrator's lever, and in multi-AP mode an AP's: it is
		// granted only to a caller who is a queue superuser on every AP
		// the edit could reach, checked before anything is changed.
		ctx, _, err := h.requireAuthentication(r)
		if err != nil {
			h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		// The set checked here is the set acted on: a member that joins
		// between the check and the fan-out was never vetted.
		for _, m := range h.multi.svc.Registry.Members() {
			if !m.Present || m.Untrusted() {
				continue
			}
			vetted = append(vetted, m)
			if !h.seesAllJobs(multiap.WithTarget(ctx, multiap.Target{Member: m}), r, jobScopeMutate) {
				h.writeError(w, http.StatusForbidden, fmt.Sprintf(
					"options.allow_protected_attrs and options.force need administrator rights on every access point, "+
						"and you have none on %s", m.Name))
				return
			}
		}
		if len(vetted) == 0 {
			h.writeError(w, http.StatusServiceUnavailable, "no access point is available to edit jobs on")
			return
		}
		opts.AllowProtectedAttrs, opts.Force = req.Options.AllowProtectedAttrs, req.Options.Force
	}
	h.runMultiBulk(w, r, req.Constraint, "edit", vetted, func(ctx context.Context, sch *htcondor.Schedd, c string) (multiap.BulkOutcome, error) {
		n, err := sch.EditJobs(ctx, c, attributes, opts)
		if errors.Is(err, htcondor.ErrNoJobsMatched) {
			return multiap.BulkOutcome{}, nil
		}
		if err != nil {
			return multiap.BulkOutcome{}, err
		}
		return multiap.BulkOutcome{Edited: n}, nil
	})
}
