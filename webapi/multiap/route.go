package multiap

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

// Machine-readable reasons an action could not be routed, carried in
// Error.Reason and in the "reason" member of an error response.
const (
	// ReasonIncompleteID: a mutation named cluster.proc without its
	// access point.
	ReasonIncompleteID = "incomplete_job_id"
	// ReasonUnknownAP: the id names a schedd that is not in the AP set.
	ReasonUnknownAP = "unknown_access_point"
	// ReasonAPAbsent: the AP is a member, but its schedd ad is not in
	// the collector now.
	ReasonAPAbsent = "access_point_absent"
	// ReasonAPUntrusted: the AP refused this server's tokens, or mapped
	// them to another identity, at its last trust probe.
	ReasonAPUntrusted = "access_point_untrusted"
)

// untrustedMessage is what a caller is told about an AP that failed its
// trust probe. Fixed text, so it reads the same wherever it surfaces.
const untrustedMessage = "this access point does not trust this API server's tokens"

// Target is the access point an action was routed to, and the job it is
// about. The single-job handlers find it on the request's context.
type Target struct {
	Member apregistry.Member
	// ID is the complete job id. Zero for a target that names an AP
	// without a job (a bulk action's per-AP leg).
	ID jobid.ID
}

type targetKey struct{}

// WithTarget records the AP an action goes to.
func WithTarget(ctx context.Context, t Target) context.Context {
	return context.WithValue(ctx, targetKey{}, t)
}

// TargetFrom returns the AP an action was routed to.
func TargetFrom(ctx context.Context) (Target, bool) {
	t, ok := ctx.Value(targetKey{}).(Target)
	return t, ok
}

// Member returns the AP named schedd, ready to be acted on: in the set,
// advertised now, not marked untrusted, with a schedd handle. Every
// other case is an error naming which, never "no such job".
func (s *Service) Member(schedd string) (apregistry.Member, error) {
	if err := jobid.ValidSchedd(schedd); err != nil {
		return apregistry.Member{}, &Error{Status: http.StatusBadRequest, Reason: ReasonUnknownAP,
			Msg: fmt.Sprintf("invalid access point name %q: %v", schedd, err)}
	}
	m, ok := s.Registry.Get(schedd)
	if !ok {
		return apregistry.Member{}, &Error{Status: http.StatusNotFound, Reason: ReasonUnknownAP,
			Msg: fmt.Sprintf("%q is not an access point this server serves (see /api/v1/aps)", schedd)}
	}
	if !m.Present {
		last := "never"
		if !m.LastSeen.IsZero() {
			last = m.LastSeen.UTC().Format(time.RFC3339)
		}
		return apregistry.Member{}, &Error{Status: http.StatusServiceUnavailable, Reason: ReasonAPAbsent,
			Msg: fmt.Sprintf("access point %s is not advertised in the collector right now (last seen %s); "+
				"actions on its jobs are unavailable until it returns", m.Name, last)}
	}
	if m.Untrusted() {
		msg := fmt.Sprintf("access point %s: %s", m.Name, untrustedMessage)
		if m.Trust.Reason != "" {
			msg += " (" + m.Trust.Reason + ")"
		}
		return apregistry.Member{}, &Error{Status: http.StatusServiceUnavailable, Reason: ReasonAPUntrusted, Msg: msg}
	}
	if m.Schedd == nil {
		return apregistry.Member{}, &Error{Status: http.StatusServiceUnavailable, Reason: ReasonAPAbsent,
			Msg: fmt.Sprintf("access point %s has no known address", m.Name)}
	}
	return m, nil
}

// Route is scheddFor: the AP that owns id, for an action on it.
//
// A complete id is required. A bare cluster.proc is refused with 400
// and the caller's candidate jobs, because cluster ids on different APs
// are independent: the hub may resolve 123.0 to a finished job on ap1
// while the 123.0 just submitted on ap3 has not reached it, and a wrong
// guess on remove cannot be undone. user scopes the candidate lookup to
// the caller's own jobs; with it empty, or the hub unreachable, the 400
// carries no candidates.
//
// user is the caller's User value (UserFor), and is required: every
// routed action is on behalf of an established identity, and the AP's
// own verdict on it (Admit) is part of routing.
func (s *Service) Route(ctx context.Context, user string, id jobid.ID) (apregistry.Member, error) {
	if user == "" {
		return apregistry.Member{}, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	if err := jobid.Valid(id); err != nil {
		return apregistry.Member{}, errorf(http.StatusBadRequest, "invalid job id: %v", err)
	}
	if !id.Complete() {
		e := &Error{Status: http.StatusBadRequest, Reason: ReasonIncompleteID}
		e.Candidates = s.candidates(ctx, user, id)
		e.Msg = fmt.Sprintf("job %s does not name its access point; an action needs the complete id, such as %s",
			s.Codec.Format(id), s.Codec.Format(id.WithSchedd("ap.example.org")))
		if len(e.Candidates) > 0 {
			ids := make([]string, len(e.Candidates))
			for i, c := range e.Candidates {
				ids[i] = c.JobID
			}
			e.Msg += " (your jobs with that number: " + strings.Join(ids, ", ") + ")"
		}
		return apregistry.Member{}, e
	}
	m, err := s.Member(id.Schedd)
	if err != nil {
		return apregistry.Member{}, err
	}
	if err := s.AdmitTo(ctx, m, user); err != nil {
		return apregistry.Member{}, err
	}
	return m, nil
}

// ReasonDenied: the AP's own records refuse the caller (an account
// disabled there).
const ReasonDenied = "access_point_denied"

// AdmitTo asks the AP's own verdict on user (Service.Admit); nil when
// there is no verdict to ask for.
func (s *Service) AdmitTo(ctx context.Context, m apregistry.Member, user string) error {
	if s.Admit == nil {
		return nil
	}
	if err := s.Admit(ctx, m, user); err != nil {
		var e *Error
		if asError(err, &e) {
			return err
		}
		return &Error{Status: http.StatusForbidden, Reason: ReasonDenied,
			Msg: fmt.Sprintf("access point %s refuses you: %v", m.Name, err)}
	}
	return nil
}

// candidates lists the caller's jobs, live and archived, with id's
// cluster.proc on any AP. Best effort: an unreachable hub yields none.
func (s *Service) candidates(ctx context.Context, user string, id jobid.ID) []JobRef {
	if s.Hub == nil {
		return nil
	}
	cands, err := s.findCandidates(ctx, s.snapshot(), user, id)
	if err != nil {
		return nil
	}
	return cands
}

// ScheddFrom returns the schedd an action routed to ctx's target should
// use, or nil when ctx carries no target.
func ScheddFrom(ctx context.Context) *htcondor.Schedd {
	t, ok := TargetFrom(ctx)
	if !ok {
		return nil
	}
	return t.Member.Schedd
}

// CandidatesOf returns the candidate jobs an error carries.
func CandidatesOf(err error) []JobRef {
	var e *Error
	if asError(err, &e) {
		return e.Candidates
	}
	return nil
}

// ReasonOf returns an error's machine-readable reason, if it has one.
func ReasonOf(err error) string {
	var e *Error
	if asError(err, &e) {
		return e.Reason
	}
	return ""
}
