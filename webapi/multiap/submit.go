package multiap

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

// Submission in multi-AP mode: AP assignment picks the AP.
//
// Assignment happens once per submission, here. Everything after it --
// the second step of a two-step submit, an upload, an action -- names the
// job by its complete id and is routed by that id (Route), never by
// asking again: a mapping that changed between the steps would otherwise
// spool input to an AP that does not have the job, and leave the job
// held waiting for it.

// Assigner places new work. *apassign.Chain satisfies it.
type Assigner interface {
	Resolve(ctx context.Context, req apassign.Request) (apassign.Assignment, error)
	Target(ctx context.Context, req apassign.Request, explicit string) (string, apassign.Assignment, error)
}

// ReasonSubmitUnconfigured is the reason when this server has no AP
// assignment.
const ReasonSubmitUnconfigured = "submit_unconfigured"

// fromAssign converts an apassign failure to this package's Error, so the
// surfaces render it with their usual status, reason and message.
func fromAssign(err error) error {
	var ae *apassign.Error
	if errors.As(err, &ae) {
		return &Error{Status: ae.Status, Reason: ae.Reason, Msg: ae.Msg}
	}
	var me *Error
	if errors.As(err, &me) {
		return err
	}
	return errorf(http.StatusServiceUnavailable, "access point assignment failed: %v", err)
}

// Assignment returns the caller's assignment: their home AP and
// alternates, validated against the AP set. For reporting (whoami,
// /api/v1/aps); a submission uses SubmitTarget.
func (s *Service) Assignment(ctx context.Context, req apassign.Request) (apassign.Assignment, error) {
	if s.Assign == nil {
		return apassign.Assignment{}, &Error{Status: http.StatusServiceUnavailable, Reason: ReasonSubmitUnconfigured,
			Msg: "this server has no access point assignment configured"}
	}
	a, err := s.Assign.Resolve(ctx, req)
	if err != nil {
		return apassign.Assignment{}, fromAssign(err)
	}
	return a, nil
}

// SubmitTarget picks the AP a new submission goes to -- the caller's home
// AP, or explicit when it names the home AP or one of the alternates --
// and returns it ready to act on: in the set, advertised, trusted, and
// admitting the caller.
func (s *Service) SubmitTarget(ctx context.Context, req apassign.Request, explicit string) (apregistry.Member, apassign.Assignment, error) {
	if req.User == "" {
		return apregistry.Member{}, apassign.Assignment{}, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	if s.Assign == nil {
		return apregistry.Member{}, apassign.Assignment{}, &Error{Status: http.StatusServiceUnavailable, Reason: ReasonSubmitUnconfigured,
			Msg: "this server has no access point assignment configured"}
	}
	name, a, err := s.Assign.Target(ctx, req, strings.TrimSpace(explicit))
	if err != nil {
		return apregistry.Member{}, a, fromAssign(err)
	}
	m, err := s.Member(name)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.Status == http.StatusNotFound {
			// The assignment validated against a set this AP has since
			// left: the server's problem, not the caller's.
			e.Status = http.StatusServiceUnavailable
		}
		return apregistry.Member{}, a, err
	}
	if err := s.AdmitTo(ctx, m, req.User); err != nil {
		return apregistry.Member{}, a, err
	}
	return m, a, nil
}

// InSet resolves name to the AP set's spelling of it, for the
// assignment chain's validation.
func (s *Service) InSet(name string) (string, bool) {
	m, ok := s.Registry.Get(name)
	if !ok {
		return "", false
	}
	return m.Name, true
}

// Usable reports why a member cannot take new work now, or nil: the same
// conditions as an action (advertised, trusted, an address).
func (s *Service) Usable(name string) error {
	_, err := s.Member(name)
	return err
}

// CredentialTarget picks the AP whose credd a credential operation acts
// on: explicit when given -- any AP in the set, since a user may hold
// jobs on an AP that is no longer their home -- else the caller's home
// AP. Credentials are per credd, and a credd is per AP.
func (s *Service) CredentialTarget(ctx context.Context, req apassign.Request, explicit string) (apregistry.Member, error) {
	if req.User == "" {
		return apregistry.Member{}, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	name := strings.TrimSpace(explicit)
	if name == "" {
		a, err := s.Assignment(ctx, req)
		if err != nil {
			return apregistry.Member{}, err
		}
		name = a.Schedd
	}
	m, err := s.Member(name)
	if err != nil {
		return apregistry.Member{}, err
	}
	if err := s.AdmitTo(ctx, m, req.User); err != nil {
		return apregistry.Member{}, err
	}
	return m, nil
}
