// Package apassign answers one question for an htcondor-api that fronts
// several access points: which access point should this user's NEW work
// go to.
//
// Existing jobs stay where they are and are reached by their complete
// id; this package is consulted once per submission, and never again
// for the same job. Sites answer the question very differently, so the
// answer comes from an ordered chain of backends (static, mapfile, rest)
// with the behavior every backend needs -- caching, a hard timeout, the
// last known good answer when a backend breaks, validation against the
// AP set -- implemented once, in the Chain.
package apassign

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Kinds of work a submission can be.
const (
	KindJob            = "job"
	KindDAG            = "dag"
	KindInteractive    = "interactive"
	KindJupyter        = "jupyter"
	KindContainerBuild = "container_build"
)

// Request is who is asking, and for what kind of work.
type Request struct {
	// User is the HTCondor identity after mapping: alice@example.org,
	// the job's User attribute.
	User string
	// Subject is the authenticated principal as presented to this
	// server, before mapping to an HTCondor user.
	Subject string
	// Groups are the caller's groups, as the login recorded them.
	Groups []string
	// Kind is one of the Kind constants.
	Kind string
}

// Assignment is where a user's new work goes.
type Assignment struct {
	// Schedd is the home AP: its schedd's Name.
	Schedd string `json:"schedd"`
	// Alternates are other APs this user may target explicitly.
	Alternates []string `json:"alternates,omitempty"`
	// TTL is how long the answer may be reused. Zero means the
	// backend's default.
	TTL time.Duration `json:"-"`
	// Source names the backend that answered ("mapfile", "rest",
	// "static", "default"), for logs and /api/v1/aps.
	Source string `json:"source"`
	// Stale is set when the answer is a last known good one, served
	// because the backend that should answer is failing.
	Stale bool `json:"stale,omitempty"`
}

// Allows reports whether target names the assignment's Schedd or one of
// its Alternates, compared as schedd names are: without regard to case.
// It returns the assignment's spelling of the name.
func (a Assignment) Allows(target string) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", false
	}
	if strings.EqualFold(target, a.Schedd) {
		return a.Schedd, true
	}
	for _, alt := range a.Alternates {
		if strings.EqualFold(target, alt) {
			return alt, true
		}
	}
	return "", false
}

// Targets is the home AP followed by the alternates.
func (a Assignment) Targets() []string {
	if a.Schedd == "" {
		return nil
	}
	return append([]string{a.Schedd}, a.Alternates...)
}

// ErrNoAnswer is returned by a backend that has no answer for this user:
// the chain asks the next one.
var ErrNoAnswer = errors.New("no access point assignment for this user")

// ErrDenied is returned by a backend that refuses this user: the chain
// stops, and the user may not submit.
var ErrDenied = errors.New("this user may not submit work")

// Assigner is one backend. Assign returns an Assignment, ErrNoAnswer
// (not mine; ask the next backend), ErrDenied (stop: this user may not
// submit), or another error (the backend is broken; do not fall
// through).
type Assigner interface {
	Assign(ctx context.Context, req Request) (Assignment, error)
}

// Machine-readable reasons, in Error.Reason and the "reason" member of
// an HTTP error.
const (
	// ReasonNoAssignment: no backend answered and there is no default.
	ReasonNoAssignment = "no_access_point_assigned"
	// ReasonDenied: a backend refused the user.
	ReasonDenied = "assignment_denied"
	// ReasonUnavailable: the backend that should answer is failing,
	// and no recent answer for this user is known.
	ReasonUnavailable = "assignment_unavailable"
	// ReasonInvalid: the answer names an AP outside the AP set.
	ReasonInvalid = "assignment_invalid"
	// ReasonTargetNotAllowed: an explicit target is neither the home AP
	// nor an alternate.
	ReasonTargetNotAllowed = "target_not_allowed"
	// ReasonTargetUnusable: the target is in the AP set but cannot take
	// work now (absent from the collector, or untrusted).
	ReasonTargetUnusable = "target_unavailable"
)

// Error is a failure to place work, with the HTTP status it maps to.
type Error struct {
	Status int
	Reason string
	Msg    string
	Err    error
}

func (e *Error) Error() string { return e.Msg }

func (e *Error) Unwrap() error { return e.Err }

// StatusOf maps an error to an HTTP status; 500 for one not from here.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return http.StatusInternalServerError
}

// ReasonOf returns an error's machine-readable reason, or "".
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func errorf(status int, reason string, wrapped error, format string, args ...any) *Error {
	return &Error{Status: status, Reason: reason, Err: wrapped, Msg: fmt.Sprintf(format, args...)}
}

// --- the caller's claims ---------------------------------------------------

// Caller is what the authentication layer knows about a caller beyond
// their HTCondor identity: the principal it authenticated, and the
// groups recorded at login. Carried on the request context, because the
// surfaces that submit (REST, MCP) authenticate in different places.
type Caller struct {
	Subject string
	Groups  []string
}

type callerKey struct{}

// WithCaller records the caller's claims on ctx.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the claims WithCaller recorded.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}
