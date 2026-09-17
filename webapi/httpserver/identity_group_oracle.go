package httpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbockelm/golang-htcondor/idmap"
	"github.com/bbockelm/golang-htcondor/logging"
)

// systemGroupOracle re-reads a user's group membership at refresh time
// and narrows or revokes the grant to match what the system says now.
//
// This closes the gap reauthorizeRefreshGrant documents: the groups
// stored with a grant are the membership as of consent, so re-running
// the policy against them catches POLICY drift -- an operator changing
// MCP_WRITE_GROUP -- but not MEMBERSHIP drift. A user removed from a
// group upstream still carried it in the session and still passed.
//
// The reason that gap existed was that reading live membership meant
// holding a live credential to the identity provider, which this server
// does not have. Reading it from the ACCOUNT DATABASE needs no such
// thing: the groups are right there, and the grant's subject is already
// the local account name because identity mapping put it there. So the
// source that makes system groups possible at login is the same one that
// makes re-checking them possible at refresh.
//
// It is only registered when groups come from the system. With
// token-sourced groups there is nothing local to re-read, and inventing
// an answer would be worse than the honest silence of no oracle at all.
type systemGroupOracle struct {
	identity *localIdentity
	// validate re-runs the deployment's group policy, and scopesFor
	// recomputes the scopes a membership earns. Both are the Handler's,
	// so the oracle cannot drift from the policy applied at login.
	validate  func(groups []string) error
	scopesFor func(groups, requested []string) []string
	logger    *logging.Logger
}

// Name identifies the oracle in log lines.
func (o *systemGroupOracle) Name() string { return "system-groups" }

// Check re-reads membership for username and reports what it now earns.
//
// Fails OPEN, as the interface requires: an account database that cannot
// be read returns "no opinion" rather than revoking. A refresh endpoint
// that hard-denies whenever NSS hiccups is an outage amplifier, and the
// absolute grant lifetime cap is what bounds exposure meanwhile.
func (o *systemGroupOracle) Check(ctx context.Context, username string, scopes []string) (ReauthDecision, error) {
	groups, err := o.identity.groups.GroupsFor(ctx, username)

	// A degraded read is the dangerous case for THIS caller. The list is
	// usable enough to log somebody in -- it is what `id` would say --
	// but it is indistinguishable from a list that shrank because the
	// user really was removed from a group, and acting on that here
	// means revoking their grant. An outage must not do that to
	// everybody whose token happens to refresh during it.
	var degraded *idmap.DegradedError
	if errors.As(err, &degraded) {
		return ReauthDecision{}, fmt.Errorf(
			"not re-checking %q: %s was unavailable, so a shorter group list may be an outage rather than lost membership: %w",
			username, degraded.Source, degraded.Err)
	}
	if err != nil {
		// Deliberately an error, not a revocation: the caller logs it and
		// treats it as no opinion.
		return ReauthDecision{}, fmt.Errorf("re-reading groups for %q: %w", username, err)
	}

	// Lost access to the service altogether.
	if err := o.validate(groups); err != nil {
		return ReauthDecision{
			Status: UserStatusRevoked,
			Reason: fmt.Sprintf("group membership no longer grants access: %v", err),
		}, nil
	}

	// Still entitled to something, but perhaps less than before. Report
	// the difference rather than failing the refresh, so a user who lost
	// write access keeps working read-only.
	allowed := o.scopesFor(groups, scopes)
	var denied []string
	for _, s := range scopes {
		if !containsString(allowed, s) {
			denied = append(denied, s)
		}
	}
	if len(denied) > 0 {
		o.logger.Info(logging.DestinationHTTP,
			"Live group membership no longer covers every granted scope",
			"username", username, "groups", groups, "denied", denied)
	}
	return ReauthDecision{Status: UserStatusActive, DeniedScopes: denied}, nil
}
