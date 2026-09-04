package httpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// oracleTimeout bounds how long a single refresh may wait on the schedd.
// A refresh is on a client's critical path, and every oracle fails open, so a
// slow schedd should cost a bounded delay and then be ignored rather than
// stalling the token endpoint.
const oracleTimeout = 5 * time.Second

// UserRecordOracle reports a user revoked when the schedd's per-user record
// says so — that is, when an admin has run
// `condor_qusers -disable <user> -reason "..."`.
//
// This is the stronger of the two schedd-backed oracles, because it reads an
// explicit administrative act rather than inferring one from an ACL. The
// record's DisableReason is carried through to the OAuth2 error, so the
// operator's note reaches whoever is looking at the failure.
//
// Absence of a record is deliberately NOT a denial. The schedd creates a
// record the first time a user submits, so "no record" routinely means "this
// user has never submitted here" — denying on it would lock out every new
// user and everyone on a freshly built pool.
type UserRecordOracle struct {
	// Schedd supplies the current schedd client. It is a function rather
	// than a value because the handler re-creates its Schedd when the
	// daemon's address changes.
	Schedd func() *htcondor.Schedd
	// UIDDomain qualifies bare usernames before the lookup; schedd records
	// are keyed on the fully-qualified "user@domain" form.
	UIDDomain string
	Logger    *logging.Logger
}

// Name implements RevocationOracle.
func (o *UserRecordOracle) Name() string { return "schedd-userrec" }

// Check implements RevocationOracle.
func (o *UserRecordOracle) Check(ctx context.Context, username string, _ []string) (ReauthDecision, error) {
	schedd := o.schedd()
	if schedd == nil {
		return ReauthDecision{}, fmt.Errorf("no schedd configured")
	}
	user := qualifyUser(username, o.UIDDomain)
	if user == "" {
		return ReauthDecision{}, fmt.Errorf("cannot qualify username %q without a UID domain", username)
	}

	ctx, cancel := context.WithTimeout(ctx, oracleTimeout)
	defer cancel()

	record, err := schedd.GetUserRecord(ctx, user)
	if err != nil {
		return ReauthDecision{}, fmt.Errorf("querying user record for %s: %w", user, err)
	}
	if record == nil {
		// No record: the schedd has never seen this user submit. No
		// information, so no opinion.
		return ReauthDecision{Status: UserStatusUnknown}, nil
	}
	if record.IsDisabled() {
		reason := record.DisableReason
		if reason == "" {
			reason = "the account is disabled on the access point"
		}
		return ReauthDecision{Status: UserStatusRevoked, Reason: reason}, nil
	}
	return ReauthDecision{Status: UserStatusActive}, nil
}

func (o *UserRecordOracle) schedd() *htcondor.Schedd {
	if o.Schedd == nil {
		return nil
	}
	return o.Schedd()
}

// ScheddACLOracle strips scopes whose HTCondor authorization level the schedd
// would refuse for this user, by running a DC_SEC_QUERY probe — the same
// question condor_ping asks.
//
// It is the weaker of the two oracles and is deliberately scoped to narrowing
// rather than revoking. Two reasons:
//
//   - It cannot see identity at all. The MCP server mints the IDTOKEN it
//     probes with, so the schedd is being asked "do your ACLs admit this
//     name", not "does this person still exist". A deleted user whose name
//     still matches ALLOW_WRITE passes.
//   - ALLOW_WRITE is `*@uid_domain` in many pools, in which case the probe
//     tells you nothing about any individual.
//
// What it does catch is a pool that genuinely enumerates users in its ACLs,
// where removing someone from ALLOW_WRITE should stop their write access
// without waiting for the grant's lifetime cap.
type ScheddACLOracle struct {
	Schedd    func() *htcondor.Schedd
	UIDDomain string
	Logger    *logging.Logger
	// MintToken produces an HTCondor IDTOKEN asserting username, used as
	// the probe credential. The scopes argument is passed through to the
	// handler's minter; Check passes nil so the probe token carries no
	// limit_authz narrowing (see Check for why).
	MintToken func(username string, scopes []string) (string, error)
}

// Name implements RevocationOracle.
func (o *ScheddACLOracle) Name() string { return "schedd-acl" }

// Check implements RevocationOracle.
//
// It probes only the levels the user actually holds: a grant with no write
// scope never asks about WRITE. The verdict is always Active — this oracle
// answers a question about permissions, not about the person — with denied
// scopes listed for whatever the schedd refuses.
func (o *ScheddACLOracle) Check(ctx context.Context, username string, scopes []string) (ReauthDecision, error) {
	schedd := o.schedd()
	if schedd == nil {
		return ReauthDecision{}, fmt.Errorf("no schedd configured")
	}

	probes := scopeAuthzProbes(scopes)
	if len(probes) == 0 {
		return ReauthDecision{Status: UserStatusUnknown}, nil
	}
	if o.MintToken == nil {
		return ReauthDecision{}, fmt.Errorf("no token minter configured")
	}

	// Probe as the user, not as this server. The schedd evaluates its ACLs
	// against whatever identity the connection authenticates as, so a probe
	// carrying the server's own credentials would answer a question about
	// the server. Mint the same kind of IDTOKEN the MCP data path uses.
	//
	// The authz levels are deliberately left off the minted token: a token
	// narrowed with limit_authz would fail the probe because we asked for a
	// narrower token, not because the ACL refuses the user, which is the
	// opposite of what is being measured.
	probeToken, err := o.MintToken(username, nil)
	if err != nil {
		return ReauthDecision{}, fmt.Errorf("minting probe token for %s: %w", username, err)
	}
	secConfig, err := htcondor.NewClientSecurityConfig(ctx, probeToken, "", 0, "CLIENT", nil)
	if err != nil {
		return ReauthDecision{}, fmt.Errorf("building probe security config: %w", err)
	}
	// Keep probe sessions out of the MCP data path's session cache: these
	// are negotiated with an AuthCommand set and should not be resumed for
	// ordinary schedd traffic.
	secConfig.SecurityTag = "authz-probe:" + username

	ctx, cancel := context.WithTimeout(ctx, oracleTimeout)
	defer cancel()
	ctx = htcondor.WithSecurityConfig(ctx, secConfig)

	var denied []string
	for _, probe := range probes {
		result, err := schedd.PingWithOptions(ctx, &htcondor.PingOptions{
			CheckPermission: probe.permission,
		})
		if err != nil {
			// One failed probe fails the whole check, which the caller
			// turns into "no opinion". Reporting a partial answer would
			// let a transient error strip a scope.
			return ReauthDecision{}, fmt.Errorf("probing %s for %s: %w", probe.name, username, err)
		}
		if !result.Authorized {
			denied = append(denied, probe.scopes...)
		}
	}
	if len(denied) == 0 {
		return ReauthDecision{Status: UserStatusActive}, nil
	}
	return ReauthDecision{
		Status:       UserStatusActive,
		Reason:       fmt.Sprintf("the access point no longer authorizes %s", strings.Join(denied, ", ")),
		DeniedScopes: denied,
	}, nil
}

func (o *ScheddACLOracle) schedd() *htcondor.Schedd {
	if o.Schedd == nil {
		return nil
	}
	return o.Schedd()
}

// authzProbe maps one HTCondor authorization level to the scopes that depend
// on it.
type authzProbe struct {
	name       string
	permission int
	scopes     []string
}

// scopeAuthzProbes returns the probes worth running for a granted scope set.
//
// Only WRITE and READ are probed. The condor:/* scopes for ADMINISTRATOR,
// CONFIG, DAEMON and NEGOTIATOR are deliberately absent: mapCondorScopesToAuthz
// already drops those from every minted token, so a grant that nominally
// carries them confers nothing and probing for them would only produce noise.
func scopeAuthzProbes(scopes []string) []authzProbe {
	held := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		held[s] = true
	}

	var probes []authzProbe

	var writeScopes []string
	for _, s := range []string{"mcp:write", "condor:/WRITE"} {
		if held[s] {
			writeScopes = append(writeScopes, s)
		}
	}
	if len(writeScopes) > 0 {
		probes = append(probes, authzProbe{
			name:       "WRITE",
			permission: htcondor.DCNopWrite,
			scopes:     writeScopes,
		})
	}

	var readScopes []string
	for _, s := range []string{"mcp:read", "condor:/READ"} {
		if held[s] {
			readScopes = append(readScopes, s)
		}
	}
	if len(readScopes) > 0 {
		probes = append(probes, authzProbe{
			name:       "READ",
			permission: htcondor.DCNopRead,
			scopes:     readScopes,
		})
	}

	return probes
}

// qualifyUser appends the UID domain to a bare username, matching how
// generateHTCondorTokenWithScopes builds the subject it asserts to the schedd.
// A bare name with no domain available returns empty, so callers report "no
// opinion" rather than looking up a name the schedd cannot key on.
func qualifyUser(username, uidDomain string) string {
	if username == "" {
		return ""
	}
	if strings.Contains(username, "@") {
		return username
	}
	if uidDomain == "" {
		return ""
	}
	return username + "@" + uidDomain
}

// defaultRevocationOracles is the oracle set used when the caller expresses
// no preference. Only the user-record oracle is on by default: it costs one
// indexed lookup, it fires only on an explicit `condor_qusers -disable`, and
// it cannot misfire on a pool that has never used user records (absence is
// "no opinion"). The ACL probe is opt-in because it costs extra round trips
// on every refresh and reports nothing useful in a pool with wildcard ACLs.
var defaultRevocationOracles = []string{"schedd-userrec"}

// buildRevocationOracles turns configured oracle names into instances.
// Unrecognized names are logged and skipped rather than failing startup: an
// oracle is a defense-in-depth measure, and a typo should not stop the server
// from serving.
func (h *Handler) buildRevocationOracles(names []string) []RevocationOracle {
	if names == nil {
		names = defaultRevocationOracles
	}
	var oracles []RevocationOracle
	for _, name := range names {
		switch strings.TrimSpace(strings.ToLower(name)) {
		case "":
			continue
		case "schedd-userrec":
			oracles = append(oracles, &UserRecordOracle{
				Schedd:    h.getSchedd,
				UIDDomain: h.uidDomain,
				Logger:    h.logger,
			})
		case "schedd-acl":
			oracles = append(oracles, &ScheddACLOracle{
				Schedd:    h.getSchedd,
				UIDDomain: h.uidDomain,
				Logger:    h.logger,
				MintToken: h.generateHTCondorTokenWithScopes,
			})
		default:
			h.logger.Warn(logging.DestinationHTTP,
				"Ignoring unknown OAuth2 revocation oracle", "oracle", name)
		}
	}
	if len(oracles) > 0 {
		enabled := make([]string, 0, len(oracles))
		for _, o := range oracles {
			enabled = append(enabled, o.Name())
		}
		h.logger.Info(logging.DestinationHTTP,
			"OAuth2 refresh revocation oracles enabled", "oracles", enabled)
	} else {
		h.logger.Info(logging.DestinationHTTP,
			"No OAuth2 refresh revocation oracles enabled; the grant lifetime cap is the only backstop")
	}
	return oracles
}
