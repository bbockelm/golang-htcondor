package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/idmap"
	"github.com/bbockelm/golang-htcondor/logging"
)

// condor_placementd as an identity mapping (HTTP_API_IDENTITY_MAP =
// placementd, alone or in the ordered list).
//
// A sign-in identity the placementd has mapped -- authorized, unexpired,
// with an account -- signs in AS that account: the session's username is the
// account verbatim (its domain need not be UID_DOMAIN), and every token
// minted for it is bounded by what the account was granted:
//
//   - the subject is the account, never anything else;
//   - the scope is condor:/READ and/or condor:/WRITE, whichever of those the
//     account holds -- the placementd's other grants (INSTRUCTOR, WEBADMIN)
//     are not HTCondor authorization levels and are dropped;
//   - the "project" claim names the session's selected project, as the
//     placementd's own tokens do.
//
// The account comes only from the placementd's answer for the session's
// verified identity, and is re-read at most every placementRevalidateEvery on
// the next mint; a removed, expired or re-pointed identity ends the session.

// placementRevalidateEvery bounds how stale a placementd session's view of
// its account may be when a token is minted for it.
const placementRevalidateEvery = 5 * time.Minute

// placementJobLevels are the HTCondor authorization levels this server will
// mint from a placementd grant: the two it mints for every other session.
var placementJobLevels = []string{"READ", "WRITE"}

// PlacementAccountInfo is the placementd account behind a session or an
// OAuth2 grant.
type PlacementAccountInfo struct {
	// Account is the AP user, user@domain, exactly as the placementd gave it.
	Account string `json:"account"`
	// Authorizations are the account's grants as the placementd lists
	// them, including ones that are not HTCondor authorization levels.
	Authorizations []string `json:"authorizations,omitempty"`
	// Projects are the projects the account may name; the first is the
	// default.
	Projects []string `json:"projects,omitempty"`
	// Project is the selected project, put in every minted token.
	Project string `json:"project,omitempty"`
	// MappingExpiresAt is when the placementd stops honoring the
	// identity; zero for never.
	MappingExpiresAt time.Time `json:"mapping_expires_at,omitzero"`
	// CheckedAt is when the account was last read from the placementd.
	CheckedAt time.Time `json:"checked_at"`
}

// Levels are the HTCondor authorization levels among the account's grants.
func (p *PlacementAccountInfo) Levels() []string {
	if p == nil {
		return nil
	}
	return placementLevels(p.Authorizations)
}

// placementLevels is the subset of grants that are levels this server mints.
func placementLevels(grants []string) []string {
	var out []string
	for _, level := range placementJobLevels {
		for _, g := range grants {
			if strings.EqualFold(strings.TrimSpace(g), level) {
				out = append(out, level)
				break
			}
		}
	}
	return out
}

func encodePlacementAccount(info *PlacementAccountInfo) (string, error) {
	if info == nil {
		return "", nil
	}
	raw, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("encoding the placementd account: %w", err)
	}
	return string(raw), nil
}

func decodePlacementAccount(raw string) (*PlacementAccountInfo, error) {
	if raw == "" {
		return nil, nil
	}
	var info PlacementAccountInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// splitPlacementdStrategy separates "placementd" from the strategies the
// local resolver implements. placementdFirst is true when placementd is
// listed before every local strategy, so it is tried first; otherwise it is
// tried after them.
func splitPlacementdStrategy(all []idmap.Strategy) (local []idmap.Strategy, placementdFirst, placementd bool) {
	for _, s := range all {
		if s == idmap.StrategyPlacementd {
			if !placementd {
				placementdFirst = len(local) == 0
			}
			placementd = true
			continue
		}
		local = append(local, s)
	}
	return local, placementdFirst, placementd
}

// lookupPlacementAccount asks the placementd which account identity maps to.
// It returns nil, with no error, when the identity is not mapped, is
// expired, names no account, or holds no level this server mints: none of
// those may sign in as an account.
func (h *Handler) lookupPlacementAccount(ctx context.Context, identity string) (*PlacementAccountInfo, error) {
	if identity == "" || h.placementd == nil {
		return nil, nil
	}
	ctx = htcondor.WithDaemonCredential(ctx, "placementd identity mapping: the sign-in identity's own account")
	users, err := h.placementd.QueryUsers(ctx, identity)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.UserName != identity {
			continue
		}
		if !u.Authorized || u.APUserID == "" || !strings.Contains(u.APUserID, "@") {
			return nil, nil
		}
		if !u.MappingExpiration.IsZero() && !u.MappingExpiration.After(time.Now()) {
			return nil, nil
		}
		info := &PlacementAccountInfo{
			Account:          u.APUserID,
			Authorizations:   slices.Clone(u.Authorizations),
			Projects:         slices.Clone(u.Projects),
			MappingExpiresAt: u.MappingExpiration,
			CheckedAt:        time.Now(),
		}
		if len(info.Projects) > 0 {
			info.Project = info.Projects[0]
		}
		if len(info.Levels()) == 0 {
			return nil, nil
		}
		return info, nil
	}
	return nil, nil
}

// placementdMapLogin tries the placementd mapping for a login.
func (h *Handler) placementdMapLogin(ctx context.Context, identity string) *PlacementAccountInfo {
	if !h.placementOnboard.mapIdentity || identity == "" || !h.placementOnboardingEnabled(ctx) {
		return nil
	}
	info, err := h.lookupPlacementAccount(ctx, identity)
	if err != nil {
		h.logger.Warn(logging.DestinationHTTP, "Could not ask the placementd for the sign-in identity's account",
			"identity", identity, "error", err)
		return nil
	}
	return info
}

// startPlacementdSession finishes a browser login mapped through the
// placementd: a full session as the placementd account.
func (h *Handler) startPlacementdSession(w http.ResponseWriter, li loginIdentity, m loginMapping, oidcSubject string) {
	sessionID, sessionData, err := h.sessionStore.CreateSession(browserSessionData(li, m))
	if err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to create a placementd session",
			"error", err, "oidc_subject", oidcSubject)
		h.writeError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}
	h.setSessionCookie(w, sessionID, sessionData.ExpiresAt)
	h.logger.Info(logging.DestinationSecurity, "Signed in through the placementd mapping",
		"oidc_subject", oidcSubject, "identity", li.placementID, "account", m.placement.Account,
		"levels", m.placement.Levels(), "project", m.placement.Project, "session_key", sessionLogID(sessionID))

	redirectURL := li.originalURL
	if redirectURL == "" || !isSafeLocalRedirect(redirectURL) {
		redirectURL = "/"
	}
	h.finishBrowserLogin(w, redirectURL)
}

// errPlacementSessionEnded is a placementd session whose identity no longer
// maps to the account it signed in as.
var errPlacementSessionEnded = errors.New("this sign-in no longer maps to the account it signed in as; sign in again")

// revalidatePlacementSession re-reads a placementd session's account when
// the last read is older than placementRevalidateEvery. A removed, expired
// or re-pointed identity ends the session; changed grants or projects are
// taken up. It returns the session to mint for.
func (h *Handler) revalidatePlacementSession(ctx context.Context, sessionID string, sd *SessionData) (*SessionData, error) {
	if !sd.IsPlacementd() {
		return sd, nil
	}
	if time.Since(sd.Placement.CheckedAt) < placementRevalidateEvery {
		return sd, nil
	}
	info, err := h.lookupPlacementAccount(ctx, sd.PlacementIdentity)
	if err != nil {
		// The placementd is unreachable. The session keeps what it had
		// until the next mint asks again; the cap on its age is the
		// session's own expiry, which never exceeds the mapping'h.
		h.logger.Warn(logging.DestinationHTTP, "Could not re-read a placementd session's account",
			"identity", sd.PlacementIdentity, "error", err)
		return sd, nil
	}
	if info == nil || info.Account != sd.Placement.Account {
		h.sessionStore.Delete(sessionID)
		h.logger.Info(logging.DestinationSecurity, "Ended a placementd session whose identity changed",
			"identity", sd.PlacementIdentity, "account", sd.Placement.Account,
			"now", map[bool]string{true: "unmapped", false: "re-pointed"}[info == nil])
		return nil, errPlacementSessionEnded
	}
	// Keep the selected project while the account still has it.
	for _, p := range info.Projects {
		if strings.EqualFold(p, sd.Placement.Project) {
			info.Project = p
		}
	}
	expires := sd.ExpiresAt
	if !info.MappingExpiresAt.IsZero() && info.MappingExpiresAt.Before(expires) {
		expires = info.MappingExpiresAt
	}
	if err := h.sessionStore.UpdatePlacement(sessionID, info, expires); err != nil {
		return nil, fmt.Errorf("storing the re-read placementd account: %w", err)
	}
	updated := *sd
	updated.Placement = info
	updated.ExpiresAt = expires
	return &updated, nil
}

// mintPlacementSessionToken mints a request token for a placementd session:
// the account as subject, its levels as scope, its project as a claim.
func (h *Handler) mintPlacementSessionToken(ctx context.Context, sessionID string, sd *SessionData) (token, subject string, err error) {
	sd, err = h.revalidatePlacementSession(ctx, sessionID, sd)
	if err != nil {
		return "", "", err
	}
	if h.trustDomain == "" {
		return "", "", fmt.Errorf("TRUST_DOMAIN not configured for server; cannot generate token")
	}
	levels := sd.Placement.Levels()
	if len(levels) == 0 {
		return "", "", fmt.Errorf("account %s holds no permission on this access point's jobs: %w",
			sd.Placement.Account, errNoAuthorizationLimits)
	}
	now := time.Now()
	token, err = generateMCPAccessJWTWithClaims(filepath.Dir(h.signingKeyPath), filepath.Base(h.signingKeyPath),
		sd.Placement.Account, h.trustDomain, now.Unix(), now.Add(requestTokenLifetime).Unix(), levels,
		placementProjectClaim(sd.Placement.Project))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate token for placementd account %s: %w", sd.Placement.Account, err)
	}
	return token, sd.Placement.Account, nil
}

// placementProjectClaim is the extra claim carrying a project, or none.
func placementProjectClaim(project string) map[string]any {
	if project == "" {
		return nil
	}
	return map[string]any{"project": project}
}

// --- OAuth2 grants authorized by a placementd session ----------------------

// placementMintBound limits a token minted for an OAuth2 subject that a
// placementd session authorized.
type placementMintBound struct {
	Levels  []string
	Project string
}

// errPlacementGrantIdentity refuses a grant of a placementd account that
// does not name the identity whose sign-in authorized it, or names one that
// never signed in as the account. Several identities can map to one account
// with different grants and projects, so without its own identity there is
// no bound the grant can be held to.
var errPlacementGrantIdentity = errors.New("this grant does not name the sign-in identity that authorized it; authorize it again")

// recordPlacementSubject remembers that the OAuth2 subject sd.Username is a
// placementd account reached through sd.PlacementIdentity, so every token
// minted for the grants that identity authorizes is bounded by what it
// holds. Each identity of an account keeps its own bound.
func (h *Handler) recordPlacementSubject(ctx context.Context, sd *SessionData) error {
	if !sd.IsPlacementd() || h.db == nil {
		return nil
	}
	authz, _ := json.Marshal(sd.Placement.Authorizations)
	var exp int64
	if !sd.Placement.MappingExpiresAt.IsZero() {
		exp = sd.Placement.MappingExpiresAt.Unix()
	}
	_, err := h.db.ExecContext(ctx, `INSERT INTO placement_oauth_subjects
		(subject, identity, authorizations, project, mapping_expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(subject, identity) DO UPDATE SET authorizations = excluded.authorizations,
		project = excluded.project, mapping_expires_at = excluded.mapping_expires_at, updated_at = excluded.updated_at`,
		sd.Placement.Account, sd.PlacementIdentity, string(authz), sd.Placement.Project, exp, time.Now().Unix())
	return err
}

// placementSubjectRecorded reports whether any placementd session has
// authorized grants for subject.
func (h *Handler) placementSubjectRecorded(ctx context.Context, subject string) (bool, error) {
	if h.db == nil || subject == "" {
		return false, nil
	}
	var one int
	err := h.db.QueryRowContext(ctx, `SELECT 1 FROM placement_oauth_subjects WHERE subject = ? LIMIT 1`,
		subject).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading the placementd bound for %s: %w", subject, err)
	}
	return true, nil
}

// placementSubjectBound returns the bound for a grant of subject that
// identity authorized, or nil when no placementd session authorized grants
// for subject. A subject that has bounds but none for identity -- identity
// empty included -- is errPlacementGrantIdentity. Any error is fatal to the
// mint: without the bound there is nothing to stay within.
func (h *Handler) placementSubjectBound(ctx context.Context, subject, identity string) (*placementMintBound, error) {
	recorded, err := h.placementSubjectRecorded(ctx, subject)
	if err != nil || !recorded {
		return nil, err
	}
	if identity == "" {
		return nil, errPlacementGrantIdentity
	}
	var authz, project string
	var exp int64
	err = h.db.QueryRowContext(ctx, `SELECT authorizations, project, mapping_expires_at
		FROM placement_oauth_subjects WHERE subject = ? AND identity = ?`, subject, identity).Scan(&authz, &project, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errPlacementGrantIdentity
	}
	if err != nil {
		return nil, fmt.Errorf("reading the placementd bound for %s: %w", subject, err)
	}
	var grants []string
	if authz != "" {
		if err := json.Unmarshal([]byte(authz), &grants); err != nil {
			return nil, fmt.Errorf("reading the placementd bound for %s: %w", subject, err)
		}
	}
	if exp != 0 && time.Unix(exp, 0).Before(time.Now()) {
		grants = nil
	}
	return &placementMintBound{Levels: placementLevels(grants), Project: project}, nil
}

// updatePlacementSubject stores a re-read account for the bound of subject
// through identity, or forgets its grants when info is nil (identity no
// longer maps to subject). Other identities' bounds are untouched.
func (h *Handler) updatePlacementSubject(ctx context.Context, subject, identity string, info *PlacementAccountInfo) {
	if h.db == nil {
		return
	}
	if info == nil {
		_, _ = h.db.ExecContext(ctx, `UPDATE placement_oauth_subjects SET authorizations = '', updated_at = ?
			WHERE subject = ? AND identity = ?`, time.Now().Unix(), subject, identity)
		return
	}
	authz, _ := json.Marshal(info.Authorizations)
	var exp int64
	if !info.MappingExpiresAt.IsZero() {
		exp = info.MappingExpiresAt.Unix()
	}
	_, _ = h.db.ExecContext(ctx, `UPDATE placement_oauth_subjects SET authorizations = ?,
		mapping_expires_at = ?, updated_at = ? WHERE subject = ? AND identity = ?`,
		string(authz), exp, time.Now().Unix(), subject, identity)
}

// grantIdentityKey carries, on a context, the sign-in identity of the grant
// being approved or re-checked.
type grantIdentityKey struct{}

// withGrantIdentityContext records identity on ctx for the token minted to
// probe the access point on that grant's behalf; "" leaves ctx as it is.
func withGrantIdentityContext(ctx context.Context, identity string) context.Context {
	if identity == "" {
		return ctx
	}
	return context.WithValue(ctx, grantIdentityKey{}, identity)
}

// grantIdentityFromContext is the identity withGrantIdentityContext
// recorded, or "".
func grantIdentityFromContext(ctx context.Context) string {
	identity, _ := ctx.Value(grantIdentityKey{}).(string)
	return identity
}

// mintGrantProbeToken mints the schedd-acl oracle's probe token for the
// grant whose identity ctx carries.
func (h *Handler) mintGrantProbeToken(ctx context.Context, username string, scopes []string) (string, error) {
	return h.generateGrantHTCondorToken(username, grantIdentityFromContext(ctx), scopes)
}

// boundPlacementAuthz applies a placementd bound to the levels a grant's
// scopes map to: never more than the account holds.
func boundPlacementAuthz(authz []string, bound *placementMintBound) []string {
	if bound == nil {
		return authz
	}
	var out []string
	for _, a := range authz {
		if slices.Contains(bound.Levels, strings.ToUpper(a)) {
			out = append(out, strings.ToUpper(a))
		}
	}
	return out
}

// --- features that need a local account ------------------------------------

// refuseForPlacementdSession answers 403 for a feature a placementd account
// cannot use, because it needs a local Unix account this server would look
// up or act as. It reports whether it refused.
func (h *Handler) refuseForPlacementdSession(w http.ResponseWriter, r *http.Request, what string) bool {
	sd, ok := h.getSessionFromRequest(r)
	if !ok || !sd.IsPlacementd() {
		return false
	}
	h.writeError(w, http.StatusForbidden, what+" is not available to accounts assigned by the placement service.")
	return true
}

// approvingPlacementIdentity is the identity of the placementd-mapped
// session approving a grant for username, or "" when the approver is not
// one (a local account, or a name the user header asserted).
func (h *Handler) approvingPlacementIdentity(r *http.Request, username string) string {
	sd, ok := h.placementdSession(r)
	if !ok || sd.Username != username {
		return ""
	}
	return sd.PlacementIdentity
}

// placementdSessionFromContext reports the placementd session behind a
// request, if any.
func (h *Handler) placementdSession(r *http.Request) (*SessionData, bool) {
	sd, ok := h.getSessionFromRequest(r)
	if !ok || !sd.IsPlacementd() {
		return nil, false
	}
	return sd, true
}
