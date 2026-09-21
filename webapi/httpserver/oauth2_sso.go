package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/ory/fosite"
	"golang.org/x/oauth2"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/logging"
)

// UserInfo represents user information from the IDP
type UserInfo struct {
	Subject string                 `json:"sub"`
	Email   string                 `json:"email"`
	Name    string                 `json:"name"`
	Groups  interface{}            `json:"groups"` // Can be []string or string
	Claims  map[string]interface{} // Additional claims
}

// extractGroups extracts group names from the groups claim
// Groups can be:
// - []string: List of group names
// - string: Space-delimited list of group names
// - nil: No groups
func extractGroups(groupsClaim interface{}) []string {
	if groupsClaim == nil {
		return nil
	}

	switch v := groupsClaim.(type) {
	case []interface{}:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				groups = append(groups, str)
			}
		}
		return groups
	case []string:
		return v
	case string:
		// Space-delimited
		if v == "" {
			return nil
		}
		return strings.Fields(v)
	default:
		return nil
	}
}

// validateAccess reports whether a user's groups satisfy a required set.
func (s *Handler) validateAccess(required *groupSet, userGroups []string) error {
	if required.allows(userGroups) {
		return nil
	}
	return fmt.Errorf("user is not in any of the required access groups: %s", required)
}

// validateWebUIAccess gates logging in to the web interface.
//
// Separate from validateGroupAccess because the two answer different
// questions: who may drive this AP through an agent, and who may open its
// web interface. They were one knob, so granting somebody the browser
// necessarily granted them MCP.
func (s *Handler) validateWebUIAccess(userGroups []string) error {
	return s.validateAccess(s.webUIRequiredGroups(), userGroups)
}

// webUIRequiredGroups is the set gating web interface login.
//
// With none of its own it falls back to the MCP groups, so a deployment
// that was using HTTP_API_MCP_ACCESS_GROUP to gate the browser -- which
// is what that knob did before these were separated -- is not silently
// opened by the separation. Resolved per call rather than aliased at
// startup so that a reconfigure of either knob takes effect immediately.
func (s *Handler) webUIRequiredGroups() *groupSet {
	if s.webuiAccessGroups.configured() {
		return s.webuiAccessGroups
	}
	return s.mcpAccessGroups
}

func (s *Handler) validateGroupAccess(userGroups []string) error {
	// If access group is configured, user must be in it
	return s.validateAccess(s.mcpAccessGroups, userGroups)
}

// getScopesForGroups determines OAuth2 scopes based on group membership.
// For mcp:read and mcp:write scopes:
//   - If a specific read/write group is configured, the user must be in that group.
//   - Otherwise, if the general access group is configured and the user is in it
//     (already verified by validateGroupAccess), grant the scope.
//   - If no groups are configured at all, grant the scope to any authenticated user.
func (s *Handler) getScopesForGroups(userGroups []string, requestedScopes []string) []string {
	grantedScopes := []string{"openid"} // Always grant openid

	// Check each requested scope
	for _, scope := range requestedScopes {
		switch scope {
		case "openid":
			// Already added
			continue
		case "mcp:read":
			switch {
			case s.mcpReadGroups.configured():
				// Specific read group configured — user must be in it
				if s.mcpReadGroups.allows(userGroups) {
					grantedScopes = append(grantedScopes, scope)
				}
			case s.mcpAccessGroups.configured():
				// No specific read group; fall back to access group (already validated)
				if s.mcpAccessGroups.allows(userGroups) {
					grantedScopes = append(grantedScopes, scope)
				}
			default:
				// No groups configured — grant to any authenticated user
				grantedScopes = append(grantedScopes, scope)
			}
		case "mcp:write":
			switch {
			case s.mcpWriteGroups.configured():
				// Specific write group configured — user must be in it
				if s.mcpWriteGroups.allows(userGroups) {
					grantedScopes = append(grantedScopes, scope)
				}
			case s.mcpAccessGroups.configured():
				// No specific write group; fall back to access group (already validated)
				if s.mcpAccessGroups.allows(userGroups) {
					grantedScopes = append(grantedScopes, scope)
				}
			default:
				// No groups configured — grant to any authenticated user
				grantedScopes = append(grantedScopes, scope)
			}
		case "mcp:admin":
			// Read every user's jobs.
			//
			// Note the default, which is the opposite of mcp:read and
			// mcp:write above: those fall back to granting when no group
			// is configured, because a server with no group policy is a
			// single-tenant one where every authenticated caller is
			// already entitled to the surface. That reasoning does not
			// extend to a cross-user privilege -- "no admin group
			// configured" has to mean nobody, not everybody.
			if s.mcpAdminGroups.configured() && s.mcpAdminGroups.allows(userGroups) {
				grantedScopes = append(grantedScopes, scope)
			}
		case "mcp:superuser":
			// Change another user's jobs: remove, hold, release, edit.
			// Deliberately not implied by mcp:admin -- seeing every job
			// and being able to remove every job are different powers,
			// and the group that should hold the second is usually much
			// smaller than the group that holds the first.
			if s.mcpSuperuserGroups.configured() && s.mcpSuperuserGroups.allows(userGroups) {
				grantedScopes = append(grantedScopes, scope)
			}
		default:
			// Grant other scopes if requested (profile, email, condor:/*, etc.).
			//
			// Re: condor:/* scopes — these grant *narrowing* claims on
			// the resulting HTCondor IDTOKEN (limit_authz), not new
			// authority. The schedd ACL still has the final say:
			// holding `condor:/WRITE` only lets the user submit if
			// they're in ALLOW_WRITE on the schedd side. See
			// mapCondorScopesToAuthz for the full security model.
			//
			// Because of that narrowing semantics, granting condor:/*
			// here without an explicit per-user group check is safe in
			// today's deployment: a non-submitter who somehow obtains
			// `condor:/WRITE` still can't submit. The audit-style
			// concern ("user clicks Authorize on a malicious client
			// asking for condor:/ADMINISTRATOR → admin token") is
			// also addressed defensively in mapCondorScopesToAuthz,
			// which silently drops ADMINISTRATOR / CONFIG / DAEMON /
			// NEGOTIATOR from the authz set even if requested.
			grantedScopes = append(grantedScopes, scope)
		}
	}

	return grantedScopes
}

// fetchUserInfo fetches user information from the IDP user info endpoint
func (s *Handler) fetchUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if s.oauth2UserInfoURL == "" {
		return nil, fmt.Errorf("user info URL not configured")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", s.oauth2UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Use custom HTTP client if configured
	client := s.getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	userInfo := &UserInfo{
		Claims: claims,
	}

	s.logger.Info(logging.DestinationHTTP, "Fetched user info from IDP", "claims", claims)

	// Extract standard claims
	if sub, ok := claims[s.oauth2UsernameClaim].(string); ok {
		userInfo.Subject = sub
	}
	if email, ok := claims["email"].(string); ok {
		userInfo.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = name
	}

	// Extract groups from configured claim
	if groupsClaim, ok := claims[s.oauth2GroupsClaim]; ok {
		userInfo.Groups = groupsClaim
	}

	return userInfo, nil
}

// handleOAuth2Callback handles the OAuth2 callback from the IDP
func (s *Handler) handleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Provider == nil || s.oauth2Config == nil {
		s.writeError(w, http.StatusInternalServerError, "OAuth2 not configured")
		return
	}

	ctx := r.Context()

	// Extract state and code from query parameters
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errorParam := r.URL.Query().Get("error")

	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		s.logger.Error(logging.DestinationHTTP, "OAuth2 callback error from IDP",
			"error", errorParam, "error_description", errorDesc)
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %s", errorDesc))
		return
	}

	if state == "" || code == "" {
		s.writeError(w, http.StatusBadRequest, "Missing state or code parameter")
		return
	}

	// Retrieve the stored authorize request and original URL
	ar, originalURL, ok := s.oauth2StateStore.GetWithURL(state)
	if !ok {
		s.logger.Error(logging.DestinationHTTP, "Invalid or expired OAuth2 state", "state", state)
		s.writeError(w, http.StatusBadRequest, "Invalid or expired state parameter")
		return
	}

	// Check if this is a browser-initiated flow (no authorize request)
	isBrowserFlow := (ar == nil)

	if !isBrowserFlow {
		s.logger.Info(logging.DestinationHTTP, "Processing OAuth2 callback", "state", state, "client_id", ar.GetClient().GetID())
	} else {
		s.logger.Info(logging.DestinationHTTP, "Processing OAuth2 callback for browser flow", "state", state, "original_url", originalURL)
	}

	// Exchange authorization code for token
	// Use custom HTTP client if configured (e.g. for self-signed certs)
	client := s.getHTTPClient()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	token, err := s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to exchange code for token", "error", err)
		s.writeError(w, http.StatusUnauthorized, "Failed to exchange authorization code")
		return
	}

	// Fetch user info from IDP
	// Use the same client for user info fetch
	userInfo, err := s.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to fetch user info", "error", err)
		s.writeError(w, http.StatusUnauthorized, "Failed to fetch user information")
		return
	}

	// Apply the admin's login policy before anything is derived from the
	// claims the IDP supplied.
	if err := s.evaluateLoginRequirements(userInfo.Claims); err != nil {
		s.logger.Warn(logging.DestinationHTTP, "Login refused by OAuth2 requirements",
			"requirements", s.oauth2RequirementsText, "claims_returned", claimNames(userInfo.Claims))
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}

	if userInfo.Subject == "" {
		// Name the claim that was looked for and what the IDP actually
		// sent. Without this the message is the same whether the claim is
		// misconfigured, misspelled, or genuinely absent -- and the
		// operator cannot tell which from the log.
		s.logger.Error(logging.DestinationHTTP, "User info missing subject claim",
			"claim", s.oauth2UsernameClaim, "claims_returned", claimNames(userInfo.Claims))
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf(
			"Invalid user information: the identity provider returned no %q claim", s.oauth2UsernameClaim))
		return
	}

	// File the provider's refresh token, if it gave one, before the
	// identity below is translated to a local account: this is keyed by
	// the provider's own subject, because it is that provider this
	// credential will be presented back to.
	s.rememberUpstreamRefresh(ctx, userInfo.Subject, token.RefreshToken,
		scopesFromToken(token, s.oauth2Config.Scopes))

	// Extract groups
	userGroups := extractGroups(userInfo.Groups)

	// The provider has said who this is. Where the deployment keeps that
	// answer in the account database instead -- a subject that is not a
	// login name, group membership that is not in the token -- translate
	// here, once, before anything downstream reads either.
	//
	// Everything that follows takes its identity from `subject` rather
	// than userInfo.Subject: the group policy below, the granted scopes,
	// the browser session, the OAuth2 session, and through the state
	// store, the consent and device-approval flows.
	subject := userInfo.Subject
	if s.localIdentity != nil {
		// A previously confirmed mapping, if this browser has one. It is
		// re-confirmed against the live account database below, never
		// trusted; what it avoids is the enumeration needed to discover
		// the account from scratch, which a just-restarted daemon cannot
		// do until its directory is answering.
		hint := s.readIdentityCookie(r, subject)
		account, groups, hinted, err := s.localIdentity.resolveWithHint(ctx, subject, userGroups, hint)
		if err != nil {
			// Refused, not degraded. See localIdentity's comment on why
			// there is no fallback to the token's own claims.
			s.logger.Warn(logging.DestinationHTTP,
				"Refusing a login that maps to no single local account",
				"oidc_subject", subject, "error", err)
			// A browser is on the other end of the SSO callback, so this
			// renders like the group-policy refusal next to it rather
			// than handing the person a JSON object to read.
			s.renderIdentityDeniedPage(w, err)
			return
		}
		s.logger.Info(logging.DestinationHTTP, "Resolved the asserted identity locally",
			"oidc_subject", subject, "account", account, "from_hint", hinted,
			"groups", groups, "groups_from_system", s.localIdentity.sourcesGroups())

		// Remember the mapping only when it was made with full knowledge
		// of the account database. A hinted mapping is not re-issued: it
		// was confirmed by name, which cannot rule out a second account
		// claiming the same GECOS, so extending its life would launder a
		// weaker check into a longer-lived claim.
		if !hinted && s.localIdentity.indexIsComplete() {
			s.setIdentityCookie(w, subject, account)
		}
		subject, userGroups = account, groups
	}

	s.logger.Info(logging.DestinationHTTP, "User authenticated via SSO",
		"subject", subject, "groups", userGroups)

	// Which gate applies depends on what is being logged in to. The web
	// interface and MCP are separate grants: somebody may be entitled to
	// open this AP's pages without being entitled to drive it through an
	// agent, and the reverse.
	accessErr := s.validateGroupAccess(userGroups)
	required := s.mcpAccessGroups
	if isBrowserFlow {
		accessErr, required = s.validateWebUIAccess(userGroups), s.webUIRequiredGroups()
	}
	if accessErr != nil {
		s.logger.Warn(logging.DestinationHTTP, "User denied access",
			"subject", subject, "groups", userGroups,
			"required_groups", required.String(),
			"surface", map[bool]string{true: "web-ui", false: "mcp"}[isBrowserFlow],
			"error", accessErr)

		// A browser gets a page. This used to return the API's JSON error
		// body, which is unreadable in a tab and gives somebody who has
		// just logged in successfully nothing to act on.
		if isBrowserFlow {
			s.renderAccessDeniedPage(w, required)
			return
		}
		err := accessErr

		// Create RFC6749 error to redirect back to client
		accessDeniedErr := fosite.ErrAccessDenied.WithDescription(err.Error()).WithHintf("User does not have required group membership")
		s.oauth2Provider.GetProvider().WriteAuthorizeError(ctx, w, ar, accessDeniedErr)
		return
	}

	// For browser flow, create session and redirect back to original URL
	if isBrowserFlow {
		// Create HTTP session cookie for browser-based authentication
		sessionID, sessionData, err := s.sessionStore.Create(subject, userGroups)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to create HTTP session",
				"error", err, "subject", subject)
			s.writeError(w, http.StatusInternalServerError, "Failed to create session")
			return
		}
		s.setSessionCookie(w, sessionID, sessionData.ExpiresAt)
		s.logger.Info(logging.DestinationHTTP, "Created HTTP session cookie for browser flow",
			"subject", subject, "session_id", sessionID[:8]+"...",
			"expires_at", sessionData.ExpiresAt)

		// Redirect back to original URL or default to root.
		// Belt-and-braces re-validation: the state-bound originalURL
		// was checked at redirectToLogin time, but we re-check here so
		// any future code path that stores a return URL without going
		// through redirectToLogin can't introduce an open redirect.
		redirectURL := originalURL
		if redirectURL != "" && !isSafeLocalRedirect(redirectURL) {
			s.logger.Warn(logging.DestinationHTTP, "Discarding unsafe redirect URL from OAuth2 state", "value", redirectURL)
			redirectURL = ""
		}
		if redirectURL == "" {
			redirectURL = "/"
		}
		s.logger.Info(logging.DestinationHTTP, "Browser authentication successful, redirecting",
			"subject", subject, "redirect_url", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Determine granted scopes based on group membership
	requestedScopes := ar.GetRequestedScopes()
	grantedScopes := s.getScopesForGroups(userGroups, requestedScopes)

	s.logger.Info(logging.DestinationHTTP, "Granting scopes based on group membership",
		"subject", subject,
		"requested_scopes", requestedScopes,
		"granted_scopes", grantedScopes)

	// Grant scopes
	for _, scope := range grantedScopes {
		ar.GrantScope(scope)
	}

	// Create session with the authenticated user. The IDP-asserted groups
	// are persisted with the grant so reauthorizeRefreshGrant can re-run
	// getScopesForGroups when the grant is refreshed — this is the only
	// place they are ever read, and they would otherwise be dropped here.
	session := DefaultOpenIDConnectSession(subject).WithGroups(userGroups)

	// Generate OAuth2 response
	response, err := s.oauth2Provider.GetProvider().NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		// Extract more detailed error information
		errorDetails := fmt.Sprintf("%v", err)
		var rfc6749Err *fosite.RFC6749Error
		if errors.As(err, &rfc6749Err) {
			errorDetails = fmt.Sprintf("RFC6749Error: name=%s, description=%s, hint=%s, debug=%s",
				rfc6749Err.ErrorField, rfc6749Err.DescriptionField, rfc6749Err.HintField, rfc6749Err.DebugField)
		}

		s.logger.Error(logging.DestinationHTTP, "Failed to create authorize response",
			"error", err, "error_details", errorDetails,
			"subject", subject, "client_id", ar.GetClient().GetID())
		s.oauth2Provider.GetProvider().WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	s.logger.Info(logging.DestinationHTTP, "OAuth2 callback completed successfully",
		"subject", subject, "granted_scopes", grantedScopes)

	// OAuth2 client flow - write the standard OAuth2 response
	s.oauth2Provider.GetProvider().WriteAuthorizeResponse(ctx, w, ar, response)
}

// handleLogin initiates the OAuth2 login flow
func (s *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Check if already authenticated
	if _, ok := s.getSessionFromRequest(r); ok {
		// Already authenticated, redirect to return_to or root.
		// Validate return_to is a same-origin path to defeat open
		// redirect attacks (gosec G710): a malicious link of the
		// form `/login?return_to=https://evil.example/` should NOT
		// be allowed to bounce a logged-in user off-site. gosec's
		// taint tracker still flags the http.Redirect because it
		// can't follow the validation; the check is real.
		returnURL := r.URL.Query().Get("return_to")
		if !isSafeLocalRedirect(returnURL) {
			returnURL = "/"
		}
		http.Redirect(w, r, returnURL, http.StatusFound) //nolint:gosec // validated by isSafeLocalRedirect
		return
	}

	s.redirectToLogin(w, r)
}

// claimNames lists the claim keys an IDP returned, sorted.
//
// Keys only: the values carry the user's identity and affiliations, and
// this runs on a failure path that an unauthenticated caller can reach
// repeatedly.
func claimNames(claims map[string]any) []string {
	names := make([]string, 0, len(claims))
	for k := range claims {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// claimsToClassAd renders an IDP's claims as a ClassAd.
//
// Values arrive as encoding/json produces them, so a string stays a
// string, a JSON array becomes a ClassAd list, a nested object becomes a
// nested ad addressable as "outer.inner", and null becomes UNDEFINED. A
// claim name that is not a bare identifier -- "urn:oid:..." or one with a
// hyphen -- is kept and can be referenced with the quoted-attribute
// syntax, 'urn:oid:1.3.6.1'.
func claimsToClassAd(claims map[string]any) *classad.ClassAd {
	ad := classad.New()
	for name, value := range claims {
		// A claim this library cannot represent is skipped rather than
		// aborting the login: it leaves the attribute UNDEFINED, which a
		// requirements expression can test for, and which fails closed
		// under any comparison.
		_ = ad.Set(name, value)
	}
	return ad
}

// evaluateLoginRequirements applies the admin's login policy to a token.
//
// The expression is evaluated against the claims, exactly as a schedd
// evaluates Requirements against a machine ad, so a deployment can say
// more than a list of providers can express -- an IDP AND an affiliation
// AND an assurance level:
//
//	idp == "https://login.wisc.edu/idp/shibboleth" &&
//	  regexp("MEMBER@wisc.edu", affiliation)
//
// It FAILS CLOSED. Only an expression evaluating to boolean TRUE admits
// the login; UNDEFINED, ERROR, and a non-boolean result all refuse. That
// is the important direction: a policy naming a claim the IDP stopped
// sending -- or misspelling one -- evaluates to UNDEFINED, and the
// alternative would be to silently admit everybody the moment the policy
// stopped meaning anything.
func (s *Handler) evaluateLoginRequirements(claims map[string]any) error {
	if s.oauth2Requirements == nil {
		return nil
	}

	result := s.oauth2Requirements.Eval(claimsToClassAd(claims))
	ok, err := result.BoolValue()
	if err != nil || !ok {
		// The expression text is the operator's own configuration, so it
		// is safe to return; the claim VALUES are not, and are not.
		return fmt.Errorf("this login does not satisfy the deployment's login requirements")
	}
	return nil
}

// renderIdentityDeniedPage tells a browser that its login could not be
// matched to a local account.
//
// Like the group-policy refusal below, the person here authenticated
// successfully and was then turned away by this deployment. The two
// refusals differ in what the person can do about it -- ask for a group,
// versus report a configuration problem -- so they say different things,
// but neither should reach a browser as JSON.
func (s *Handler) renderIdentityDeniedPage(w http.ResponseWriter, err error) {
	s.renderResultPage(w, http.StatusForbidden, "Access denied", "#f44336",
		"Access denied",
		"You signed in successfully, but this access point could not match your identity to a local account.",
		describeFailure(err))
}

// renderAccessDeniedPage tells a browser why its login was refused.
//
// The person reaching this authenticated successfully -- the identity
// provider vouched for them -- and were then turned away by this
// deployment's own group policy. That distinction is what the page has to
// convey, along with the group to ask for, or they will report it as a
// broken login.
func (s *Handler) renderAccessDeniedPage(w http.ResponseWriter, required *groupSet) {
	message := "You signed in successfully, but this access point's policy does not grant you access."
	sub := ""
	if required.configured() {
		sub = "Access requires membership in one of: " + required.String() +
			". Ask an administrator of this access point to add you."
	} else {
		sub = "Ask an administrator of this access point for access."
	}
	s.renderResultPage(w, http.StatusForbidden, "Access denied", "#f44336",
		"Access denied", message, sub)
}
