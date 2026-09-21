package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Asking the identity provider, on a refresh, whether a user is still who
// they were.
//
// This is the membership drift the rest of the refresh path cannot see. The
// groups in a session are frozen at consent, so re-running the policy catches
// an operator changing it and not a user being removed from a group upstream;
// systemGroupOracle closes that where the deployment reads an account
// database, and a container has none. Here the provider is asked directly,
// with the credential it issued at login.
//
// The whole safety of this rests on one distinction, the same one that makes
// systemGroupOracle safe to act on: the provider saying "this grant is dead"
// is a fact about the user, while the provider not answering is a fact about
// the network. Reading the second as the first revokes every grant that
// happens to refresh during an outage.

// upstreamCheckInterval is the least time between two questions about one
// user.
//
// A client refreshes on its own timer -- minutes, sometimes less -- and there
// is no reason the provider should hear about that. Without a floor, one busy
// agent turns into steady load on somebody else's identity service, which is
// both rude and the sort of thing that gets an access point rate-limited at
// the worst possible moment.
const upstreamCheckInterval = 15 * time.Minute

// userInfoFetcher is the provider call, injected so a test can be the
// provider. It returns the subject and groups the provider now reports.
type userInfoFetcher func(ctx context.Context, accessToken string) (*UserInfo, error)

// tokenRefresher exchanges a stored refresh token for a usable access token.
type tokenRefresher func(ctx context.Context, refreshToken string) (*oauth2.Token, error)

type upstreamUserInfoOracle struct {
	store    *upstreamRefreshStore
	issuer   func() string
	refresh  tokenRefresher
	userInfo userInfoFetcher

	// validate and scopesFor are the deployment's own policy, the same
	// two systemGroupOracle consults, so a group read from the provider
	// is judged by exactly the rules a group read at login was.
	validate  func(groups []string) error
	scopesFor func(groups, requested []string) []string

	logger *logging.Logger
	now    func() time.Time
}

func (o *upstreamUserInfoOracle) Name() string { return "upstream-userinfo" }

// Check asks the provider about one user.
func (o *upstreamUserInfoOracle) Check(ctx context.Context, username string, scopes []string) (ReauthDecision, error) {
	issuer := o.issuer()
	if issuer == "" {
		return ReauthDecision{}, nil
	}

	grant, err := o.store.Load(ctx, username, issuer)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No credential for this user. The ordinary case wherever the
		// provider does not release offline_access, and not an opinion
		// about them.
		return ReauthDecision{}, nil
	case err != nil:
		return ReauthDecision{}, fmt.Errorf("reading the stored credential for %q: %w", username, err)
	}
	if !grant.HasOfflineAccess() {
		return ReauthDecision{}, nil
	}

	// Rate limit per user, not globally: one agent refreshing hard must
	// not stop everybody else being checked, and must not turn into load
	// on the provider either.
	if !grant.LastCheckedAt.IsZero() && o.now().Sub(grant.LastCheckedAt) < upstreamCheckInterval {
		return ReauthDecision{}, nil
	}

	token, err := o.refresh(ctx, grant.RefreshToken)
	if err != nil {
		if isUpstreamGrantDead(err) {
			// The provider has disowned the credential. That is its answer
			// about this user -- the account is gone, or an administrator
			// pulled the grant there -- and the local session should end
			// with it. Forget the credential too: it will never work
			// again, and retrying it every refresh is asking a provider to
			// rate-limit us.
			if err := o.store.Delete(ctx, username, issuer); err != nil {
				o.logger.Warn(logging.DestinationHTTP,
					"Could not forget a credential the provider rejected",
					"subject", username, "error", err)
			}
			return ReauthDecision{
				Status: UserStatusRevoked,
				Reason: "the identity provider no longer recognises this authorization",
			}, nil
		}
		// Anything else is the provider being unreachable, which is not an
		// opinion about the user.
		return ReauthDecision{}, fmt.Errorf(
			"not re-checking %q: the identity provider could not be reached: %w", username, err)
	}

	info, err := o.userInfo(ctx, token.AccessToken)
	if err != nil {
		if isUpstreamUserGone(err) {
			return ReauthDecision{
				Status: UserStatusRevoked,
				Reason: "the identity provider no longer has this user",
			}, nil
		}
		return ReauthDecision{}, fmt.Errorf(
			"not re-checking %q: reading userinfo failed: %w", username, err)
	}

	// The call named nobody: the credential decided whose claims came
	// back. If they are somebody else's, the row is wrong and acting on
	// it would apply one person's groups to another -- so refuse to act
	// rather than guess which of the two identities is the real one.
	if grant.ProviderSubject != "" && info.Subject != "" && info.Subject != grant.ProviderSubject {
		return ReauthDecision{}, fmt.Errorf(
			"not re-checking %q: the provider answered for %q, not the %q this credential was filed under",
			username, info.Subject, grant.ProviderSubject)
	}

	if err := o.store.MarkChecked(ctx, username, issuer, o.now()); err != nil {
		o.logger.Warn(logging.DestinationHTTP, "Could not record an upstream check",
			"subject", username, "error", err)
	}

	groups := extractGroups(info.Groups)
	if err := o.validate(groups); err != nil {
		return ReauthDecision{
			Status: UserStatusRevoked,
			Reason: fmt.Sprintf("group membership at the identity provider no longer grants access: %v", err),
		}, nil
	}

	// Still entitled to something, perhaps less. Report the difference
	// rather than failing the refresh, so a user who lost write access
	// keeps working read-only -- the same shape systemGroupOracle uses.
	allowed := o.scopesFor(groups, scopes)
	var denied []string
	for _, s := range scopes {
		if !containsString(allowed, s) {
			denied = append(denied, s)
		}
	}
	if len(denied) > 0 {
		o.logger.Info(logging.DestinationHTTP,
			"Narrowing a grant to the membership the identity provider now reports",
			"subject", username, "denied", denied, "groups", groups)
		return ReauthDecision{Status: UserStatusActive, DeniedScopes: denied}, nil
	}
	return ReauthDecision{Status: UserStatusActive}, nil
}

// isUpstreamGrantDead reports whether the provider refused the refresh token
// because it is finished, rather than because it could not answer.
//
// invalid_grant is the one code that means this: RFC 6749 uses it for a
// refresh token that is expired, revoked, or no longer matches. Every other
// failure -- a timeout, a 5xx, a DNS failure, invalid_client -- is about the
// call, not the user.
func isUpstreamGrantDead(err error) bool {
	if err == nil {
		return false
	}
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) {
		if retrieve.ErrorCode == "invalid_grant" {
			return true
		}
		// A provider that sends no machine-readable code but answers 400
		// is still refusing the credential rather than failing to serve
		// it; 401 is the same statement about the client's own
		// registration and is deliberately NOT read as the user being
		// gone.
		return retrieve.ErrorCode == "" && retrieve.Response != nil &&
			retrieve.Response.StatusCode == http.StatusBadRequest
	}
	return false
}

// isUpstreamUserGone reports whether userinfo said the user no longer exists.
//
// Deliberately narrow. 401 here means the access token this server just
// minted is not accepted, which is more often a clock skew or a provider
// quirk than a deleted account, so only an explicit 404 counts.
func isUpstreamUserGone(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "status 404")
}

// registerUpstreamOracle wires the provider check into the refresh path.
//
// A named method so a test can exercise the decision rather than the
// composition around it: "always register" is not obviously wrong, and it is
// a call to a nil oauth2Config on the first refresh.
func (h *Handler) registerUpstreamOracle(logger *logging.Logger) {
	if h.upstreamRefresh == nil || h.upstreamRefreshMode == UpstreamRefreshOff {
		return
	}
	if h.oauth2Config == nil || h.oauth2UserInfoURL == "" {
		// Nothing to ask. A deployment with no upstream provider -- the
		// built-in IDP, or header auth -- has no one to check with, and
		// registering here would be a per-refresh no-op at best.
		return
	}

	h.revocationOracles = append(h.revocationOracles, &upstreamUserInfoOracle{
		store:  h.upstreamRefresh,
		issuer: h.upstreamIssuer,
		refresh: func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
			// TokenSource does the exchange and, importantly, surfaces the
			// provider's own error -- oauth2.RetrieveError with its code --
			// which is what tells a dead credential from an unreachable
			// provider.
			ctx = context.WithValue(ctx, oauth2.HTTPClient, h.getHTTPClient())
			return h.oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
		},
		userInfo:  h.fetchUserInfo,
		validate:  h.validateGroupAccess,
		scopesFor: h.getScopesForGroups,
		logger:    logger,
		now:       time.Now,
	})
	logger.Info(logging.DestinationHTTP,
		"Refresh grants will re-check membership with the identity provider",
		"mode", string(h.upstreamRefreshMode), "interval", upstreamCheckInterval.String())
}
