package httpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Deleting token rows once they are old enough to be of no use to anybody.
//
// Revocation deactivates rows rather than deleting them, deliberately: the
// listing can then still show what was revoked, which is most of the value of
// an audit page. But "keep it so an operator can see it" has a horizon, and
// without one the two token tables grow for the life of the deployment -- an
// access point issuing tokens to a few agents on a refresh timer writes a row
// every few minutes, forever.

// DefaultTokenRetention is how long a dead token row is kept.
//
// Ninety days is chosen to outlast the question an operator asks of this page
// ("what did that client do, and when did we cut it off?") without keeping
// rows nobody will ever read. Rows still in use are never touched whatever
// this says: the cutoff applies to tokens that have expired or been revoked.
const DefaultTokenRetention = 90 * 24 * time.Hour

// tokenRetention is the configured horizon, or the default.
func (h *Handler) tokenRetention() time.Duration {
	if h.tokenRetentionFor > 0 {
		return h.tokenRetentionFor
	}
	return DefaultTokenRetention
}

// purgeExpiredTokens deletes access and refresh rows that are both dead and
// older than the retention horizon.
//
// Dead is the important half. A row is removed only if it has expired or been
// revoked AND has been in that state past the horizon -- a live grant is
// never touched however old the authorization behind it is, because a
// long-lived refresh token that is still working is not stale data, it is
// somebody's session.
func (h *Handler) purgeExpiredTokens(ctx context.Context) (int64, error) {
	if h.oauth2Provider == nil {
		return 0, nil
	}
	db := h.oauth2Provider.GetStorage().GetDB()
	cutoff := time.Now().UTC().Add(-h.tokenRetention())

	var total int64
	for _, table := range []string{"oauth2_access_tokens", "oauth2_refresh_tokens"} {
		// requested_at is the age of the row; expires_at decides whether it
		// is dead. A NULL expires_at is a refresh token with no expiry, so
		// only an explicit deactivation makes it eligible.
		res, err := db.ExecContext(ctx,
			"DELETE FROM "+table+" WHERE requested_at < ? AND "+ //nolint:gosec // G202: table is from a fixed literal list
				"(active = 0 OR (expires_at IS NOT NULL AND expires_at < ?))",
			cutoff, cutoff)
		if err != nil {
			return total, fmt.Errorf("purging %s: %w", table, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			total += n
		}
	}
	return total, nil
}

// grantStateGrace is how long past its expiry an in-flight authorization
// row is kept: a device code, an authorization code, or the PKCE and
// OpenID Connect state stored beside one. None of them is any use once
// expired -- what came of the authorization is in the token tables --
// so the grace only covers clock skew and a row whose expiry was taken
// from a shorter-lived token than the code it belongs to.
const grantStateGrace = time.Hour

// grantStateTables hold in-flight authorization state with an expires_at.
var grantStateTables = []string{
	"oauth2_device_codes",
	"oauth2_authorization_codes",
	"oauth2_pkce_requests",
	"oauth2_oidc_sessions",
}

// purgeExpiredGrantState deletes in-flight authorization rows that have
// expired. These are written by endpoints a caller reaches before
// authenticating, so unlike the token rows they are not kept for audit
// and HTTP_API_TOKEN_RETENTION does not apply.
//
// Compared with julianday rather than as text: expires_at is written in
// whatever zone the time it came from carried.
func (h *Handler) purgeExpiredGrantState(ctx context.Context) (int64, error) {
	if h.oauth2Provider == nil {
		return 0, nil
	}
	db := h.oauth2Provider.GetStorage().GetDB()
	cutoff := time.Now().UTC().Add(-grantStateGrace)

	var total int64
	for _, table := range grantStateTables {
		res, err := db.ExecContext(ctx,
			"DELETE FROM "+table+" WHERE julianday(expires_at) < julianday(?)", //nolint:gosec // G202: table is from a fixed literal list
			cutoff)
		if err != nil {
			return total, fmt.Errorf("purging %s: %w", table, err)
		}
		if n, err := res.RowsAffected(); err == nil {
			total += n
		}
	}
	return total, nil
}

// unusedClientTTL is how long a dynamically registered client that has
// never obtained a token is kept. Registering is unauthenticated and an
// application normally completes its first authorization within minutes
// of registering, so a week covers one that was set up and left.
const unusedClientTTL = 7 * 24 * time.Hour

// purgeUnusedClients deletes dynamically registered clients that never
// obtained a token. A client an operator has touched -- annotated, given
// a service identity, or granted client_credentials or token exchange,
// none of which a registration can declare -- is kept whatever its use.
func (h *Handler) purgeUnusedClients(ctx context.Context) (int64, error) {
	if h.oauth2Provider == nil {
		return 0, nil
	}
	db := h.oauth2Provider.GetStorage().GetDB()
	cutoff := time.Now().UTC().Add(-unusedClientTTL)
	res, err := db.ExecContext(ctx, `
		DELETE FROM oauth2_clients
		WHERE origin = ? AND last_used_at IS NULL
			AND notes = '' AND service_subject = ''
			AND grant_types NOT LIKE '%client_credentials%'
			AND grant_types NOT LIKE ?
			AND julianday(created_at) < julianday(?)
			AND NOT EXISTS (SELECT 1 FROM oauth2_access_tokens t WHERE t.client_id = oauth2_clients.id)
			AND NOT EXISTS (SELECT 1 FROM oauth2_refresh_tokens t WHERE t.client_id = oauth2_clients.id)`,
		string(ClientOriginDynamic), "%"+tokenExchangeGrantType+"%", cutoff)
	if err != nil {
		return 0, fmt.Errorf("purging unused clients: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// runTokenRetention purges on a timer for the life of the process.
//
// Expired authorization state and unused clients are swept hourly: they
// are written by unauthenticated endpoints, so how fast they can pile up
// is set by the rate limits on those, and an hour of it is small. Token
// rows are swept daily, and not at all when retention is off: this is
// housekeeping, and a table that has been growing for years does not need
// to be trimmed to the minute. One pass on start, so a deployment that is
// restarted often still gets swept.
func (h *Handler) runTokenRetention(ctx context.Context) {
	var lastTokenSweep time.Time
	sweep := func() {
		if n, err := h.purgeExpiredGrantState(ctx); err != nil {
			h.logger.Warn(logging.DestinationHTTP, "Expired authorization state sweep failed", "error", err)
		} else if n > 0 {
			h.logger.Info(logging.DestinationHTTP, "Deleted expired authorization state", "rows", n)
		}
		if n, err := h.purgeUnusedClients(ctx); err != nil {
			h.logger.Warn(logging.DestinationHTTP, "Unused client sweep failed", "error", err)
		} else if n > 0 {
			h.logger.Info(logging.DestinationHTTP, "Deleted dynamically registered clients that never obtained a token",
				"clients", n, "after", unusedClientTTL.String())
		}

		if h.tokenRetentionFor < 0 || time.Since(lastTokenSweep) < 24*time.Hour {
			return
		}
		lastTokenSweep = time.Now()
		n, err := h.purgeExpiredTokens(ctx)
		if err != nil {
			h.logger.Warn(logging.DestinationHTTP, "Token retention sweep failed",
				"retention", h.tokenRetention().String(), "error", err)
			return
		}
		if n > 0 {
			h.logger.Info(logging.DestinationHTTP, "Deleted expired token rows past the retention horizon",
				"rows", n, "retention", h.tokenRetention().String())
		}
	}

	sweep()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// ParseTokenRetention reads HTTP_API_TOKEN_RETENTION.
//
// "0" or "off" keeps rows forever, which is a defensible choice for a
// deployment whose audit policy says so -- and an explicit one, rather than
// something reached by leaving a knob unset.
func ParseTokenRetention(raw string) (time.Duration, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case "":
		return 0, nil
	case "0", "off", "never":
		return -1, nil
	}
	d, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("expected a duration with a unit (e.g. 2160h), got %q", raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive, got %q", raw)
	}
	return d, nil
}
