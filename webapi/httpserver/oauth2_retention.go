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

// runTokenRetention purges on a timer for the life of the process.
//
// Daily rather than hourly: this is housekeeping, and a table that has been
// growing for years does not need to be trimmed to the minute. One pass on
// start, so a deployment that is restarted often still gets swept.
func (h *Handler) runTokenRetention(ctx context.Context) {
	sweep := func() {
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
	ticker := time.NewTicker(24 * time.Hour)
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
