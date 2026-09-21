package httpserver

import (
	"context"
	"testing"
	"time"
)

// seedToken writes one row directly, so a test can place it in the past
// without waiting or mocking a clock into fosite.
func seedToken(t *testing.T, f *reauthFixture, table, sig string, requestedAt time.Time, active int, expiresAt *time.Time) {
	t.Helper()
	db := f.server.oauth2Provider.GetStorage().GetDB()
	//nolint:gosec // G202: table comes from this test's own two literals
	_, err := db.ExecContext(context.Background(),
		"INSERT INTO "+table+` (signature, request_id, requested_at, client_id, subject,
			scopes, granted_scopes, form_data, session_data, active, expires_at)
		 VALUES (?, ?, ?, 'c', 'alice', '[]', '[]', '{}', '{}', ?, ?)`,
		sig, "req-"+sig, requestedAt.UTC(), active, expiresAt)
	if err != nil {
		t.Fatalf("seeding %s: %v", table, err)
	}
}

func countRows(t *testing.T, f *reauthFixture, table string) int {
	t.Helper()
	var n int
	if err := f.server.oauth2Provider.GetStorage().GetDB().QueryRowContext(
		context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	return n
}

// TestRetentionKeepsLiveGrantsWhateverTheirAge is the half worth getting
// wrong-proof. A refresh token with no expiry that is still working is
// somebody's session, not stale data -- deleting it on age alone would log
// out every long-lived agent the moment this shipped.
func TestRetentionKeepsLiveGrantsWhateverTheirAge(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.server.tokenRetentionFor = 24 * time.Hour
	ancient := time.Now().UTC().Add(-365 * 24 * time.Hour)

	before := countRows(t, f, "oauth2_refresh_tokens")
	seedToken(t, f, "oauth2_refresh_tokens", "live-and-old", ancient, 1, nil)

	if _, err := f.server.purgeExpiredTokens(context.Background()); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := countRows(t, f, "oauth2_refresh_tokens"); got != before+1 {
		t.Errorf("a live refresh token was deleted for being old: %d rows, want %d", got, before+1)
	}
}

// A revoked row past the horizon is what this exists to remove.
func TestRetentionDeletesDeadRowsPastTheHorizon(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.server.tokenRetentionFor = 24 * time.Hour
	old := time.Now().UTC().Add(-48 * time.Hour)
	expired := old.Add(time.Hour)

	// An access token always carries an expiry -- the column is NOT NULL --
	// so the revoked one gets a past expiry too. Only refresh tokens may
	// have none, which is the asymmetry the purge query handles.
	seedToken(t, f, "oauth2_access_tokens", "revoked-old", old, 0, &expired)
	seedToken(t, f, "oauth2_access_tokens", "expired-old", old, 1, &expired)
	before := countRows(t, f, "oauth2_access_tokens")

	n, err := f.server.purgeExpiredTokens(context.Background())
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n < 2 {
		t.Errorf("purged %d rows; both the revoked and the expired one should have gone", n)
	}
	if got := countRows(t, f, "oauth2_access_tokens"); got != before-2 {
		t.Errorf("%d rows remain, want %d", got, before-2)
	}
}

// Dead but recent stays: an operator asking "when did we cut that client
// off?" is asking about exactly these rows.
func TestRetentionKeepsRecentlyRevokedRows(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.server.tokenRetentionFor = 90 * 24 * time.Hour
	recent := time.Now().UTC().Add(-2 * time.Hour)

	recentExpiry := recent.Add(time.Hour)
	seedToken(t, f, "oauth2_access_tokens", "revoked-recent", recent, 0, &recentExpiry)
	before := countRows(t, f, "oauth2_access_tokens")

	if _, err := f.server.purgeExpiredTokens(context.Background()); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := countRows(t, f, "oauth2_access_tokens"); got != before {
		t.Errorf("a recently revoked row was deleted; the page can no longer show it")
	}
}

func TestParseTokenRetention(t *testing.T) {
	for raw, want := range map[string]time.Duration{
		"":      0,
		"2160h": 2160 * time.Hour,
		"off":   -1,
		"0":     -1,
	} {
		got, err := ParseTokenRetention(raw)
		if err != nil {
			t.Errorf("ParseTokenRetention(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("ParseTokenRetention(%q) = %v, want %v", raw, got, want)
		}
	}
	for _, bad := range []string{"90", "-5h", "soon"} {
		if _, err := ParseTokenRetention(bad); err == nil {
			t.Errorf("ParseTokenRetention(%q) was accepted; a bare number is the "+
				"mistake worth catching, since it parses as nanoseconds elsewhere", bad)
		}
	}
}
