package httpserver

import (
	"strings"
	"testing"
)

// The two ways a client silently ends up unable to refresh, and the
// cases that must NOT be flagged. A false warning here is worse than no
// warning: it teaches an operator to ignore the column.
func TestRefreshBlockedBy(t *testing.T) {
	const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

	cases := []struct {
		name   string
		grants []string
		scopes []string
		want   []string
	}{
		{
			name:   "a properly configured interactive client is fine",
			grants: []string{"authorization_code", "refresh_token"},
			scopes: []string{"openid", "offline_access", "mcp:read"},
			want:   nil,
		},
		{
			// fosite will not issue a refresh token without the grant.
			name:   "missing the refresh_token grant",
			grants: []string{"authorization_code"},
			scopes: []string{"openid", "offline_access"},
			want:   []string{"the refresh_token grant"},
		},
		{
			// filterRequestedScopes strips offline_access at authorize
			// time when the client is not registered for it, so fosite
			// never sees the request. This is the shape that bit
			// claude.ai.
			name:   "missing the offline_access scope",
			grants: []string{"authorization_code", "refresh_token"},
			scopes: []string{"openid", "profile"},
			want:   []string{"the offline_access scope"},
		},
		{
			name:   "missing both is reported as both",
			grants: []string{"authorization_code"},
			scopes: []string{"openid"},
			want:   []string{"the refresh_token grant", "the offline_access scope"},
		},
		{
			// A machine-to-machine client re-authenticates from its own
			// secret. There is no user to send back through consent, so
			// there is nothing to warn about.
			name:   "a client_credentials client is not flagged",
			grants: []string{"client_credentials"},
			scopes: []string{"mcp:read"},
			want:   nil,
		},
		{
			// The device flow has a human on the other end, so it does
			// exhibit the symptom.
			name:   "the device flow is interactive and is flagged",
			grants: []string{deviceGrant},
			scopes: []string{"openid"},
			want:   []string{"the refresh_token grant", "the offline_access scope"},
		},
		{
			// A row whose grants we do not know must not be accused of
			// anything.
			name:   "unknown grants are not flagged",
			grants: nil,
			scopes: nil,
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := refreshBlockedBy(tc.grants, tc.scopes)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
			// Whatever it says has to name the thing to add, or an
			// operator cannot act on it.
			for _, s := range got {
				if !strings.Contains(s, "refresh_token") && !strings.Contains(s, "offline_access") {
					t.Errorf("advisory does not name what is missing: %q", s)
				}
			}
		})
	}
}

// The defaults the registration handler applies must not produce a
// warning: if they did, every dynamically registered client would be
// flagged and the column would be meaningless.
func TestRegistrationDefaultsCanRefresh(t *testing.T) {
	// Kept in sync with handleOAuth2Register's defaults.
	grants := []string{"authorization_code", "refresh_token"}
	scopes := []string{"openid", "profile", "email", "offline_access", "mcp:read", "mcp:write"}

	if blocked := refreshBlockedBy(grants, scopes); blocked != nil {
		t.Errorf("the registration defaults would be flagged as unable to refresh: %v", blocked)
	}
}
