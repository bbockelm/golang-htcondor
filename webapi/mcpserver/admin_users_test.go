package mcpserver

import (
	"strings"
	"testing"
)

// An MCP_ADMIN_USERS entry names the identity the schedd reports, whose
// domain cedar and HTCondor give in lower case: the entry matches whatever
// case its domain is written in, and only the exact user part.
func TestAdminUsersDomainCaseInsensitive(t *testing.T) {
	cases := []struct {
		entry     string
		seesAlice bool
	}{
		{"bob@test.domain", true},
		{"bob@Test.DOMAIN", true},
		{"Bob@test.domain", false},
		{"bob@test.domain.example", false},
		{"bob", false},
	}
	for _, tc := range cases {
		t.Run(tc.entry, func(t *testing.T) {
			f := newActionScopeFixture(t)
			f.server.adminUsers = map[string]struct{}{tc.entry: {}}
			// An unscoped caller (stdio), the case the list applies to.
			bob := withGrant(f.as(t, "bob"), unscopedGrant)

			text, isErr := f.call(bob, t, "query_jobs", map[string]interface{}{"constraint": "true"})
			if isErr {
				t.Fatalf("query_jobs as bob: %s", text)
			}
			if got := strings.Contains(text, `"alice"`); got != tc.seesAlice {
				t.Errorf("query_jobs as bob with MCP_ADMIN_USERS=%q returned alice's job: %v, want %v\n%s", tc.entry, got, tc.seesAlice, text)
			}
			if !strings.Contains(text, `"bob"`) {
				t.Errorf("query_jobs as bob did not return his own job:\n%s", text)
			}

			who := whoamiText(bob, t, f.server)
			if got := strings.Contains(who, `"admin": true`); got != tc.seesAlice {
				t.Errorf("whoami as bob with MCP_ADMIN_USERS=%q reports admin %v, want %v\n%s", tc.entry, got, tc.seesAlice, who)
			}
		})
	}
}
