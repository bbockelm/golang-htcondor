package mcpserver

import (
	"context"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

func whoamiServer(t *testing.T, admins ...string) *Server {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	set := make(map[string]struct{}, len(admins))
	for _, a := range admins {
		set[a] = struct{}{}
	}
	return &Server{
		logger:     lg,
		schedd:     htcondor.NewSchedd("ap2001.chtc.wisc.edu", "<10.0.0.1:9618?sock=schedd>"),
		adminUsers: set,
	}
}

func whoamiText(ctx context.Context, t *testing.T, s *Server) string {
	t.Helper()
	res, err := s.toolWhoami(ctx, nil)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	m, _ := res.(map[string]interface{})
	content, _ := m["content"].([]map[string]interface{})
	if len(content) == 0 {
		t.Fatal("whoami returned no content")
	}
	text, _ := content[0]["text"].(string)
	return text
}

// TestWhoamiReportsAdmin: the question the tool exists to answer.
func TestWhoamiReportsAdmin(t *testing.T) {
	s := whoamiServer(t, "bbockelm@ap2001.chtc.wisc.edu")
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "bbockelm@ap2001.chtc.wisc.edu")

	got := whoamiText(ctx, t, s)
	t.Logf("\n%s", got)

	for _, want := range []string{
		"bbockelm@ap2001.chtc.wisc.edu",
		`"admin": true`,
		"all users",
		// MCP_ADMIN_USERS grants the read tier only, and the answer has
		// to say so rather than leave the caller to discover it when a
		// removal is refused.
		`"superuser": false`,
		"mcp:superuser",
		"MCP_ADMIN_USERS",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("whoami is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "not an administrator") {
		t.Errorf("an admin was reported as not an admin:\n%s", got)
	}
}

// TestWhoamiExplainsAnUnmatchedAdminEntry covers the failure that
// prompted the split: MCP_ADMIN_USERS is compared verbatim against the
// identity the schedd reports, so an entry written with the wrong domain
// never matches -- and the result is indistinguishable from not being
// listed. whoami has to name the mismatch.
func TestWhoamiExplainsAnUnmatchedAdminEntry(t *testing.T) {
	// Configured with the schedd name; the caller authenticates as
	// user@UID_DOMAIN. This is the real misconfiguration.
	s := whoamiServer(t, "bbockelm@ap2001.chtc.wisc.edu")
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "bbockelm@chtc.wisc.edu")

	got := whoamiText(ctx, t, s)
	t.Logf("\n%s", got)

	if !strings.Contains(got, `"admin": false`) {
		t.Errorf("an unmatched entry must not grant admin:\n%s", got)
	}
	// The point: say the list exists and did not match, not merely
	// "you are not an admin".
	for _, want := range []string{"MCP_ADMIN_USERS", "bbockelm@chtc.wisc.edu"} {
		if !strings.Contains(got, want) {
			t.Errorf("whoami should explain the mismatch, missing %q:\n%s", want, got)
		}
	}
}

// A caller holding mcp:superuser may mutate across users even though
// MCP_ADMIN_USERS does not list them.
func TestWhoamiReportsSuperuserFromScope(t *testing.T) {
	s := whoamiServer(t)
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "carol@uid.domain")
	ctx = WithGrantedScopes(ctx, []string{"mcp:read", "mcp:write", scopeMCPSuperuser})

	got := whoamiText(ctx, t, s)
	t.Logf("\n%s", got)

	if !strings.Contains(got, `"superuser": true`) {
		t.Errorf("mcp:superuser must grant the mutate tier:\n%s", got)
	}
}

// TestWhoamiReportsNonAdminConfinement: a non-admin must be told that the other
// tools are confined to their own jobs, which is the thing that otherwise shows
// up as an inexplicably empty query.
func TestWhoamiReportsNonAdminConfinement(t *testing.T) {
	s := whoamiServer(t, "someone-else@ap2001.chtc.wisc.edu")
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "bbockelm@ap2001.chtc.wisc.edu")

	got := whoamiText(ctx, t, s)
	t.Logf("\n%s", got)

	for _, want := range []string{"not an administrator", `"admin": false`, "your own jobs"} {
		if !strings.Contains(got, want) {
			t.Errorf("whoami is missing %q:\n%s", want, got)
		}
	}
}

// TestWhoamiAgreesWithEnforcement is the property that makes the tool worth
// trusting: it must report the confinement the tools actually apply, not a
// separately-derived opinion about it.
func TestWhoamiAgreesWithEnforcement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		admins []string
	}{
		{"admin", []string{"bbockelm@ap2001.chtc.wisc.edu"}},
		{"non-admin", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := whoamiServer(t, tc.admins...)
			ctx := htcondor.WithAuthenticatedUser(context.Background(), "bbockelm@ap2001.chtc.wisc.edu")

			scope, ok := s.ownerScope(ctx, tierRead)
			if !ok {
				t.Fatal("ownerScope refused an authenticated caller")
			}
			got := whoamiText(ctx, t, s)

			if scope.AllUsers && !strings.Contains(got, "all users") {
				t.Errorf("enforcement covers all users, whoami does not say so:\n%s", got)
			}
			if !scope.AllUsers && !strings.Contains(got, scope.Owner) {
				t.Errorf("enforcement confines to %q, whoami does not name it:\n%s", scope.Owner, got)
			}
		})
	}
}

// TestWhoamiOnAnUnidentifiedCaller: saying so is the useful answer, since every
// owner-scoped tool will refuse.
func TestWhoamiOnAnUnidentifiedCaller(t *testing.T) {
	s := whoamiServer(t)
	got := whoamiText(context.Background(), t, s)
	t.Logf("\n%s", got)

	if !strings.Contains(got, "not authenticated") {
		t.Errorf("an unidentified caller was not told so:\n%s", got)
	}
	if !strings.Contains(got, "refuse") {
		t.Errorf("whoami does not say the tools will refuse:\n%s", got)
	}
}

// TestWhoamiReportsScopes surfaces the token's scopes, which is what made an
// earlier "everything is refused" deployment hard to diagnose.
func TestWhoamiReportsScopes(t *testing.T) {
	s := whoamiServer(t)
	ctx := WithGrantedScopes(
		htcondor.WithAuthenticatedUser(context.Background(), "bbockelm@ap2001.chtc.wisc.edu"),
		[]string{"openid", "mcp:read"})

	got := whoamiText(ctx, t, s)
	if !strings.Contains(got, "mcp:read") || !strings.Contains(got, "openid") {
		t.Errorf("whoami does not report the token scopes:\n%s", got)
	}
}

// TestWhoamiIsReadOnly: it reports, so it must be usable by a read-only token.
func TestWhoamiIsReadOnly(t *testing.T) {
	if !readOnlyMCPTools["whoami"] {
		t.Error("whoami is not in the read-only allowlist, so mcp:read alone cannot call it")
	}
}
