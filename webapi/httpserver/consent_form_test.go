package httpserver

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// scopeInputsInsideForm returns the scope values the browser would actually
// submit: the name="scope" controls that lie between <form and </form>.
// Controls outside the form element are not submitted, however they look.
func scopeInputsInsideForm(t *testing.T, page string) []string {
	t.Helper()
	open := strings.Index(page, "<form")
	closed := strings.Index(page, "</form>")
	if open < 0 || closed < 0 || closed < open {
		t.Fatalf("no <form> in the rendered page")
	}
	body := page[open:closed]

	var out []string
	for _, chunk := range strings.Split(body, `name="scope"`)[1:] {
		i := strings.Index(chunk, `value="`)
		if i < 0 {
			continue
		}
		rest := chunk[i+len(`value="`):]
		j := strings.Index(rest, `"`)
		if j < 0 {
			continue
		}
		out = append(out, rest[:j])
	}
	return out
}

// TestConsentFormSubmitsEveryScope is the bug behind a login that completes and
// then grants nothing but openid:
//
//	User approved consent accepted_scopes=[openid] granted_scopes=[openid]
//	  requested_scopes=[openid profile email offline_access mcp:read mcp:write ...]
//
// The scope checkboxes were rendered outside the <form>, so the browser never
// submitted them, narrowConsentScopes saw an empty form and returned its
// unconditional {openid}, and ticking the boxes changed nothing. Rendering the
// page and reading what is inside the form is the only way to see that; a test
// that posts its own scope fields asserts what the page was assumed to do.
func TestConsentFormSubmitsEveryScope(t *testing.T) {
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	h := &Handler{logger: lg}

	requested := []string{
		"openid", "profile", "email", "offline_access",
		"mcp:read", "mcp:write", "condor:/READ", "condor:/WRITE",
	}

	rec := httptest.NewRecorder()
	h.renderConsentPage(rec, consentPageParams{
		Title:           "Authorize",
		Username:        "bbockelm",
		ClientID:        "https://claude.ai/oauth/claude-code-client-metadata",
		RequestedScopes: requested,
		FormAction:      "/mcp/oauth2/consent",
		HiddenFields:    map[string]string{"state": "abc"},
	})

	page := rec.Body.String()
	got := scopeInputsInsideForm(t, page)
	t.Logf("scope inputs the browser would submit: %v", got)

	inside := make(map[string]bool, len(got))
	for _, s := range got {
		inside[s] = true
	}
	for _, want := range requested {
		if !inside[want] {
			t.Errorf("scope %q is not submitted by the form (rendered outside it, or missing)", want)
		}
	}
}

// TestDeviceConsentFormSubmitsEveryScope: the device page is the same renderer,
// so the same markup bug silenced device logins too. Fixing the scope narrowing
// (the granted-set intersection) was necessary and not sufficient -- the form
// never submitted a scope field for either flow.
func TestDeviceConsentFormSubmitsEveryScope(t *testing.T) {
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	h := &Handler{logger: lg}

	requested := []string{"openid", "mcp:read", "mcp:write", "offline_access"}
	rec := httptest.NewRecorder()
	h.renderDeviceConsentPage(rec, nil, "bbockelm", "ABCD-EFGH",
		deviceRequestLike(requested, nil))

	got := scopeInputsInsideForm(t, rec.Body.String())
	t.Logf("device consent submits: %v", got)

	inside := make(map[string]bool, len(got))
	for _, s := range got {
		inside[s] = true
	}
	for _, want := range requested {
		if !inside[want] {
			t.Errorf("device consent does not submit %q", want)
		}
	}
}
