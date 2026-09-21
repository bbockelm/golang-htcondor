package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// warningHeadline is the banner's own text. Matched instead of the CSS
// class, which the stylesheet carries on every page whether or not a
// banner is rendered -- asserting the class passed against a page that
// had none.
const warningHeadline = "asking for administrative access"

func consentTestHandler(t *testing.T, adminGroup, superuserGroup string) *Handler {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return &Handler{
		logger:             lg,
		mcpAdminGroups:     newGroupSet(adminGroup),
		mcpSuperuserGroups: newGroupSet(superuserGroup),
		mcpReadGroups:      newGroupSet(""),
		mcpWriteGroups:     newGroupSet(""),
		mcpAccessGroups:    newGroupSet(""),
	}
}

func renderConsentFor(t *testing.T, h *Handler, groups, requested []string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.renderConsentPage(rec, groups, consentPageParams{
		Title:           "Authorize Application",
		Username:        "bbockelm",
		ClientID:        "test-client",
		RequestedScopes: requested,
		FormAction:      "/mcp/oauth2/consent",
		HiddenFields:    map[string]string{"state": "s"},
	})
	return rec.Body.String()
}

// TestPrivilegedScopesAreAdvertised: a client only asks for scopes the
// server advertises, so an unadvertised scope cannot be requested by
// anything -- which is what left the whole admin/superuser tier
// unreachable rather than merely unused.
func TestPrivilegedScopesAreAdvertised(t *testing.T) {
	advertised := make(map[string]bool, len(oauth2AdvertisedScopes))
	for _, scope := range oauth2AdvertisedScopes {
		advertised[scope] = true
	}
	for scope := range privilegedScopes {
		if !advertised[scope] {
			t.Errorf("%s is not advertised, so no client can request it", scope)
		}
	}
}

// TestPrivilegedScopesAreOfferedUnchecked is the difference between this
// being a safety feature and a liability.
//
// Rendered checked like every other scope, an admin grants every client
// power over everyone's jobs unless they remember to decline, on every
// authorization -- and having forgotten once is not visible afterwards.
// Unchecked makes granting it an act rather than an omission.
func TestPrivilegedScopesAreOfferedUnchecked(t *testing.T) {
	h := consentTestHandler(t, "condor-admins", "condor-supers")
	page := renderConsentFor(t, h,
		[]string{"condor-admins", "condor-supers"},
		[]string{"openid", "mcp:read", "mcp:admin", "mcp:superuser"})

	for _, scope := range []string{"mcp:admin", "mcp:superuser"} {
		i := strings.Index(page, `value="`+scope+`"`)
		if i < 0 {
			t.Fatalf("%s was not offered to a member of its group:\n%s", scope, page)
		}
		// The input element ends at the next ">".
		input := page[i:]
		if end := strings.Index(input, ">"); end >= 0 {
			input = input[:end]
		}
		if strings.Contains(input, "checked") {
			t.Errorf("%s is pre-checked; granting it would be the default: %s", scope, input)
		}
	}

	// An ordinary scope keeps the old behaviour -- declining mcp:read is
	// not the decision this is protecting.
	i := strings.Index(page, `value="mcp:read"`)
	if i < 0 {
		t.Fatal("mcp:read was not offered")
	}
	if input := page[i : i+strings.Index(page[i:], ">")]; !strings.Contains(input, "checked") {
		t.Errorf("mcp:read is no longer pre-checked: %s", input)
	}

	// Assert the banner's words, not its class: the class is in the
	// stylesheet of every page, so matching it is satisfied by a page
	// with no banner at all.
	if !strings.Contains(page, warningHeadline) {
		t.Error("no warning is shown on a page offering administrative access")
	}
}

// TestUngrantableScopesAreNotOffered: a checkbox that cannot be granted
// reads either as a privilege the user holds and does not, or as a
// refusal nobody gave them. getScopesForGroups drops it at grant time
// either way, so offering it only misleads.
func TestUngrantableScopesAreNotOffered(t *testing.T) {
	h := consentTestHandler(t, "condor-admins", "condor-supers")
	requested := []string{"openid", "mcp:read", "mcp:admin", "mcp:superuser"}

	page := renderConsentFor(t, h, []string{"some-other-group"}, requested)
	for _, scope := range []string{"mcp:admin", "mcp:superuser"} {
		if strings.Contains(page, `value="`+scope+`"`) {
			t.Errorf("%s was offered to a user outside its group", scope)
		}
	}
	if strings.Contains(page, warningHeadline) {
		t.Error("a warning about administrative access is shown when none is on offer")
	}
	if !strings.Contains(page, `value="mcp:read"`) {
		t.Error("filtering removed a scope the user can have")
	}

	// A member of the admin group but not the superuser group sees
	// exactly the one they can be given.
	page = renderConsentFor(t, h, []string{"condor-admins"}, requested)
	if !strings.Contains(page, `value="mcp:admin"`) {
		t.Error("mcp:admin was withheld from a member of the admin group")
	}
	if strings.Contains(page, `value="mcp:superuser"`) {
		t.Error("mcp:superuser was offered to someone outside the superuser group")
	}
}

// The device flow renders through the same page, so it inherits the same
// filtering -- and it resolves the approver from the request rather than
// being handed a name, which is what made it easy to miss.
func TestDeviceConsentFiltersUngrantableScopes(t *testing.T) {
	h := consentTestHandler(t, "condor-admins", "condor-supers")
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/mcp/oauth2/device/verify", nil)

	h.renderDeviceConsentPage(rec, req, "bbockelm", "ABCD-EFGH",
		deviceRequestLike([]string{"openid", "mcp:read", "mcp:superuser"}, nil))

	page := rec.Body.String()
	if strings.Contains(page, `value="mcp:superuser"`) {
		t.Error("the device page offered mcp:superuser to an unidentified approver")
	}
	if !strings.Contains(page, `value="mcp:read"`) {
		t.Error("the device page dropped a scope it should offer")
	}
}
