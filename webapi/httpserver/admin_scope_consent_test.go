package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
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
	h.renderConsentPage(context.Background(), rec, groups, consentPageParams{
		Title:           "Authorize Application",
		Username:        "bbockelm",
		ClientID:        "test-client",
		RequestedScopes: requested,
		FormAction:      "/mcp/oauth2/consent",
		HiddenFields:    map[string]string{"state": "s"},
	})
	return rec.Body.String()
}

// TestPrivilegedScopesAreReachable: a privileged scope nothing can ask
// for is not a safety feature, it is dead vocabulary -- which is what
// left the whole admin/superuser tier unreachable rather than merely
// unused.
//
// There are two ways to reach one, and a scope needs only one of them.
// An OAuth2 client asks for what the server advertises, so an OAuth2
// scope must be in oauth2AdvertisedScopes. An API key is minted
// directly by an administrator and never goes through an authorization
// flow at all, so an API-key scope must be in validScopes instead. The
// pool:* entitlements are mintable today and not advertised; whether
// they should also become OAuth2 scopes is open (see
// design_notes/ENTITLEMENT_VOCABULARY.md), and this test is written so
// that answering it either way does not require editing the test.
func TestPrivilegedScopesAreReachable(t *testing.T) {
	advertised := make(map[string]bool, len(oauth2AdvertisedScopes))
	for _, scope := range oauth2AdvertisedScopes {
		advertised[scope] = true
	}
	for scope := range privilegedScopes {
		_, mintable := validScopes[scope]
		if !advertised[scope] && !mintable {
			t.Errorf("%s is privileged but neither advertised nor mintable, "+
				"so nothing can ever request it", scope)
		}
	}
}

// And the OAuth2 half of that keeps its stronger form: a privileged
// scope an OAuth2 grant can carry must stay advertised, or every client
// holding it fails to refresh.
func TestOAuth2PrivilegedScopesStayAdvertised(t *testing.T) {
	advertised := make(map[string]bool, len(oauth2AdvertisedScopes))
	for _, scope := range oauth2AdvertisedScopes {
		advertised[scope] = true
	}
	for _, scope := range []string{"mcp:admin", "mcp:superuser", scopePoolRead, scopePoolWrite} {
		if !privilegedScopes[scope] {
			t.Errorf("%s is no longer marked privileged", scope)
		}
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
		[]string{"openid", "mcp:read", "mcp:admin", "mcp:superuser", scopePoolRead, scopePoolWrite})

	for _, scope := range []string{"mcp:admin", "mcp:superuser", scopePoolRead, scopePoolWrite} {
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
	for _, scope := range []string{"mcp:admin", "mcp:superuser", scopePoolRead, scopePoolWrite} {
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

// Advertising a privileged scope is only safe because something grants
// it deliberately. getScopesForGroups ends in a default branch that
// grants an unrecognized scope unconditionally, so a scope advertised
// without a case of its own is handed to every client that asks for it.
//
// That is the whole hazard of this change: pool:read and pool:write
// went from unreachable to requestable by anyone, and the only thing
// between "requestable" and "granted" is the switch above.
func TestAdvertisedPrivilegedScopesAreNotGrantedByDefault(t *testing.T) {
	h := consentTestHandler(t, "condor-admins", "condor-supers")

	outsider := []string{"users"}
	for _, scope := range []string{"mcp:admin", "mcp:superuser", scopePoolRead, scopePoolWrite} {
		got := h.getScopesForGroups(outsider, []string{scope})
		if slices.Contains(got, scope) {
			t.Errorf("%s was granted to a user in none of the privileged groups: %v", scope, got)
		}
	}

	// And the entitled user does get them, or the advertisement is a
	// promise the server never keeps.
	if got := h.getScopesForGroups([]string{"condor-admins"}, []string{scopePoolRead}); !slices.Contains(got, scopePoolRead) {
		t.Errorf("an admin-group member was not granted %s: %v", scopePoolRead, got)
	}
	if got := h.getScopesForGroups([]string{"condor-supers"}, []string{scopePoolWrite}); !slices.Contains(got, scopePoolWrite) {
		t.Errorf("a superuser-group member was not granted %s: %v", scopePoolWrite, got)
	}
	// Neither implies the other.
	if got := h.getScopesForGroups([]string{"condor-admins"}, []string{scopePoolWrite}); slices.Contains(got, scopePoolWrite) {
		t.Errorf("the admin group was granted %s: %v", scopePoolWrite, got)
	}
}

// With no privileged group configured at all, nobody gets them --
// "unset" means nobody, not everybody, for a cross-user power.
func TestPoolScopesNeedAConfiguredGroup(t *testing.T) {
	h := consentTestHandler(t, "", "")
	for _, scope := range []string{scopePoolRead, scopePoolWrite} {
		if got := h.getScopesForGroups([]string{"anyone"}, []string{scope}); slices.Contains(got, scope) {
			t.Errorf("%s was granted with no group configured: %v", scope, got)
		}
	}
}
