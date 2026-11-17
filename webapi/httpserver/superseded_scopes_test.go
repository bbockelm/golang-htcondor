package httpserver

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

// A superseded spelling and the name that replaced it are one power.
// Asked for together -- which is what a client registered on either side
// of the rename does -- they rendered as two checkboxes with the same
// label text, the same description and the same consequence, and a
// reader had no way to tell that ticking either one did the same thing.
func TestSupersededScopeIsHiddenBesideItsReplacement(t *testing.T) {
	h := consentTestHandler(t, "condor-admins", "condor-supers")
	page := renderConsentFor(t, h,
		[]string{"condor-admins", "condor-supers"},
		[]string{"openid", "mcp:read", "mcp:admin", "mcp:superuser", scopeAnyUserRead, scopeAnyUserWrite})

	for _, scope := range oauth2SupersededScopes {
		if strings.Contains(page, `value="`+scope+`"`) {
			t.Errorf("%s was offered beside the name that replaced it", scope)
		}
		if strings.Contains(page, "<strong>"+scope+"</strong>") {
			t.Errorf("%s is named on the page", scope)
		}
	}
	for _, scope := range []string{scopeAnyUserRead, scopeAnyUserWrite} {
		if n := strings.Count(page, `value="`+scope+`"`); n != 1 {
			t.Errorf("%s has %d checkboxes, want 1", scope, n)
		}
	}
}

// Asked for on its own, it is kept and offered under the newer name.
// Dropping it would take a power away from the one client that cannot
// ask for it by any other name: a registered client's scope list is
// fixed at registration, so one registered before anyuser:read existed
// can never request it.
func TestSupersededScopeAloneIsOfferedUnderItsNewName(t *testing.T) {
	h := consentTestHandler(t, "condor-admins", "condor-supers")
	page := renderConsentFor(t, h,
		[]string{"condor-admins", "condor-supers"},
		[]string{"openid", "mcp:read", "mcp:admin"})

	if !strings.Contains(page, `value="mcp:admin"`) {
		t.Fatalf("the only spelling the client can ask for was dropped:\n%s", page)
	}
	if !strings.Contains(page, "<strong>"+scopeAnyUserRead+"</strong>") {
		t.Errorf("the box is not labelled %s:\n%s", scopeAnyUserRead, page)
	}
	if strings.Contains(page, "<strong>mcp:admin</strong>") {
		t.Error("the superseded name is shown to the reader")
	}
	// Still unchecked, still warned about: relabelling it does not make
	// it an ordinary scope.
	i := strings.Index(page, `value="mcp:admin"`)
	if input := page[i : i+strings.Index(page[i:], ">")]; strings.Contains(input, "checked") {
		t.Errorf("mcp:admin is pre-checked: %s", input)
	}
	if !strings.Contains(page, warningHeadline) {
		t.Error("no warning is shown on a page offering administrative access")
	}
}

// Ticking the box accepts every spelling of that power the client asked
// for, so a client still holding the old name keeps what the user just
// granted it. This is the whole of "functional but invisible": the old
// name is never shown and never stops working.
func TestTickingTheReplacementAcceptsTheOldSpelling(t *testing.T) {
	requested := []string{"openid", "mcp:read", "mcp:admin", scopeAnyUserRead}

	ticked := url.Values{
		consentFormVersionField: {"1"},
		"scope":                 {"mcp:read", scopeAnyUserRead},
	}
	got := narrowConsentScopes(requested, ticked)
	for _, want := range []string{"openid", "mcp:read", scopeAnyUserRead, "mcp:admin"} {
		if !slices.Contains(got, want) {
			t.Errorf("accepting %s did not accept %s: %v", scopeAnyUserRead, want, got)
		}
	}

	// And an unticked box accepts neither spelling. A hidden scope that
	// rode along regardless would be a cross-user power granted by a
	// page that never mentioned it.
	untouched := url.Values{
		consentFormVersionField: {"1"},
		"scope":                 {"mcp:read"},
	}
	got = narrowConsentScopes(requested, untouched)
	for _, unwanted := range []string{"mcp:admin", scopeAnyUserRead} {
		if slices.Contains(got, unwanted) {
			t.Errorf("%s was accepted without being ticked: %v", unwanted, got)
		}
	}

	// Nothing rides along that the client did not ask for.
	got = narrowConsentScopes([]string{"openid", scopeAnyUserRead}, ticked)
	if slices.Contains(got, "mcp:admin") {
		t.Errorf("mcp:admin was accepted though unrequested: %v", got)
	}
}

// The name and its tag have to share one grid cell. The label is
// display:contents, so every element inside it is a grid item of the
// <li>: a tag outside .scope-head has no placement of its own, auto-flows
// into the 18px checkbox column, and wraps to three lines on top of the
// description -- which is how it shipped.
func TestPrivilegedTagSharesTheNameLine(t *testing.T) {
	h := consentTestHandler(t, "condor-admins", "condor-supers")
	page := renderConsentFor(t, h, []string{"condor-admins"},
		[]string{"openid", scopeAnyUserRead})

	i := strings.Index(page, `<span class="scope-head">`)
	if i < 0 {
		t.Fatalf("no .scope-head wrapping the name and its tag:\n%s", page)
	}
	head := page[i:]
	head = head[:strings.Index(head, "</span></span>")]
	if !strings.Contains(head, "<strong>"+scopeAnyUserRead+"</strong>") {
		t.Errorf(".scope-head does not hold the scope name: %s", head)
	}
	if !strings.Contains(head, `<span class="privileged-tag">`) {
		t.Errorf(".scope-head does not hold the tag: %s", head)
	}
	if !strings.Contains(page, ".scopes-list li.scope-privileged .scope-head {") {
		t.Error("the stylesheet gives .scope-head no placement of its own")
	}
}

// A grant carrying a superseded spelling must still refresh. A CIMD
// client has no stored scope list -- cimdClientScopes is recomputed on
// every authorize and every refresh -- so a name dropped from here stops
// being requestable at once, and every grant holding it fails with
// "the OAuth 2.0 Client is not allowed to request scope ...".
func TestSupersededScopesStayRequestableByACIMDClient(t *testing.T) {
	for _, scope := range oauth2SupersededScopes {
		if !slices.Contains(cimdClientScopes(""), scope) {
			t.Errorf("a CIMD client may no longer request %s", scope)
		}
		if !slices.Contains(cimdClientScopes("openid "+scope), scope) {
			t.Errorf("a CIMD document declaring %s was not taken at its word", scope)
		}
	}
}

// Every superseded name maps to a name that is actually offered, and to
// the same power: both answer to the same group, so the alias renames
// rather than widens.
func TestSupersededScopesMapToAdvertisedEquivalents(t *testing.T) {
	h := consentTestHandler(t, "condor-admins", "condor-supers")
	for old, canonical := range supersededScopes {
		if !slices.Contains(oauth2AdvertisedScopes, canonical) {
			t.Errorf("%s is offered under %s, which is not advertised", old, canonical)
		}
		if getScopeDescription(old) != getScopeDescription(canonical) {
			t.Errorf("%s and %s describe themselves differently", old, canonical)
		}
		for _, groups := range [][]string{{"condor-admins"}, {"condor-supers"}, {"nobody"}} {
			oldGranted := slices.Contains(h.getScopesForGroups(groups, []string{old}), old)
			newGranted := slices.Contains(h.getScopesForGroups(groups, []string{canonical}), canonical)
			if oldGranted != newGranted {
				t.Errorf("%v: %s granted = %v but %s granted = %v",
					groups, old, oldGranted, canonical, newGranted)
			}
		}
	}
}
