package httpserver

import (
	"encoding/json"
	"net/url"
	"testing"
)

// openid used to be granted whether or not it was asked for.
//
// A grant may not exceed what its client is registered for, and fosite
// checks the granted set against the registration on every refresh. So
// a client that never asked for openid got a grant that worked once and
// then failed for ever, naming a scope the user never chose.
func TestOpenIDIsGrantedOnlyWhenRequested(t *testing.T) {
	h := &Handler{}

	granted := h.getScopesForGroups(nil, []string{"condor:/WRITE", "offline_access"})
	for _, scope := range granted {
		if scope == "openid" {
			t.Fatalf("openid was granted without being requested; granted = %v", granted)
		}
	}

	// And a client that does ask still gets it.
	granted = h.getScopesForGroups(nil, []string{"openid", "condor:/WRITE"})
	found := false
	for _, scope := range granted {
		if scope == "openid" {
			found = true
		}
	}
	if !found {
		t.Errorf("openid was requested and not granted; granted = %v", granted)
	}
}

// A grant the groups refused entirely is an empty list, not nil, so it is
// stored as [] rather than JSON null; and a member still gets what they
// asked for.
func TestRefusedGrantIsEmptyNotNil(t *testing.T) {
	h := &Handler{mcpAccessGroups: newGroupSet("ap2001-login")}
	requested := []string{"mcp:read", "mcp:write"}

	granted := h.getScopesForGroups([]string{"someone-else"}, requested)
	if granted == nil || len(granted) != 0 {
		t.Fatalf("a refused grant = %#v, want an empty non-nil list", granted)
	}
	if raw, err := json.Marshal(granted); err != nil || string(raw) != "[]" {
		t.Errorf("a refused grant is stored as %s (err %v), want []", raw, err)
	}

	if got := h.getScopesForGroups([]string{"ap2001-login"}, requested); len(got) != 2 {
		t.Errorf("a member of the access group was granted %v, want %v", got, requested)
	}
}

// The consent narrowing seeded openid too. Fixing only one of the two
// leaves the other putting it back.
func TestConsentDoesNotReinstateUnrequestedOpenID(t *testing.T) {
	form := url.Values{}
	form.Set("consent_form_version", "1")
	form.Add("scope", "condor:/WRITE")

	accepted := narrowConsentScopes([]string{"condor:/WRITE", "offline_access"}, form)
	for _, scope := range accepted {
		if scope == "openid" {
			t.Fatalf("openid came back through the consent form; accepted = %v", accepted)
		}
	}

	// A client that asked for it keeps it without needing a checkbox:
	// the page renders it as a fixed entry rather than one.
	accepted = narrowConsentScopes([]string{"openid", "condor:/WRITE"}, form)
	found := false
	for _, scope := range accepted {
		if scope == "openid" {
			found = true
		}
	}
	if !found {
		t.Errorf("openid was requested and dropped; accepted = %v", accepted)
	}
}
