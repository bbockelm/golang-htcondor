package httpserver

import (
	"context"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// The bug this exists for, in one sentence: a CIMD client has no stored
// scope list, so narrowing the advertised set retroactively narrowed what
// every existing grant was allowed to ask for, and refreshing one failed
// with "the OAuth 2.0 Client is not allowed to request scope
// condor:/ADVERTISE_MASTER". Every already-authorized client died at once
// and could only be revived by a human re-authorizing it.
func TestDeprecatedScopesStayRequestable(t *testing.T) {
	for _, scope := range oauth2DeprecatedScopes {
		if slices.Contains(oauth2AdvertisedScopes, scope) {
			t.Errorf("%s is both advertised and deprecated; it should be one or the other", scope)
		}
		// A client whose document declares nothing gets the whole set.
		if got := cimdClientScopes(""); !slices.Contains(got, scope) {
			t.Errorf("a CIMD client that declares no scopes may not request %s; its existing grants cannot refresh", scope)
		}
		// A client whose document names it keeps it.
		if got := cimdClientScopes("openid mcp:read " + scope); !slices.Contains(got, scope) {
			t.Errorf("a CIMD client that declares %s may not request it; its existing grants cannot refresh", scope)
		}
	}
}

// Requestable is not the same as granted. Keeping these alive must not
// quietly restore the authorization they used to look like they carried.
func TestDeprecatedScopesGrantNothing(t *testing.T) {
	if authz := mapCondorScopesToAuthz(oauth2DeprecatedScopes); len(authz) != 0 {
		t.Errorf("deprecated scopes mapped to %v; they must authorize nothing", authz)
	}
	// Still nothing extra when they ride along with a real one.
	withReal := append([]string{"condor:/READ"}, oauth2DeprecatedScopes...)
	authz := mapCondorScopesToAuthz(withReal)
	if len(authz) != 1 || authz[0] != "READ" {
		t.Errorf("condor:/READ plus the deprecated scopes authorized %v, want [READ]", authz)
	}
}

// And they must not come back as consent-page clutter -- the reason they
// were dropped in the first place. Dropping them here is also how a grant
// sheds one: the next authorization simply does not carry it.
func TestConsentPageDoesNotOfferDeprecatedScopes(t *testing.T) {
	if len(oauth2DeprecatedScopes) == 0 {
		t.Skip("nothing deprecated")
	}
	h := aclTestHandler(t)
	rec := httptest.NewRecorder()

	requested := append([]string{"openid", "mcp:read"}, oauth2DeprecatedScopes...)
	h.renderConsentPage(context.Background(), rec, nil, consentPageParams{
		Title:           "Authorize Application",
		Username:        "alice",
		ClientID:        "c",
		RequestedScopes: requested,
		FormAction:      "/mcp/oauth2/consent",
	})

	body := rec.Body.String()
	for _, scope := range oauth2DeprecatedScopes {
		if strings.Contains(body, `value="`+scope+`"`) {
			t.Errorf("the consent page offered %s, which grants nothing", scope)
		}
	}
	if !strings.Contains(body, `value="mcp:read"`) {
		t.Error("the page dropped mcp:read along with them")
	}
}

// The discovery documents advertise only what a new client should ask
// for, and both render oauth2AdvertisedScopes verbatim, so the list is
// the thing to hold: a deprecated scope back in it would be handed to
// clients that never had it.
func TestDeprecatedScopesAreNotAdvertised(t *testing.T) {
	for _, scope := range oauth2DeprecatedScopes {
		if slices.Contains(oauth2AdvertisedScopes, scope) {
			t.Errorf("%s is advertised again; new clients would be offered a scope that grants nothing", scope)
		}
	}
}
