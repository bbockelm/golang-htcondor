package httpserver

import (
	"net/url"
	"sort"
	"testing"

	"github.com/ory/fosite"
)

// deviceRequestLike builds a requester shaped like a stored device-code
// session: the scopes the client asked for, and the granted set as the device
// flow actually leaves it.
func deviceRequestLike(requested, granted []string) fosite.Requester {
	r := fosite.NewRequest()
	r.RequestedScope = requested
	r.GrantedScope = granted
	return r
}

// TestDeviceApprovalKeepsTheScopesTheUserAccepted reproduces the reported
// failure: a device login completes, and the token carries only "openid", so
// every MCP method is refused.
//
//	WARN [http] MCP method not allowed by scopes method=server/discover scopes=[openid]
//
// The consent page renders a checkbox per requested scope and the browser
// submits them, so the form carries the full set. Nothing in the device flow
// ever calls GrantScope, so the stored session's granted set is empty -- and
// the device-only narrowing intersected with exactly that, so it could only
// ever yield "openid". It now narrows what was REQUESTED by what the user
// ticked, like the authorization-code path, with group policy applied after.
func TestDeviceApprovalKeepsTheScopesTheUserAccepted(t *testing.T) {
	requested := []string{"openid", "profile", "email", "offline_access", "mcp:read", "mcp:write"}

	form := url.Values{}
	form.Set("consent_form_version", "1")
	for _, s := range requested {
		form.Add("scope", s)
	}

	// The device-code session as stored: requested scopes recorded, granted
	// scopes empty because the device flow never grants any.
	request := deviceRequestLike(requested, nil)
	_ = request

	// What the approve branch now computes.
	got := narrowConsentScopes(request.GetRequestedScopes(), form, "consent_form_version")
	sort.Strings(got)

	want := append([]string(nil), requested...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("approved scopes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("approved scopes = %v, want %v", got, want)
		}
	}
}
