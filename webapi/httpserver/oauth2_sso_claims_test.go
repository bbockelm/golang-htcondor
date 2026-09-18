// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"reflect"
	"strings"
	"testing"
)

func newClaimTestHandler(t *testing.T, cfg HandlerConfig) *Handler {
	t.Helper()
	cfg.Logger = testLogger(t)
	if cfg.ScheddName == "" {
		cfg.ScheddName = "test-schedd"
		cfg.ScheddAddr = "127.0.0.1:9618"
	}
	cfg.OAuth2DBPath = t.TempDir() + "/sessions.db"
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// The regression test for a real failure: every SSO login was refused
// with "missing subject claim" on a deployment with MCP disabled.
//
// The claim names were assigned inside "if cfg.EnableMCP", but they are
// read on the shared SSO callback path, which runs whenever the internal
// IDP is configured -- and Start() configures that regardless of MCP. So
// the lookup was claims[""], which no token can satisfy, and the message
// blamed the IDP for omitting a claim it had actually sent.
func TestClaimNamesAreSetWithoutMCP(t *testing.T) {
	h := newClaimTestHandler(t, HandlerConfig{EnableMCP: false})

	if h.oauth2UsernameClaim != "sub" {
		t.Errorf("oauth2UsernameClaim = %q, want \"sub\"; an empty name makes every login fail", h.oauth2UsernameClaim)
	}
	if h.oauth2GroupsClaim != "groups" {
		t.Errorf("oauth2GroupsClaim = %q, want \"groups\"", h.oauth2GroupsClaim)
	}
}

// And the configured value must reach the handler on that same path --
// otherwise setting the knob to work around the bug above did nothing.
func TestConfiguredClaimNameAppliesWithoutMCP(t *testing.T) {
	h := newClaimTestHandler(t, HandlerConfig{
		EnableMCP:           false,
		OAuth2UsernameClaim: "eppn",
		OAuth2GroupsClaim:   "isMemberOf",
	})

	if h.oauth2UsernameClaim != "eppn" {
		t.Errorf("oauth2UsernameClaim = %q, want eppn", h.oauth2UsernameClaim)
	}
	if h.oauth2GroupsClaim != "isMemberOf" {
		t.Errorf("oauth2GroupsClaim = %q, want isMemberOf", h.oauth2GroupsClaim)
	}
}

func TestClaimNamesStillSetWithMCP(t *testing.T) {
	h := newClaimTestHandler(t, HandlerConfig{EnableMCP: true, OAuth2UsernameClaim: "eppn"})
	if h.oauth2UsernameClaim != "eppn" {
		t.Errorf("oauth2UsernameClaim = %q, want eppn", h.oauth2UsernameClaim)
	}
}

// The allow-list answers "which campus", which the issuer cannot: a
// federation like CILogon fronts many institutions behind one issuer.
func TestValidateIdentityProvider(t *testing.T) {
	const wisc = "https://login.wisc.edu/idp/shibboleth"

	cases := []struct {
		name    string
		allowed []string
		claims  map[string]any
		wantErr bool
	}{
		{"unconfigured accepts any provider", nil,
			map[string]any{"idp": "https://elsewhere.example/idp"}, false},
		{"listed provider is accepted", []string{wisc},
			map[string]any{"idp": wisc}, false},
		{"unlisted provider is refused", []string{wisc},
			map[string]any{"idp": "https://elsewhere.example/idp"}, true},
		// Fails closed: "cannot tell which provider this came from" is not
		// a reason to trust it.
		{"missing claim is refused once configured", []string{wisc},
			map[string]any{"sub": "someone"}, true},
		{"non-string claim is refused", []string{wisc},
			map[string]any{"idp": 42}, true},
		{"one of several listed providers", []string{"https://a.example", wisc},
			map[string]any{"idp": wisc}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{oauth2IDPClaim: "idp", oauth2AllowedIDPs: tc.allowed}
			err := h.validateIdentityProvider(tc.claims)
			if tc.wantErr && err == nil {
				t.Fatal("expected the login to be refused")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

func TestValidateIdentityProviderUsesTheConfiguredClaim(t *testing.T) {
	h := &Handler{oauth2IDPClaim: "identity_provider", oauth2AllowedIDPs: []string{"campus"}}
	if err := h.validateIdentityProvider(map[string]any{"identity_provider": "campus"}); err != nil {
		t.Errorf("configured claim not consulted: %v", err)
	}
	// The default name must not be consulted when another was configured.
	if err := h.validateIdentityProvider(map[string]any{"idp": "campus"}); err == nil {
		t.Error("read the default claim name instead of the configured one")
	}
}

// The failure path names what was looked for and what arrived, because
// without it the message is identical whether the claim is misconfigured,
// misspelled, or genuinely absent.
func TestClaimNamesListsKeysNotValues(t *testing.T) {
	got := claimNames(map[string]any{
		"sub":  "http://cilogon.org/serverA/users/9265706",
		"eppn": "bockelman@wisc.edu",
		"idp":  "https://login.wisc.edu/idp/shibboleth",
	})
	want := []string{"eppn", "idp", "sub"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("claimNames = %v, want %v (sorted)", got, want)
	}
	// Values identify the person and must not be logged on a path an
	// unauthenticated caller can reach repeatedly.
	for _, n := range got {
		if strings.Contains(n, "@") || strings.Contains(n, "cilogon.org") {
			t.Errorf("claim VALUE leaked into the key list: %q", n)
		}
	}
}
