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
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/idmap"
)

const wiscIDP = "https://login.wisc.edu/idp/shibboleth"

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

// realClaims is the userinfo payload from the login that prompted this,
// so the policy tests run against what an IDP actually sends.
func realClaims() map[string]any {
	return map[string]any{
		"idp":         wiscIDP,
		"eppn":        "bockelman@wisc.edu",
		"affiliation": "AFFILIATE@wisc.edu;EMPLOYEE@wisc.edu;MEMBER@wisc.edu",
		"acr":         "https://refeds.org/profile/mfa",
		"sub":         "http://cilogon.org/serverA/users/9265706",
		"eduPersonAssurance": []any{
			"https://refeds.org/assurance/IAP/low",
			"https://refeds.org/assurance/ATP/ePA-1m",
		},
	}
}

// The policy answers questions a provider list cannot: this IDP AND this
// affiliation AND this assurance level.
func TestLoginRequirements(t *testing.T) {
	cases := []struct {
		name         string
		requirements string
		wantAllowed  bool
	}{
		{"no policy accepts any login", "", true},
		{"matching provider", `idp == "` + wiscIDP + `"`, true},
		{"different provider", `idp == "https://elsewhere.example/idp"`, false},
		{"provider and affiliation", `idp == "` + wiscIDP + `" && regexp("MEMBER@wisc.edu", affiliation)`, true},
		{"affiliation absent", `regexp("STUDENT@wisc.edu", affiliation)`, false},
		{"list membership", `member("https://refeds.org/assurance/IAP/low", eduPersonAssurance)`, true},
		{"MFA required and present", `acr == "https://refeds.org/profile/mfa"`, true},

		// Fails closed: a policy naming a claim the IDP stopped sending
		// evaluates to UNDEFINED, and must refuse rather than silently
		// admit everybody the moment it stopped meaning anything.
		{"claim the IDP does not send", `department == "physics"`, false},
		{"misspelled claim name", `idpp == "x"`, false},

		// A non-boolean result is not a pass.
		{"non-boolean result", `eppn`, false},
		{"explicitly false", `false`, false},
		{"explicitly true", `true`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{}
			if tc.requirements != "" {
				expr, err := classad.ParseExpr(tc.requirements)
				if err != nil {
					t.Fatalf("ParseExpr(%q): %v", tc.requirements, err)
				}
				h.oauth2Requirements = expr
				h.oauth2RequirementsText = tc.requirements
			}
			err := h.evaluateLoginRequirements(realClaims())
			if tc.wantAllowed && err != nil {
				t.Fatalf("login refused: %v", err)
			}
			if !tc.wantAllowed && err == nil {
				t.Fatal("login allowed; the requirements should have refused it")
			}
		})
	}
}

// A malformed policy must stop the daemon at startup, not at the first
// person's login.
func TestMalformedRequirementsRefuseToStart(t *testing.T) {
	_, err := NewHandler(HandlerConfig{
		ScheddName:         "test-schedd",
		ScheddAddr:         "127.0.0.1:9618",
		Logger:             testLogger(t),
		OAuth2DBPath:       t.TempDir() + "/sessions.db",
		OAuth2Requirements: `idp == `,
	})
	if err == nil {
		t.Fatal("a malformed requirements expression was accepted")
	}
	if !strings.Contains(err.Error(), "HTTP_API_OAUTH2_REQUIREMENTS") {
		t.Errorf("error should name the setting: %v", err)
	}
}

// The refusal must not echo the claim values back to the caller: they
// identify the person, and this path is reachable unauthenticated.
func TestRefusalDoesNotLeakClaimValues(t *testing.T) {
	expr, err := classad.ParseExpr(`idp == "https://elsewhere.example/idp"`)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{oauth2Requirements: expr}

	err = h.evaluateLoginRequirements(realClaims())
	if err == nil {
		t.Fatal("expected refusal")
	}
	for _, secret := range []string{"bockelman@wisc.edu", "cilogon.org/serverA", "AFFILIATE@wisc.edu"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("refusal message leaked a claim value (%q): %s", secret, err)
		}
	}
}

// Claims become a ClassAd faithfully enough for a policy to be written
// against them: lists stay lists, nested objects stay addressable.
func TestClaimsToClassAd(t *testing.T) {
	ad := claimsToClassAd(map[string]any{
		"idp":    wiscIDP,
		"list":   []any{"a", "b"},
		"nested": map[string]any{"inner": "value"},
		"null":   nil,
		"number": float64(1789697789),
	})

	for _, e := range []string{
		`idp == "` + wiscIDP + `"`,
		`member("b", list)`,
		`nested.inner == "value"`,
		`null =?= UNDEFINED`,
		`number > 0`,
	} {
		expr, err := classad.ParseExpr(e)
		if err != nil {
			t.Fatalf("ParseExpr(%q): %v", e, err)
		}
		got, err := expr.Eval(ad).BoolValue()
		if err != nil || !got {
			t.Errorf("%s => %v (err %v); the claim did not survive conversion", e, got, err)
		}
	}
}

// The failure path names what was looked for and what arrived, because
// without it the message is identical whether the claim is misconfigured,
// misspelled, or genuinely absent.
func TestClaimNamesListsKeysNotValues(t *testing.T) {
	got := claimNames(map[string]any{
		"sub":  "http://cilogon.org/serverA/users/9265706",
		"eppn": "bockelman@wisc.edu",
		"idp":  wiscIDP,
	})
	want := []string{"eppn", "idp", "sub"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("claimNames = %v, want %v (sorted)", got, want)
	}
	for _, n := range got {
		if strings.Contains(n, "@") || strings.Contains(n, "cilogon.org") {
			t.Errorf("claim VALUE leaked into the key list: %q", n)
		}
	}
}

// The startup log must say WHICH chain groups come from, not merely that
// they come from the system.
//
// The chain is chosen per build: with cgo it is getgrouplist(3), which
// consults every service in nsswitch.conf; without cgo -- how the release
// binaries and container are built -- it is files plus sss, with anything
// else marked degraded. An operator whose directory groups are missing
// needs that distinction in the log, not just "groups_from=system".
func TestGroupSourceIsNamedForTheOperator(t *testing.T) {
	passwd := writePasswd(t)

	li := newLocalIdentity(nil, []string{"system"}, passwd, time.Minute, false, testLogger(t))
	if li == nil {
		t.Fatal("expected a localIdentity when groups come from the system")
	}
	name := li.groupSourceName()
	if name == "" {
		t.Fatal("group source is unnamed; the startup log would not say where membership is read from")
	}
	// It should name a real lookup, not a placeholder.
	if !strings.Contains(name, "stdlib") && !strings.Contains(name, "chain") {
		t.Errorf("group source = %q, want it to name the underlying lookup", name)
	}
	t.Logf("group source on this build: %s", name)

	// With token-sourced groups there is nothing local to name.
	tokenOnly := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, nil, passwd, time.Minute, false, testLogger(t))
	if got := tokenOnly.groupSourceName(); got != "" {
		t.Errorf("group source = %q, want empty when groups come from the token", got)
	}
}
