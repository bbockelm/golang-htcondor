package main

import (
	"reflect"
	"testing"
)

// HTTP_API_ENABLE_MCP is a boolean, and HTCondor configuration is
// conventionally written `= True`. That spelling used to mean off, which
// -- MCP being one of the two surfaces that turn OAuth2 on -- also meant
// a configured identity provider was never read.
func TestMCPEnabledReadsEverySpellingOfTrue(t *testing.T) {
	for value, want := range map[string]bool{
		"true": true, "True": true, "TRUE": true, "1": true, "t": true,
		"false": false, "False": false, "0": false, "": false,
	} {
		knobs := map[string]string{}
		if value != "" {
			knobs["HTTP_API_ENABLE_MCP"] = value
		}
		if got := mcpEnabled(cfgWith(t, knobs)); got != want {
			t.Errorf("HTTP_API_ENABLE_MCP=%q: enabled = %v, want %v", value, got, want)
		}
	}
	if mcpEnabled(cfgWith(t, nil)) {
		t.Error("unset HTTP_API_ENABLE_MCP should leave MCP off")
	}
}

func TestOAuth2SettingsAreReadWithCapitalizedEnableMCP(t *testing.T) {
	cfg := cfgWith(t, map[string]string{
		"HTTP_API_ENABLE_MCP":       "True",
		"HTTP_API_OAUTH2_CLIENT_ID": "upstream-client",
	})
	got := loadMCPConfig(cfg, ":8080", false, testLogger(t))
	if !got.enabled {
		t.Error("MCP not enabled by HTTP_API_ENABLE_MCP = True")
	}
	if got.oauth2ClientID != "upstream-client" {
		t.Errorf("client id = %q, want it read", got.oauth2ClientID)
	}
}

// A server that serves neither the web UI nor MCP reads no OAuth2
// settings, so a configured provider goes nowhere. The names it ignored
// are what the startup warning reports.
func TestConfiguredOAuth2Settings(t *testing.T) {
	cfg := cfgWith(t, map[string]string{
		"HTTP_API_OAUTH2_IDP":            "https://cilogon.org",
		"HTTP_API_OAUTH2_CLIENT_ID":      "cilogon:/client_id/abc",
		"HTTP_API_OAUTH2_USERNAME_CLAIM": "eppn", // not one of the names that mean "meant to log people in"
		"HTTP_API_OAUTH2_AUTH_URL":       "   ",  // blank counts as unset
	})
	want := []string{"HTTP_API_OAUTH2_IDP", "HTTP_API_OAUTH2_CLIENT_ID"}
	if got := configuredOAuth2Settings(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("configuredOAuth2Settings = %v, want %v", got, want)
	}
	if got := configuredOAuth2Settings(cfgWith(t, nil)); len(got) != 0 {
		t.Errorf("no OAuth2 settings: got %v, want none", got)
	}
}
