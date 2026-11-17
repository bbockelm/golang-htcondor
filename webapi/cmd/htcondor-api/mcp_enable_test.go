package main

import (
	"reflect"
	"strings"
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

// HTTP_API_MCP_OAUTH2 = false: MCP is served, but its callers forward an
// HTCondor token rather than logging in here. The OAuth2 settings are
// then read by nothing, exactly as on a server that serves neither
// surface.
func TestMCPOAuth2CanBeWithdrawn(t *testing.T) {
	knobs := map[string]string{
		"HTTP_API_ENABLE_MCP":       "true",
		"HTTP_API_OAUTH2_CLIENT_ID": "upstream-client",
	}
	// Unset: served, as every deployment did before the setting existed.
	if got := loadMCPConfig(cfgWith(t, knobs), ":8080", false, testLogger(t)); got.oauth2Disabled {
		t.Error("unset HTTP_API_MCP_OAUTH2 withdrew OAuth2 from MCP")
	} else if got.oauth2ClientID != "upstream-client" {
		t.Error("the OAuth2 settings were not read on a server that serves OAuth2")
	}

	knobs["HTTP_API_MCP_OAUTH2"] = "false"
	got := loadMCPConfig(cfgWith(t, knobs), ":8080", false, testLogger(t))
	if !got.enabled {
		t.Fatal("withdrawing OAuth2 also turned MCP off; the endpoint this is for would be gone")
	}
	if !got.oauth2Disabled {
		t.Fatal("HTTP_API_MCP_OAUTH2 = false did not withdraw OAuth2")
	}
	if got.oauth2ClientID != "" {
		t.Errorf("client id = %q: the OAuth2 settings were read for a surface that serves none", got.oauth2ClientID)
	}
	// The MCP settings proper are still read -- only OAuth2 was withdrawn.
	if got.oauth2DBPath == "" {
		t.Error("the unified DB path was not resolved")
	}
}

// With a web UI, withdrawing OAuth2 from MCP leaves the UI's own login
// alone: its settings are still read, and the redirect URI it registers
// is the plain spelling rather than the /mcp/ one.
func TestMCPOAuth2WithdrawnKeepsTheWebUILogin(t *testing.T) {
	got := loadMCPConfig(cfgWith(t, map[string]string{
		"HTTP_API_ENABLE_MCP":       "true",
		"HTTP_API_MCP_OAUTH2":       "false",
		"HTTP_API_OAUTH2_CLIENT_ID": "upstream-client",
	}), ":8080", true, testLogger(t))
	if got.oauth2ClientID != "upstream-client" {
		t.Error("the web UI lost its OAuth2 settings because MCP withdrew OAuth2")
	}
	if strings.Contains(got.oauth2RedirectURL, "/mcp/") {
		t.Errorf("redirect URI %q names a spelling this server no longer routes", got.oauth2RedirectURL)
	}
}

// An MCP-only server that leaves the setting alone still advertises the
// /mcp/ spelling, which is what such a server has always done.
func TestMCPOnlyServerKeepsTheMCPSpelling(t *testing.T) {
	got := loadMCPConfig(cfgWith(t, map[string]string{
		"HTTP_API_ENABLE_MCP":       "true",
		"HTTP_API_OAUTH2_CLIENT_ID": "upstream-client",
	}), ":8080", false, testLogger(t))
	if !strings.Contains(got.oauth2RedirectURL, "/mcp/oauth2/callback") {
		t.Errorf("redirect URI %q: an MCP-only server should keep the /mcp/ spelling", got.oauth2RedirectURL)
	}
}
