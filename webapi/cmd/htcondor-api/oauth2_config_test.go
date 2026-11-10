package main

import (
	"fmt"
	"testing"
)

// The OAuth2 settings are read whenever the web UI or MCP is served; the
// MCP settings only with MCP.
//
// They used to be read only with HTTP_API_ENABLE_MCP, so a web UI with
// MCP off ignored its issuer, identity provider, access groups and
// identity mapping without a word -- and the handler could not tell,
// because what it was handed was simply empty.
func TestOAuth2SettingsAreReadWithTheWebUIOrMCP(t *testing.T) {
	for _, webUI := range []bool{false, true} {
		for _, mcp := range []bool{false, true} {
			t.Run(fmt.Sprintf("webui=%v/mcp=%v", webUI, mcp), func(t *testing.T) {
				cfg := cfgWith(t, map[string]string{ //nolint:gosec // G101: test endpoint URLs, no credentials
					"HTTP_API_ENABLE_MCP":       fmt.Sprint(mcp),
					"HTTP_API_OAUTH2_ISSUER":    "https://ap.example.edu",
					"HTTP_API_OAUTH2_CLIENT_ID": "upstream-client",
					"HTTP_API_OAUTH2_AUTH_URL":  "https://idp.example.edu/authorize",
					"HTTP_API_OAUTH2_TOKEN_URL": "https://idp.example.edu/token",
					"HTTP_API_MCP_ACCESS_GROUP": "chtc_staff",
					"HTTP_API_IDENTITY_MAP":     "username",
					"MCP_INSTRUCTIONS":          "be nice",
				})
				got := loadMCPConfig(cfg, ":8080", webUI, testLogger(t))
				oauth := webUI || mcp

				if got.enabled != mcp {
					t.Errorf("enabled = %v, want %v", got.enabled, mcp)
				}
				for name, read := range map[string]bool{
					"issuer":       got.oauth2Issuer == "https://ap.example.edu",
					"client id":    got.oauth2ClientID == "upstream-client",
					"auth url":     got.oauth2AuthURL == "https://idp.example.edu/authorize",
					"access group": got.mcpAccessGroup == "chtc_staff",
					"identity map": len(got.identityMapStrategies) == 1,
				} {
					if read != oauth {
						t.Errorf("%s read = %v, want %v", name, read, oauth)
					}
				}
				if read := got.instructions == "be nice"; read != mcp {
					t.Errorf("MCP instructions read = %v, want %v", read, mcp)
				}

				if !oauth {
					return
				}
				want := "https://ap.example.edu/oauth2/callback"
				if mcp && !webUI {
					want = "https://ap.example.edu/mcp/oauth2/callback"
				}
				if got.oauth2RedirectURL != want {
					t.Errorf("redirect URL = %q, want %q", got.oauth2RedirectURL, want)
				}
			})
		}
	}
}
