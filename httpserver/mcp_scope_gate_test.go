package httpserver

import (
	"encoding/json"
	"testing"

	"github.com/bbockelm/golang-htcondor/mcpserver"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// TestIsMethodAllowedByScopes pins the OAuth2 scope gate that decides
// whether a request's MCP method is permitted: mcp:write allows
// everything, mcp:read allows read-only methods/tools only, and the
// absence of either scope denies everything. "Read-only tool" is keyed
// off mcpserver.IsReadOnlyTool, so query_jobs is allowed under read but
// submit_job is not.
func TestIsMethodAllowedByScopes(t *testing.T) {
	h := &Handler{}

	toolsCall := func(tool string) *mcpserver.MCPMessage {
		return &mcpserver.MCPMessage{
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"` + tool + `"}`),
		}
	}
	method := func(m string) *mcpserver.MCPMessage {
		return &mcpserver.MCPMessage{Method: m}
	}

	tests := []struct {
		name   string
		scopes []string
		msg    *mcpserver.MCPMessage
		want   bool
	}{
		{"read allows tools/list", []string{"mcp:read"}, method("tools/list"), true},
		{"read allows a read-only tool", []string{"mcp:read"}, toolsCall("query_jobs"), true},
		{"read denies a write tool", []string{"mcp:read"}, toolsCall("submit_job"), false},
		{"write allows a write tool", []string{"mcp:write"}, toolsCall("submit_job"), true},
		{"write allows a read tool", []string{"mcp:write"}, toolsCall("query_jobs"), true},
		{"no scopes denies a read-only method", nil, method("tools/list"), false},
		{"no scopes denies a read-only tool", nil, toolsCall("query_jobs"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ar := fosite.NewAccessRequest(&openid.DefaultSession{})
			for _, s := range tt.scopes {
				ar.GrantScope(s)
			}
			if got := h.isMethodAllowedByScopes(ar, tt.msg); got != tt.want {
				t.Errorf("isMethodAllowedByScopes(scopes=%v, method=%q) = %v, want %v",
					tt.scopes, tt.msg.Method, got, tt.want)
			}
		})
	}
}
