package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// verifierByBearer reports a different grant per bearer, so one handler --
// and one server cache -- serves callers with different grants.
func verifierByBearer(infos map[string]func() *auth.TokenInfo) auth.TokenVerifier {
	return func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		mk, ok := infos[token]
		if !ok {
			return nil, auth.ErrInvalidToken
		}
		info := mk()
		info.Expiration = time.Now().Add(time.Hour)
		return info, nil
	}
}

func sdkPostAs(t *testing.T, ts *httptest.Server, bearer string, payload map[string]interface{}) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), "POST", ts.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

var (
	sdkToolsList = map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
)

func sdkCall(name string) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{"name": name, "arguments": map[string]interface{}{}},
	}
}

// listedTools returns the names a tools/list response carries.
func listedTools(t *testing.T, raw string) []string {
	t.Helper()
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("decoding tools/list %q: %v", raw, err)
	}
	var names []string
	for _, tool := range resp.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// A token stating a scope set that is nil or empty is scoped and granted
// nothing: it sees no tools and can call none. Nil used to mean "no scope
// model" and was served the whole catalogue.
func TestSDKTokenGrantedNothingSeesNothing(t *testing.T) {
	s := sdkTestServer(t)
	for name, scopes := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(s.SDKHTTPHandler(verifierFor(scopes)))
			defer ts.Close()

			if got := listedTools(t, sdkPost(t, ts, sdkToolsList)); len(got) != 0 {
				t.Errorf("a token granted nothing was shown %v", got)
			}
			for _, tool := range []string{"submit_job", "query_jobs"} {
				called := sdkPost(t, ts, sdkCall(tool))
				if !strings.Contains(strings.ToLower(called), "unknown tool") {
					t.Errorf("%s was not refused for a token granted nothing:\n%s", tool, called)
				}
			}
		})
	}
}

// An unscoped caller (a forwarded HTCondor token) sees everything and a
// token granted nothing sees nothing. Both carry no scopes, so a cache keyed
// on the scopes alone handed whichever arrived second the first one's server.
// Both orders, on one handler.
func TestSDKUnscopedAndEmptyGrantDoNotShareAServer(t *testing.T) {
	for _, emptyFirst := range []bool{true, false} {
		for name, scopes := range map[string][]string{"nil": nil, "empty": {}} {
			order := "unscoped first"
			if emptyFirst {
				order = "granted-nothing first"
			}
			t.Run(order+"/"+name, func(t *testing.T) {
				s := sdkTestServer(t)
				ts := httptest.NewServer(s.SDKHTTPHandler(verifierByBearer(map[string]func() *auth.TokenInfo{
					"unscoped": UnscopedTokenInfo,
					"nothing":  func() *auth.TokenInfo { return &auth.TokenInfo{Scopes: scopes} },
				})))
				defer ts.Close()

				checkNothing := func() {
					if got := listedTools(t, sdkPostAs(t, ts, "nothing", sdkToolsList)); len(got) != 0 {
						t.Errorf("a token granted nothing was shown %v", got)
					}
				}
				checkUnscoped := func() {
					got := strings.Join(listedTools(t, sdkPostAs(t, ts, "unscoped", sdkToolsList)), " ")
					if !strings.Contains(got, "submit_job") || !strings.Contains(got, "query_jobs") {
						t.Errorf("an unscoped caller was not shown the whole catalogue: %s", got)
					}
				}
				if emptyFirst {
					checkNothing()
					checkUnscoped()
				} else {
					checkUnscoped()
					checkNothing()
				}
			})
		}
	}
}

// handleCallTool applies the catalogue's scope rule itself, so a call cannot
// reach a tool the caller's grant would not list -- whichever transport
// carried it, and whatever server it was dispatched on.
func TestHandleCallToolRechecksTheGrant(t *testing.T) {
	s := sdkTestServer(t)
	call := func(ctx context.Context, name string) error {
		params, err := json.Marshal(map[string]interface{}{"name": name, "arguments": map[string]interface{}{}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.handleCallTool(ctx, params)
		return err
	}
	refusedByScope := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "not permitted by the scopes")
	}

	readOnly := WithGrantedScopes(context.Background(), []string{"mcp:read"})
	if err := call(readOnly, "submit_job"); !refusedByScope(err) {
		t.Errorf("a read-only grant reached submit_job: %v", err)
	}
	if err := call(readOnly, "get_version"); err != nil {
		t.Errorf("a read-only grant was refused a read tool: %v", err)
	}

	nothing := WithGrantedScopes(context.Background(), nil)
	if err := call(nothing, "query_jobs"); !refusedByScope(err) {
		t.Errorf("a grant of nothing reached query_jobs: %v", err)
	}
	if err := call(nothing, "get_version"); !refusedByScope(err) {
		t.Errorf("a grant of nothing reached get_version: %v", err)
	}

	// No grant at all is stdio, which is not scope-limited.
	if err := call(context.Background(), "get_version"); err != nil {
		t.Errorf("an unscoped caller was refused: %v", err)
	}
}

// The tools run under the grant the catalogue was built from, so their own
// scope checks -- the owner-scope tiers among them -- read the same answer.
// whoami reports the grant it ran under.
func TestSDKToolsRunUnderTheVerifiedGrant(t *testing.T) {
	s := sdkTestServer(t)
	ts := httptest.NewServer(s.SDKHTTPHandler(verifierFor([]string{"mcp:read"})))
	defer ts.Close()

	got := sdkPost(t, ts, sdkCall("whoami"))
	if !strings.Contains(got, `oauth_scopes`) || !strings.Contains(got, `mcp:read`) {
		t.Errorf("whoami did not run under the caller's grant:\n%s", got)
	}
}
