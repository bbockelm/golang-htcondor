package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
)

// The chat's job scope: the page asks for mine or everyone, the server
// resolves it with the page's own checks, and every job tool reads only
// the resolution. These run the tools the way handleChat does, against
// the two-owner fake schedd plus a job and a history record of root's
// (root is the Web UI administrator).

// scopeFixture is twoOwnerScheddServer plus root's own job 3.0 and
// history record 13.0, so an administrator's "mine" has something in it.
func scopeFixture(t *testing.T) *twoOwnerFixture {
	t.Helper()
	f := twoOwnerScheddServer(t)
	f.schedd.AddJobs(fakeschedd.JobAd(3, 0, "root", 1))
	f.schedd.AddHistory(fakeschedd.JobAd(13, 0, "root", 4))
	return f
}

// The callers. root's session is in the Web UI admin group (both tiers);
// carol's bearer carries mcp:admin (the read tier only); alice is nobody
// in particular.
func (f *twoOwnerFixture) admin(t *testing.T) func(*http.Request) {
	return f.session(t, "root", "condor-admins")
}

// chatToolCtx is the context handleChat runs tools under for the caller
// auth adds, on page, asking for scope: authenticated, carrying the
// request, and carrying the scope resolveChatScope settled.
func chatToolCtx(t *testing.T, f *twoOwnerFixture, auth func(*http.Request), page, scope string) (context.Context, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/chat", nil)
	auth(req)
	authCtx, _, err := f.s.requireAuthentication(req)
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	actor := htcondor.GetAuthenticatedUserFromContext(authCtx)
	toolCtx := context.WithValue(authCtx, chatRequestKey{}, req)
	return chat.WithScope(toolCtx, f.s.resolveChatScope(toolCtx, req, page, scope)), actor
}

func findChatTool(t *testing.T, f *twoOwnerFixture, name string) chat.Tool {
	t.Helper()
	for _, tool := range f.s.buildChatTools() {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("the chat offers no %s", name)
	return nil
}

// runChatTool runs one tool as handleChat would.
func runChatTool(t *testing.T, f *twoOwnerFixture, auth func(*http.Request), page, scope, name, args string) (string, error) {
	t.Helper()
	ctx, actor := chatToolCtx(t, f, auth, page, scope)
	return findChatTool(t, f, name).Execute(ctx, actor, json.RawMessage(args))
}

// describeChatTool is the approval-card detail the engine would show.
func describeChatTool(t *testing.T, f *twoOwnerFixture, auth func(*http.Request), page, scope, name, args string) map[string]any {
	t.Helper()
	ctx, actor := chatToolCtx(t, f, auth, page, scope)
	d, ok := findChatTool(t, f, name).(chat.ConfirmationDescriber)
	if !ok {
		t.Fatalf("%s describes no confirmation", name)
	}
	return d.DescribeConfirmation(ctx, actor, json.RawMessage(args))
}

// listedOwners runs a listing tool and returns the owners of the jobs it
// listed, sorted, and the scope it says it used.
func listedOwners(t *testing.T, f *twoOwnerFixture, auth func(*http.Request), page, scope, name string) ([]string, string) {
	t.Helper()
	out, err := runChatTool(t, f, auth, page, scope, name, `{}`)
	if err != nil {
		t.Fatalf("%s on %s (scope %q): %v", name, page, scope, err)
	}
	var resp struct {
		Jobs  []map[string]any `json:"jobs"`
		Scope string           `json:"scope"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("%s returned %s: %v", name, out, err)
	}
	var owners []string
	for _, j := range resp.Jobs {
		owner, _ := j["owner"].(string)
		owners = append(owners, owner)
	}
	slices.Sort(owners)
	return owners, resp.Scope
}

// The reading tools on the listing pages: an administrator in the
// everyone view reads every user's jobs; in the mine view, or with any
// scope string other than "everyone", their own; and a non-administrator
// sending "everyone" gets their own exactly as if they had not.
func TestChatListingToolsFollowResolvedScope(t *testing.T) {
	f := scopeFixture(t)
	alice := f.session(t, "alice")

	for _, tc := range []struct{ tool, page string }{
		{"query_jobs", "jobs"},
		{"query_jobs_archive", "archive"},
		{"query_jobs_archive", "archive-detail"},
	} {
		t.Run(tc.tool+"/"+tc.page, func(t *testing.T) {
			got, scope := listedOwners(t, f, f.admin(t), tc.page, "everyone", tc.tool)
			if !slices.Equal(got, []string{"alice", "bob", "root"}) {
				t.Errorf("admin, everyone: owners %v, want every user's", got)
			}
			if scope != "every user's jobs" {
				t.Errorf("admin, everyone: scope %q", scope)
			}

			for _, s := range []string{"mine", "", "all", "Everyone", "everyone "} {
				if got, _ := listedOwners(t, f, f.admin(t), tc.page, s, tc.tool); !slices.Equal(got, []string{"root"}) {
					t.Errorf("admin, scope %q: owners %v, want only root's own", s, got)
				}
			}

			got, scope = listedOwners(t, f, alice, tc.page, "everyone", tc.tool)
			if !slices.Equal(got, []string{"alice"}) {
				t.Errorf("non-admin forging everyone: owners %v, want only alice's own", got)
			}
			if !strings.HasPrefix(scope, "your own jobs") || !strings.Contains(scope, "page asked for everyone") {
				t.Errorf("non-admin forging everyone: scope %q should say they got their own", scope)
			}
			if got, _ := listedOwners(t, f, alice, tc.page, "mine", tc.tool); !slices.Equal(got, []string{"alice"}) {
				t.Errorf("non-admin, mine: owners %v, want only alice's own", got)
			}
		})
	}

	// A page without an everyone view never widens, even for an admin.
	if got, _ := listedOwners(t, f, f.admin(t), "submit", "everyone", "query_jobs"); !slices.Equal(got, []string{"root"}) {
		t.Errorf("admin on the submit page asking for everyone: owners %v, want root's own", got)
	}
	// A constraint naming someone else cannot reach them from mine.
	out, err := runChatTool(t, f, alice, "jobs", "everyone", "query_jobs", `{"constraint":"Owner == \"bob\""}`)
	if err != nil || strings.Contains(out, `"owner":"bob"`) {
		t.Errorf("alice naming bob reached his jobs: %v %s", err, out)
	}
	if _, err := runChatTool(t, f, f.admin(t), "jobs", "everyone", "query_jobs", `{"constraint":"true) || (true"}`); err == nil {
		t.Error("an unbalanced constraint was accepted in the everyone scope")
	}
}

// analyze_issues follows the resolved scope, not an argument: everyone's
// problems for an administrator in the everyone view, their own in mine,
// and a non-administrator's own whatever the page asked for.
func TestChatAnalyzeIssuesFollowsResolvedScope(t *testing.T) {
	f := issuesFixture(t)
	for _, tc := range []struct {
		who    string
		groups []string
		scope  string
		want   []string
	}{
		{"root", []string{"condor-admins"}, "everyone", []string{"31.0", "32.0", "33.0"}},
		{"root", []string{"condor-admins"}, "mine", nil},
		{"root", []string{"condor-admins"}, "bogus", nil},
		{"alice", nil, "everyone", []string{"31.0", "32.0"}},
		{"alice", nil, "mine", []string{"31.0", "32.0"}},
	} {
		got, err := chatIssuesScoped(t, f, tc.who, tc.scope, `{}`, tc.groups...)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.who, tc.scope, err)
		}
		if ids := exampleJobs(got); !slices.Equal(ids, tc.want) {
			t.Errorf("%s scope %q saw %v, want %v", tc.who, tc.scope, ids, tc.want)
		}
	}
	// An everyone argument from the model is no longer a way in.
	got, err := chatIssuesScoped(t, f, "root", "mine", `{"everyone":true}`, "condor-admins")
	if err != nil {
		t.Fatal(err)
	}
	if ids := exampleJobs(got); len(ids) != 0 {
		t.Errorf("admin in the mine view passing everyone=true saw %v", ids)
	}
}

// analyze_utilization follows the resolved scope the same way.
func TestChatAnalyzeUtilizationFollowsResolvedScope(t *testing.T) {
	f := utilizationFixture(t)
	for _, tc := range []struct {
		who       string
		groups    []string
		scope     string
		alice     bool
		bob       bool
		scopeLine string
	}{
		{"root", []string{"condor-admins"}, "everyone", true, true, "Scope: every user's jobs"},
		{"root", []string{"condor-admins"}, "mine", false, false, "Scope: your own jobs"},
		{"alice", nil, "everyone", true, false, "Scope: your own jobs (the page asked"},
		{"alice", nil, "mine", true, false, "Scope: your own jobs"},
	} {
		out := chatUtilizationScoped(t, f, tc.who, tc.scope, `{"days":7}`, tc.groups...)
		if strings.Contains(out, "alice_sim") != tc.alice || strings.Contains(out, "bob_sim") != tc.bob {
			t.Errorf("%s scope %q: alice's=%v bob's=%v, want %v %v:\n%s", tc.who, tc.scope,
				strings.Contains(out, "alice_sim"), strings.Contains(out, "bob_sim"), tc.alice, tc.bob, out)
		}
		if !strings.HasPrefix(out, tc.scopeLine) {
			t.Errorf("%s scope %q: answer does not start with %q:\n%s", tc.who, tc.scope, tc.scopeLine, out)
		}
	}
}

// The single-job actions on the jobs page follow the REST rule for acting
// on another user's job: the mutate tier (the Web UI admin group) may, in
// the everyone view; the read tier alone (an mcp:admin grant) may not,
// nor may anyone in the mine view, nor a non-administrator ever.
func TestChatSingleJobActionsFollowMutateScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		auth  func(*twoOwnerFixture, *testing.T) func(*http.Request)
		scope string
		acts  bool
	}{
		{"admin everyone", func(f *twoOwnerFixture, t *testing.T) func(*http.Request) { return f.admin(t) }, "everyone", true},
		{"admin mine", func(f *twoOwnerFixture, t *testing.T) func(*http.Request) { return f.admin(t) }, "mine", false},
		{"admin unknown scope", func(f *twoOwnerFixture, t *testing.T) func(*http.Request) { return f.admin(t) }, "all", false},
		{"read-tier grant everyone", func(f *twoOwnerFixture, t *testing.T) func(*http.Request) {
			return f.bearer(t, "carol", "mcp:read", "mcp:write", "mcp:admin")
		}, "everyone", false},
		{"non-admin forged everyone", func(f *twoOwnerFixture, t *testing.T) func(*http.Request) { return f.session(t, "alice") }, "everyone", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := scopeFixture(t)
			out, err := runChatTool(t, f, tc.auth(f, t), "jobs", tc.scope, "hold_job", `{"cluster_id":2,"proc_id":0}`)
			acted := f.schedd.ActedOn()
			if tc.acts {
				if err != nil || !slices.Equal(acted, []string{"2.0"}) {
					t.Fatalf("hold of bob's 2.0: err %v, acted on %v, want 2.0", err, acted)
				}
				if !strings.Contains(out, `"owner":"bob"`) {
					t.Errorf("result does not name the owner: %s", out)
				}
			} else {
				if err == nil || len(acted) != 0 {
					t.Fatalf("hold of bob's 2.0 was not refused: err %v, acted on %v, out %s", err, acted, out)
				}
				if !strings.Contains(err.Error(), "not one you can act on") {
					t.Errorf("refusal: %v", err)
				}
			}

			// edit_job_attribute and run_in_job are scoped by the same
			// lookup. The fake schedd has no QMGMT and bob's job is not
			// running, so getting past the scope shows as a different
			// error.
			for _, call := range []struct{ page, tool, args string }{
				{"job-detail", "edit_job_attribute", `{"cluster_id":2,"proc_id":0,"name":"JobPrio","expression":"5"}`},
				{"job-detail", "run_in_job", `{"job_id":"2.0","command":"ls"}`},
			} {
				_, err := runChatTool(t, f, tc.auth(f, t), call.page, tc.scope, call.tool, call.args)
				if err == nil {
					t.Fatalf("%s on bob's job unexpectedly succeeded", call.tool)
				}
				if refused := strings.Contains(err.Error(), "not one you can act on"); refused == tc.acts {
					t.Errorf("%s on bob's job: refused=%v, want %v: %v", call.tool, refused, !tc.acts, err)
				}
			}
		})
	}
}

// Bulk removal: an administrator in the everyone view removes every
// match; a non-administrator asking for everyone removes only their own.
func TestChatRemoveJobsFollowsMutateScope(t *testing.T) {
	f := scopeFixture(t)
	if _, err := runChatTool(t, f, f.session(t, "alice"), "jobs", "everyone", "remove_jobs", `{"constraint":"true"}`); err != nil {
		t.Fatal(err)
	}
	if acted := f.schedd.ActedOn(); !slices.Equal(acted, []string{"1.0"}) {
		t.Errorf("alice's remove_jobs of constraint=true acted on %v, want only her 1.0", acted)
	}

	f = scopeFixture(t)
	if _, err := runChatTool(t, f, f.admin(t), "jobs", "everyone", "remove_jobs", `{"constraint":"true"}`); err != nil {
		t.Fatal(err)
	}
	acted := f.schedd.ActedOn()
	slices.Sort(acted)
	if !slices.Equal(acted, []string{"1.0", "2.0", "3.0"}) {
		t.Errorf("admin's everyone remove_jobs acted on %v, want every job", acted)
	}

	f = scopeFixture(t)
	if _, err := runChatTool(t, f, f.admin(t), "jobs", "mine", "remove_jobs", `{"constraint":"true"}`); err != nil {
		t.Fatal(err)
	}
	if acted := f.schedd.ActedOn(); !slices.Equal(acted, []string{"3.0"}) {
		t.Errorf("admin's mine remove_jobs acted on %v, want only root's 3.0", acted)
	}
}

// The mutate tier, evaluated: the constraint a bulk edit or removal sends
// matches another user's job only for the mutate tier in the everyone
// scope.
func TestChatJobScopeMutateTier(t *testing.T) {
	bobJob := func(constraint string) bool { return scopeAdmits(t, constraint, "bob") }
	for _, tc := range []struct {
		scope      chat.Scope
		read, edit bool
	}{
		{chat.Scope{Requested: "everyone", Effective: chat.ScopeEveryone, ActOnOthers: true}, true, true},
		{chat.Scope{Requested: "everyone", Effective: chat.ScopeEveryone}, true, false},
		{chat.Scope{Requested: "everyone", Effective: chat.ScopeProjects, Projects: []string{"p"}, ActOnOthers: true}, false, false},
		{chat.Mine("everyone"), false, false},
		{chat.Scope{Requested: "everyone", Effective: "bogus", ActOnOthers: true}, false, false},
	} {
		ctx := chat.WithScope(context.Background(), tc.scope)
		read, err := chatJobScope(ctx, "alice@test.domain", "JobStatus == 5", jobScopeRead)
		if err != nil {
			t.Fatal(err)
		}
		edit, err := chatJobScope(ctx, "alice@test.domain", "JobStatus == 5", jobScopeMutate)
		if err != nil {
			t.Fatal(err)
		}
		if bobJob(read) != tc.read || bobJob(edit) != tc.edit {
			t.Errorf("%+v: reads bob's=%v acts on bob's=%v, want %v %v", tc.scope, bobJob(read), bobJob(edit), tc.read, tc.edit)
		}
		if !scopeAdmits(t, edit, "alice") {
			t.Errorf("%+v: does not reach alice's own job", tc.scope)
		}
	}
	// No scope on the context at all is the caller's own.
	c, err := chatJobScope(context.Background(), "alice", "", jobScopeRead)
	if err != nil || scopeAdmits(t, c, "bob") {
		t.Errorf("no scope on the context reached bob's job: %q %v", c, err)
	}
}

// The approval card names the owner of the job an action would touch when
// that is not the caller -- and only then.
func TestChatConfirmationNamesOwner(t *testing.T) {
	f := scopeFixture(t)
	hold := func(auth func(*http.Request), scope, job string) map[string]any {
		return describeChatTool(t, f, auth, "jobs", scope, "hold_job", job)
	}
	if got := hold(f.admin(t), "everyone", `{"cluster_id":2,"proc_id":0}`); fmt.Sprint(got["owners"]) != "[bob]" {
		t.Errorf("admin holding bob's job: card %v, want owner bob", got)
	}
	if got := hold(f.admin(t), "everyone", `{"cluster_id":3,"proc_id":0}`); got != nil {
		t.Errorf("admin holding their own job: card %v, want nothing extra", got)
	}
	if got := hold(f.admin(t), "everyone", `{"cluster_id":99,"proc_id":0}`); got["owner_unknown"] != true {
		t.Errorf("admin holding a job that does not exist: card %v, want owner unknown", got)
	}
	if got := hold(f.session(t, "alice"), "everyone", `{"cluster_id":1,"proc_id":0}`); got != nil {
		t.Errorf("non-admin: card %v, want nothing extra (confined to their own)", got)
	}

	got := describeChatTool(t, f, f.admin(t), "jobs", "everyone", "remove_jobs", `{"constraint":"true"}`)
	owners := fmt.Sprint(got["owners"])
	if !strings.Contains(owners, "alice (1)") || !strings.Contains(owners, "bob (1)") {
		t.Errorf("admin bulk removal: card %v, want every owner it matches", got)
	}
	if got := describeChatTool(t, f, f.admin(t), "jobs", "everyone", "remove_jobs", `{"cluster_id":3}`); got != nil {
		t.Errorf("admin bulk removal of their own batch: card %v, want nothing extra", got)
	}
	if got := describeChatTool(t, f, f.admin(t), "job-detail", "everyone", "run_in_job", `{"job_id":"2.0","command":"ls"}`); fmt.Sprint(got["owners"]) != "[bob]" {
		t.Errorf("admin running a command in bob's job: card %v, want owner bob", got)
	}
}

// resolveChatScope by page and caller, including a project lead, who gets
// own-plus-projects only where the page's REST endpoint gives it.
func TestResolveChatScope(t *testing.T) {
	f := scopeFixture(t)
	f.s.projectLeads = newProjectLeads("", "{project}-leads", "", nil)
	resolve := func(auth func(*http.Request), page, scope string) chat.Scope {
		ctx, _ := chatToolCtx(t, f, auth, page, scope)
		return chat.ScopeFrom(ctx)
	}
	dave := f.session(t, "dave", "proj1-leads")

	if got := resolve(f.admin(t), "jobs", "everyone"); got.Effective != chat.ScopeEveryone || !got.ActOnOthers {
		t.Errorf("admin on jobs: %+v", got)
	}
	if got := resolve(f.bearer(t, "carol", "mcp:read", "mcp:admin"), "jobs", "everyone"); got.Effective != chat.ScopeEveryone || got.ActOnOthers {
		t.Errorf("read-tier grant on jobs: %+v, want everyone without acting", got)
	}
	if got := resolve(dave, "jobs", "everyone"); got.Effective != chat.ScopeProjects || !slices.Equal(got.Projects, []string{"proj1"}) {
		t.Errorf("lead on jobs: %+v, want own plus proj1", got)
	}
	if got := resolve(dave, "issues", "everyone"); got.Effective != chat.ScopeMine || !got.Denied() {
		t.Errorf("lead on issues (no lead view there): %+v, want own, denied", got)
	}
	if got := resolve(f.session(t, "alice"), "jobs", "everyone"); got.Effective != chat.ScopeMine || !got.Denied() {
		t.Errorf("non-admin asking for everyone: %+v", got)
	}
	if got := resolve(f.admin(t), "pool", "everyone"); got.Effective != chat.ScopeMine {
		t.Errorf("admin on a page without an everyone view: %+v", got)
	}

	// The endpoint the panel reads answers the same.
	w := f.do(t, http.MethodGet, "/api/v1/chat/scope?page=jobs&scope=everyone", "", f.session(t, "alice"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"scope":"mine"`) || !strings.Contains(w.Body.String(), `"requested":"everyone"`) {
		t.Errorf("GET /api/v1/chat/scope as alice: %d %s", w.Code, w.Body.String())
	}
	w = f.do(t, http.MethodGet, "/api/v1/chat/scope?page=jobs&scope=everyone", "", f.admin(t))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"scope":"everyone"`) {
		t.Errorf("GET /api/v1/chat/scope as admin: %d %s", w.Code, w.Body.String())
	}
}

// fakeAnthropic is an LLM endpoint for handleChat tests: it records each
// request's system prompt and answers the first call with replies[0], the
// second with replies[1], and so on, then with a plain "done".
type fakeAnthropic struct {
	mu      sync.Mutex
	systems []string
	replies []string
}

func (a *fakeAnthropic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		System string `json:"system"`
	}
	_ = json.Unmarshal(body, &req)
	a.mu.Lock()
	n := len(a.systems)
	a.systems = append(a.systems, req.System)
	a.mu.Unlock()
	w.Header().Set("Content-Type", "text/event-stream")
	if n < len(a.replies) {
		_, _ = io.WriteString(w, a.replies[n])
		return
	}
	_, _ = io.WriteString(w, sseText("done"))
}

func sseText(text string) string {
	return strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		``,
		`event: content_block_delta`,
		fmt.Sprintf(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%q}}`, text),
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``, ``,
	}, "\n")
}

func sseToolUse(id, name, input string) string {
	return strings.Join([]string{
		`event: content_block_start`,
		fmt.Sprintf(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":%q,"name":%q}}`, id, name),
		``,
		`event: content_block_delta`,
		fmt.Sprintf(`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, input),
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``, ``,
	}, "\n")
}

// withChatEngine points f's chat at a fake LLM.
func withChatEngine(t *testing.T, f *twoOwnerFixture, llm *fakeAnthropic) {
	t.Helper()
	srv := httptest.NewServer(llm)
	t.Cleanup(srv.Close)
	keyFile := filepath.Join(t.TempDir(), "llm.key")
	if err := os.WriteFile(keyFile, []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := chat.NewAnthropicClient(chat.AnthropicConfig{APIKeyFile: keyFile, URL: srv.URL})
	if err != nil || client == nil {
		t.Fatalf("NewAnthropicClient: %v", err)
	}
	f.s.chatEngine = chat.NewEngine(client, f.s.buildChatTools(), chatPageInstructions(), "")
}

func postChat(t *testing.T, f *twoOwnerFixture, auth func(*http.Request), body map[string]any) string {
	t.Helper()
	body["messages"] = []map[string]any{{"role": "user", "parts": []map[string]any{{"type": "text", "text": "hello"}}}}
	raw, _ := json.Marshal(body)
	w := f.do(t, http.MethodPost, "/api/v1/chat", string(raw), auth)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/chat: %d %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// The system prompt states the scope the server resolved, not the one the
// page asked for.
func TestChatSystemPromptStatesResolvedScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		auth  func(*twoOwnerFixture, *testing.T) func(*http.Request)
		scope string
		want  string
		not   string
	}{
		{"admin everyone", func(f *twoOwnerFixture, t *testing.T) func(*http.Request) { return f.admin(t) }, "everyone",
			"your job tools\ncover every user's jobs", "ONLY the user's own"},
		{"admin mine", func(f *twoOwnerFixture, t *testing.T) func(*http.Request) { return f.admin(t) }, "mine",
			"scoped to the authenticated user's own jobs", "every user's jobs"},
		{"non-admin asking for everyone", func(f *twoOwnerFixture, t *testing.T) func(*http.Request) { return f.session(t, "alice") }, "everyone",
			"your tools cover ONLY the user's own jobs", "your job tools\ncover every user's jobs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := scopeFixture(t)
			llm := &fakeAnthropic{}
			withChatEngine(t, f, llm)
			postChat(t, f, tc.auth(f, t), map[string]any{"page": "jobs", "scope": tc.scope})
			if len(llm.systems) == 0 {
				t.Fatal("the LLM was never called")
			}
			got := llm.systems[0]
			if !strings.Contains(got, tc.want) || strings.Contains(got, tc.not) {
				t.Errorf("system prompt does not state the resolved scope (want %q, not %q):\n%s", tc.want, tc.not, got)
			}
		})
	}
}

// In the everyone view an auto-approved action still asks first, and the
// approval request names the job's owner; in the mine view the same
// auto-approval runs it.
func TestChatEveryoneScopeIgnoresAutoApprove(t *testing.T) {
	f := scopeFixture(t)
	llm := &fakeAnthropic{replies: []string{sseToolUse("tu_1", "hold_job", `{"cluster_id":2,"proc_id":0}`)}}
	withChatEngine(t, f, llm)
	out := postChat(t, f, f.admin(t), map[string]any{"page": "jobs", "scope": "everyone", "auto_approve": []string{"hold_job"}})
	if !strings.Contains(out, `"tool-approval-request"`) || !strings.Contains(out, `"approvalDescriptor":{"owners":["bob"]}`) {
		t.Errorf("everyone view: no approval request naming bob:\n%s", out)
	}
	if acted := f.schedd.ActedOn(); len(acted) != 0 {
		t.Errorf("everyone view: auto-approve acted on %v without asking", acted)
	}

	f = scopeFixture(t)
	llm = &fakeAnthropic{replies: []string{sseToolUse("tu_1", "hold_job", `{"cluster_id":3,"proc_id":0}`)}}
	withChatEngine(t, f, llm)
	out = postChat(t, f, f.admin(t), map[string]any{"page": "jobs", "scope": "mine", "auto_approve": []string{"hold_job"}})
	if strings.Contains(out, `"tool-approval-request"`) {
		t.Errorf("mine view: auto-approved hold still asked:\n%s", out)
	}
	if acted := f.schedd.ActedOn(); !slices.Equal(acted, []string{"3.0"}) {
		t.Errorf("mine view: acted on %v, want root's 3.0", acted)
	}
}
