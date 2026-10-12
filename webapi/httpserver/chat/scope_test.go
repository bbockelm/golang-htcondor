package chat

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// A context without a resolved scope, or with one the engine does not
// know, is the caller's own jobs; only "everyone" may act on others.
func TestScopeFromDefaultsToMine(t *testing.T) {
	if got := ScopeFrom(context.Background()); got.Effective != ScopeMine || got.ActOnOthers || got.Denied() {
		t.Errorf("no scope on the context: %+v", got)
	}
	got := ScopeFrom(WithScope(context.Background(), Scope{Requested: "everyone", Effective: "all", ActOnOthers: true}))
	if got.Effective != ScopeMine || got.ActOnOthers || !got.Denied() {
		t.Errorf("unknown effective scope: %+v", got)
	}
	got = ScopeFrom(WithScope(context.Background(), Scope{Requested: "everyone", Effective: ScopeProjects, ActOnOthers: true}))
	if got.Effective != ScopeProjects || got.ActOnOthers {
		t.Errorf("a project scope may not act on others: %+v", got)
	}
	for _, s := range []string{"", "all", "EVERYONE", "mine"} {
		if RequestedScope(s) != ScopeMine {
			t.Errorf("RequestedScope(%q) = %q", s, RequestedScope(s))
		}
	}
}

// The prompt's scope paragraph follows the resolved scope.
func TestSystemPromptScopeStatement(t *testing.T) {
	e := NewEngine(nil, nil, nil, "")
	everyone := e.systemPromptForPage("jobs", nil, "", Scope{Requested: ScopeEveryone, Effective: ScopeEveryone, ActOnOthers: true})
	if !strings.Contains(everyone, "cover every user's jobs") || !strings.Contains(everyone, "names\nthe job's owner") {
		t.Errorf("everyone scope:\n%s", everyone)
	}
	readOnly := e.systemPromptForPage("jobs", nil, "", Scope{Requested: ScopeEveryone, Effective: ScopeEveryone})
	if !strings.Contains(readOnly, "act only on the user's own") {
		t.Errorf("everyone scope without acting:\n%s", readOnly)
	}
	denied := e.systemPromptForPage("jobs", nil, "", Mine(ScopeEveryone))
	if !strings.Contains(denied, "may see only their own") || strings.Contains(denied, "cover every user's jobs") {
		t.Errorf("denied scope:\n%s", denied)
	}
	projects := e.systemPromptForPage("jobs", nil, "", Scope{Requested: ScopeEveryone, Effective: ScopeProjects, Projects: []string{"astro"}})
	if !strings.Contains(projects, "projects they lead\n(astro)") {
		t.Errorf("project scope:\n%s", projects)
	}
}

// The approval request carries a tool's description as the SDK's
// approvalDescriptor, and omits it when there is none.
func TestWriterApprovalDescriptor(t *testing.T) {
	rec := httptest.NewRecorder()
	w := NewWriter(rec)
	w.WriteConfirmationRequest("tu_1", "hold_job", json.RawMessage(`{"cluster_id":2}`), map[string]any{"owners": []string{"bob"}})
	w.WriteConfirmationRequest("tu_2", "hold_job", json.RawMessage(`{"cluster_id":3}`), nil)
	w.Close()
	body := rec.Body.String()
	if !strings.Contains(body, `"approvalDescriptor":{"owners":["bob"]}`) {
		t.Errorf("no descriptor on the first approval request:\n%s", body)
	}
	if strings.Count(body, "approvalDescriptor") != 1 {
		t.Errorf("descriptor on an approval request without one:\n%s", body)
	}
}
