package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// chatUtilization runs the chat's analyze_utilization as who would from
// the page: under the context the chat handler builds for that session.
func chatUtilization(t *testing.T, f *twoOwnerFixture, who, args string) string {
	t.Helper()
	return chatUtilizationAs(t, f, who, args)
}

// chatUtilizationAs is chatUtilization for a session in groups.
func chatUtilizationAs(t *testing.T, f *twoOwnerFixture, who, args string, groups ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/chat", nil)
	f.session(t, who, groups...)(req)
	authCtx, _, err := f.s.requireAuthentication(req)
	if err != nil {
		t.Fatalf("authenticating %s: %v", who, err)
	}
	for _, tool := range f.s.buildChatTools() {
		if tool.Name() != "analyze_utilization" {
			continue
		}
		out, err := tool.Execute(context.WithValue(authCtx, chatRequestKey{}, req), who, json.RawMessage(args))
		if err != nil {
			t.Fatalf("analyze_utilization as %s: %v", who, err)
		}
		return out
	}
	t.Fatal("the chat offers no analyze_utilization")
	return ""
}

// The chat analyses the caller's own finished jobs, and a constraint
// naming someone else's narrows to nothing rather than reaching theirs.
func TestChatAnalyzeUtilizationIsTheCallersOwn(t *testing.T) {
	f := utilizationFixture(t)

	out := chatUtilization(t, f, "alice", `{"days":7}`)
	if !strings.Contains(out, "3 jobs") || !strings.Contains(out, "alice_sim") || strings.Contains(out, "bob_sim") {
		t.Errorf("alice's answer is not her 3 jobs:\n%s", out)
	}

	out = chatUtilization(t, f, "alice", `{"constraint":"Owner == \"bob\""}`)
	if !strings.Contains(out, "No finished jobs") || strings.Contains(out, "bob_sim") {
		t.Errorf("alice naming bob in a constraint reached his jobs:\n%s", out)
	}

	out = chatUtilization(t, f, "bob", `{"workflow":"bob_sim"}`)
	if !strings.Contains(out, "peak memory: ") || strings.Contains(out, "alice_sim") {
		t.Errorf("bob's one-workflow answer:\n%s", out)
	}
}

// everyone=true is the page's scope toggle: an administrator gets every
// user's workflows, anyone else still gets only their own.
func TestChatAnalyzeUtilizationEveryoneIsTheToggle(t *testing.T) {
	f := utilizationFixture(t)

	out := chatUtilization(t, f, "alice", `{"everyone":true}`)
	if !strings.Contains(out, "alice_sim") || strings.Contains(out, "bob_sim") {
		t.Errorf("a non-administrator asking for everyone reached other users' jobs:\n%s", out)
	}

	out = chatUtilizationAs(t, f, "root", `{"everyone":true}`, "condor-admins")
	if !strings.Contains(out, "alice_sim") || !strings.Contains(out, "bob_sim") {
		t.Errorf("an administrator asking for everyone did not get both users' workflows:\n%s", out)
	}
}
