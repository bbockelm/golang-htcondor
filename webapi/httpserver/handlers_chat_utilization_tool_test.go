package httpserver

import (
	"strings"
	"testing"
)

// chatUtilization runs the chat's analyze_utilization as who would from
// the page: under the context the chat handler builds for that session.
func chatUtilization(t *testing.T, f *twoOwnerFixture, who, args string) string {
	t.Helper()
	return chatUtilizationScoped(t, f, who, "mine", args)
}

// chatUtilizationAs is chatUtilization for a session in groups, with the
// page asking for everyone's jobs.
func chatUtilizationAs(t *testing.T, f *twoOwnerFixture, who, args string, groups ...string) string {
	t.Helper()
	return chatUtilizationScoped(t, f, who, "everyone", args, groups...)
}

// chatUtilizationScoped runs analyze_utilization as who would from the
// page asking for scope.
func chatUtilizationScoped(t *testing.T, f *twoOwnerFixture, who, scope, args string, groups ...string) string {
	t.Helper()
	out, err := runChatTool(t, f, f.session(t, who, groups...), "utilization", scope, "analyze_utilization", args)
	if err != nil {
		t.Fatalf("analyze_utilization as %s: %v", who, err)
	}
	return out
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

// The page's everyone view: an administrator gets every user's
// workflows, anyone else still gets only their own.
func TestChatAnalyzeUtilizationEveryoneIsTheToggle(t *testing.T) {
	f := utilizationFixture(t)

	out := chatUtilizationAs(t, f, "alice", `{}`)
	if !strings.Contains(out, "alice_sim") || strings.Contains(out, "bob_sim") {
		t.Errorf("a non-administrator asking for everyone reached other users' jobs:\n%s", out)
	}

	out = chatUtilizationAs(t, f, "root", `{}`, "condor-admins")
	if !strings.Contains(out, "alice_sim") || !strings.Contains(out, "bob_sim") {
		t.Errorf("an administrator asking for everyone did not get both users' workflows:\n%s", out)
	}
}
