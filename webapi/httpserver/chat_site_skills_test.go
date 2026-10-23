package httpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
)

// siteSkillsHandler builds a server that publishes two site skills, the
// way an access point pointed at a checkout of its documentation does.
func siteSkillsHandler(t *testing.T, operatorInstructions string) *Handler {
	t.Helper()
	root := t.TempDir()
	for rel, body := range map[string]string{
		"gpu.md": "---\nname: Submitting GPU jobs\ndescription: How to request a GPU here.\n---\n" +
			"Use request_gpus = 1 and the local GPU partition.\n",
		"policy/queue.md": "---\nname: Queue policy\ndescription: Runtime limits and priorities.\n---\n" +
			"Jobs are limited to 72 hours.\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := newTestConfig(t)
	cfg.EnableMCP = true
	cfg.MCPSkillsDir = root
	h, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if operatorInstructions != "" {
		path := filepath.Join(t.TempDir(), "chat-instructions.txt")
		if err := os.WriteFile(path, []byte(operatorInstructions), 0o600); err != nil {
			t.Fatal(err)
		}
		text, err := loadOperatorChatInstructions(path)
		if err != nil {
			t.Fatalf("loading operator instructions: %v", err)
		}
		h.chatOperatorText.Store(&text)
	}
	return h.Handler
}

// TestChatPromptCarriesTheSiteSkillCatalogue: the site skills were
// published to MCP agents and to nobody else. An access point that writes
// down how its GPU partition works was telling that to an agent arriving
// over MCP and not to the user sitting in front of its own web UI, who is
// the person the documentation was written for.
func TestChatPromptCarriesTheSiteSkillCatalogue(t *testing.T) {
	h := siteSkillsHandler(t, "")
	guidance := h.siteChatGuidance()
	for _, want := range []string{
		"Site skills",
		"gpu", // the id, which is what get_site_skill takes
		"Submitting GPU jobs",
		"policy/queue",
		"get_site_skill", // how to read one on THIS surface
	} {
		if !strings.Contains(guidance, want) {
			t.Errorf("the chat's site guidance does not mention %q:\n%s", want, guidance)
		}
	}
	// The MCP affordances do not exist here and naming them would send
	// the model after a tool it has not been given.
	for _, unwanted := range []string{"skills_get", "skill://"} {
		if strings.Contains(guidance, unwanted) {
			t.Errorf("the chat's site guidance names the MCP-only %q:\n%s", unwanted, guidance)
		}
	}
}

// TestChatSiteGuidanceOrdersOperatorTextFirst: the operator's own rules
// and the skill catalogue are both site text, and both have to be there.
func TestChatSiteGuidanceOrdersOperatorTextFirst(t *testing.T) {
	h := siteSkillsHandler(t, "Never request more than 8 CPUs.")
	guidance := h.siteChatGuidance()
	rules := strings.Index(guidance, "Never request more than 8 CPUs.")
	catalogue := strings.Index(guidance, "## Site skills")
	if rules < 0 {
		t.Fatalf("the operator's instructions are missing:\n%s", guidance)
	}
	if catalogue < 0 {
		t.Fatalf("the skill catalogue is missing:\n%s", guidance)
	}
	if rules > catalogue {
		t.Error("the operator's own rules should come before the catalogue of documents")
	}
}

// TestChatSiteGuidanceEmptyWithoutSkills: a deployment that publishes
// nothing must add nothing, or every prompt carries an empty heading.
func TestChatSiteGuidanceEmptyWithoutSkills(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.EnableMCP = true
	h, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if got := h.siteChatGuidance(); got != "" {
		t.Errorf("a deployment with no site text should add none, got:\n%s", got)
	}
}

// TestGetSiteSkillReadsOne is the tool the catalogue tells the model to
// call.
func TestGetSiteSkillReadsOne(t *testing.T) {
	h := siteSkillsHandler(t, "")
	tool := h.toolGetSiteSkill()

	out, err := tool.Execute(context.Background(), "alice", json.RawMessage(`{"id":"gpu"}`))
	if err != nil {
		t.Fatalf("reading the gpu skill: %v", err)
	}
	var got struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decoding the result: %v", err)
	}
	if got.ID != "gpu" || got.Name != "Submitting GPU jobs" {
		t.Errorf("wrong skill: %+v", got)
	}
	if !strings.Contains(got.Body, "request_gpus = 1") {
		t.Errorf("the body is not the document: %q", got.Body)
	}
	// The front matter is the library's metadata, not part of what the
	// model should read back as the site's words.
	if strings.Contains(got.Body, "---") {
		t.Errorf("front matter leaked into the body: %q", got.Body)
	}
}

// TestGetSiteSkillNamesTheAlternatives: a model that misread an id can
// correct itself this turn only if the error says what does exist.
func TestGetSiteSkillNamesTheAlternatives(t *testing.T) {
	h := siteSkillsHandler(t, "")
	_, err := h.toolGetSiteSkill().Execute(
		context.Background(), "alice", json.RawMessage(`{"id":"gpus"}`))
	if err == nil {
		t.Fatal("expected an error for an unknown skill id")
	}
	for _, want := range []string{"gpus", "gpu", "policy/queue"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// TestGetSiteSkillIsOfferedOnlyWhenThereAreSkills: a tool whose every
// call returns "this access point publishes no site skills" spends
// context to offer the model a dead end.
func TestGetSiteSkillIsOfferedOnlyWhenThereAreSkills(t *testing.T) {
	withSkills := siteSkillsHandler(t, "")
	if !withSkills.toolGetSiteSkill().(*chatTool).Available() {
		t.Error("a site that publishes skills should offer the tool")
	}

	cfg := newTestConfig(t)
	cfg.EnableMCP = true
	bare, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if bare.toolGetSiteSkill().(*chatTool).Available() {
		t.Error("a site that publishes none should not offer the tool")
	}
}

// TestSetChatInstructionsRereadsTheFile: an operator who edits the rules
// and runs condor_reconfig expects the assistant to change its mind. The
// MCP surface has always behaved that way; this one read the file once at
// startup, so the same edit landed on agents and not on web users until
// the daemon was restarted and every live session dropped.
func TestSetChatInstructionsRereadsTheFile(t *testing.T) {
	h := siteSkillsHandler(t, "")
	// SetChatInstructions is a no-op without an engine, which is the
	// state a deployment with no LLM key is in. Stand one in.
	h.chatEngine = &chat.Engine{}

	path := filepath.Join(t.TempDir(), "chat-instructions.txt")
	if err := os.WriteFile(path, []byte("Rule one."), 0o600); err != nil {
		t.Fatal(err)
	}
	h.SetChatInstructions(path)
	if got := h.siteChatGuidance(); !strings.Contains(got, "Rule one.") {
		t.Fatalf("the first read did not land:\n%s", got)
	}

	// The path has not changed, only the contents -- which is the case a
	// diff of the setting cannot see, and the usual reason to reload.
	if err := os.WriteFile(path, []byte("Rule two."), 0o600); err != nil {
		t.Fatal(err)
	}
	h.SetChatInstructions(path)
	got := h.siteChatGuidance()
	if !strings.Contains(got, "Rule two.") {
		t.Errorf("the edit did not land:\n%s", got)
	}
	if strings.Contains(got, "Rule one.") {
		t.Errorf("the superseded rules are still in the prompt:\n%s", got)
	}
}

// TestSetChatInstructionsKeepsTheOldTextOnAFailedRead: a file that has
// momentarily gone missing -- a checkout being replaced, an automount
// that has not come back -- must not silently strip the assistant of the
// site's rules mid-session.
func TestSetChatInstructionsKeepsTheOldTextOnAFailedRead(t *testing.T) {
	h := siteSkillsHandler(t, "")
	h.chatEngine = &chat.Engine{}

	path := filepath.Join(t.TempDir(), "chat-instructions.txt")
	if err := os.WriteFile(path, []byte("Rule one."), 0o600); err != nil {
		t.Fatal(err)
	}
	h.SetChatInstructions(path)
	h.SetChatInstructions(filepath.Join(t.TempDir(), "gone.txt"))

	if got := h.siteChatGuidance(); !strings.Contains(got, "Rule one.") {
		t.Errorf("a failed read dropped the site's rules:\n%s", got)
	}
}

// TestBothSurfacesPublishTheSameSkills: the catalogue a web user's
// assistant is given and the catalogue an MCP agent is given come from
// one library and one renderer, so they name the same skills in the same
// order. Only the sentence about how to read one differs, because only
// that part names an affordance specific to a surface.
func TestBothSurfacesPublishTheSameSkills(t *testing.T) {
	h := siteSkillsHandler(t, "")
	lib := h.chatSkills()
	if lib.Len() == 0 {
		t.Fatal("the fixture published no skills; this test would pass vacuously")
	}

	chatText := lib.Instructions("read with the chat tool")
	mcpText := lib.Instructions("read with the MCP tool")
	for _, sk := range lib.List() {
		if !strings.Contains(chatText, sk.ID) {
			t.Errorf("the chat catalogue omits %q", sk.ID)
		}
		if !strings.Contains(mcpText, sk.ID) {
			t.Errorf("the MCP catalogue omits %q", sk.ID)
		}
	}
	if strings.ReplaceAll(chatText, "read with the chat tool", "X") !=
		strings.ReplaceAll(mcpText, "read with the MCP tool", "X") {
		t.Errorf("the two surfaces describe the same skills differently:\n--- chat ---\n%s\n--- mcp ---\n%s",
			chatText, mcpText)
	}
}
