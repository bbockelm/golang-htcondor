package mcpserver

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func guideServer(t *testing.T, disabled string) *Server {
	t.Helper()
	s, err := NewServer(Config{
		ScheddName:    "test",
		ScheddAddr:    "127.0.0.1:9618",
		DisabledTools: disabled,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

func guideAnswer(t *testing.T, s *Server, topic string) string {
	t.Helper()
	args := map[string]interface{}{}
	if topic != "" {
		args["topic"] = topic
	}
	got, err := s.toolDocGuide(context.Background(), args)
	if err != nil {
		t.Fatalf("doc_guide(%q): %v", topic, err)
	}
	sc := got.(map[string]interface{})["structuredContent"].(map[string]interface{})
	return sc["content"].(string)
}

// The mentions are derived from the text, so a topic that gains a
// paragraph about a tool is covered without anybody updating a table.
func TestGuideMentionsAreReadFromTheText(t *testing.T) {
	named := guideToolMentions()["interactive"]
	for _, want := range []string{"interactive_session_start", "interactive_session_exec", "exec_in_job"} {
		if !slices.Contains(named, want) {
			t.Errorf("the interactive topic does not name %s; mentions = %v", want, named)
		}
	}
	// Only real tools, not every identifier in the prose.
	for _, got := range named {
		if toolAnnotations[got] == nil {
			t.Errorf("%q is not a tool but was read as one", got)
		}
	}
}

// The failure this exists for: a site withdraws the session tools and
// the guide goes on explaining how to start one, which an agent reads
// as an instruction and spends a turn being refused.
func TestAWithdrawnTopicIsNotListedOrDescribed(t *testing.T) {
	s := guideServer(t, "interactive_session_* exec_in_job")

	index := guideAnswer(t, s, "")
	if strings.Contains(index, "interactive --") {
		t.Errorf("the index still offers the interactive topic:\n%s", index)
	}
	// The topics that still have tools behind them stay.
	if !strings.Contains(index, "troubleshooting") {
		t.Errorf("the index lost a topic that is still available:\n%s", index)
	}

	text := guideAnswer(t, s, "interactive")
	if strings.Contains(text, "name the session; it queues like any other") {
		t.Error("the withdrawn topic was served in full")
	}
	if !strings.Contains(text, "not available on this access point") {
		t.Errorf("the answer does not say the topic is unavailable: %q", text)
	}
	// Answered, not refused: the initialize instructions name the
	// topics, so a client that read them before the setting changed
	// asks for this one and should be told what happened.
	if !strings.Contains(text, "interactive_session_start") {
		t.Errorf("the answer does not name what is missing: %q", text)
	}
}

// The tool declaration has to agree with the answers: a client
// validates the topic against the enum before it ever calls.
func TestTheDocGuideToolDropsAWithdrawnTopic(t *testing.T) {
	s := guideServer(t, "interactive_session_* exec_in_job")

	var decl *Tool
	for _, tool := range s.toolsFor(context.Background()) {
		if tool.Name == "doc_guide" {
			decl = &tool
			break
		}
	}
	if decl == nil {
		t.Fatal("doc_guide is not in the catalogue")
	}
	props := decl.InputSchema["properties"].(map[string]interface{})
	enum := props["topic"].(map[string]interface{})["enum"].([]string)
	if slices.Contains(enum, "interactive") {
		t.Errorf("the topic enum still offers the withdrawn topic: %v", enum)
	}
	if !slices.Contains(enum, "workflow") {
		t.Errorf("the topic enum lost a topic that is still available: %v", enum)
	}
	if strings.Contains(decl.Description, "interactive --") {
		t.Errorf("the tool description still lists the withdrawn topic: %s", decl.Description)
	}
}

// A topic that has lost SOME of its tools is still worth reading, so it
// is served with a note rather than withdrawn.
func TestAPartlyWithheldTopicCarriesANote(t *testing.T) {
	s := guideServer(t, "exec_in_job")

	text := guideAnswer(t, s, "interactive")
	if !strings.Contains(text, "does not offer exec_in_job") {
		t.Errorf("the note does not name the withheld tool: %q", text)
	}
	// The rest of the topic survives: sessions still work here.
	if !strings.Contains(text, "interactive_session_start") {
		t.Error("the topic body was dropped although it still has tools behind it")
	}
	if !strings.Contains(guideAnswer(t, s, ""), "interactive --") {
		t.Error("a partly-available topic left the index")
	}
}

// Nothing withheld, nothing changed: the note must not appear on a
// server that offers everything the topic names.
func TestAnUntouchedTopicIsServedVerbatim(t *testing.T) {
	offered := map[string]bool{}
	for _, name := range guideToolMentions()["interactive"] {
		offered[name] = true
	}
	want, _ := guideText("interactive")
	got, ok := guideTextFor("interactive", offered)
	if !ok {
		t.Fatal("the interactive topic is missing")
	}
	if got != want {
		t.Errorf("the topic was altered although every tool it names is offered:\n%q", got)
	}
	if len(guideTopicsFor(offered)) == 0 {
		t.Error("no topics survived a server that withholds nothing")
	}
}

// The declared subject of a topic has to be a real tool, and has to be
// something the topic actually teaches -- otherwise the withdrawal is
// decided by a name that means nothing.
func TestEveryTopicSubjectIsARealToolItTeaches(t *testing.T) {
	mentions := guideToolMentions()
	for _, topic := range guideTopics {
		for _, need := range topic.needs {
			if toolAnnotations[need] == nil {
				t.Errorf("topic %q needs %q, which is not a tool", topic.name, need)
			}
			if !slices.Contains(mentions[topic.name], need) {
				t.Errorf("topic %q needs %q but its text never names it", topic.name, need)
			}
		}
	}
}

// Every topic that teaches a tool declares it, so a site that withdraws
// that tool withdraws the topic. A topic added without one would be
// served for ever, teaching calls that are refused -- the failure this
// whole file exists to stop.
func TestEveryToolTeachingTopicDeclaresASubject(t *testing.T) {
	// "tools" is the catalogue overview: it names everything and is
	// about nothing in particular, so it is never withdrawn.
	const overview = "tools"
	for _, topic := range guideTopics {
		if topic.name == overview || len(topic.needs) > 0 {
			continue
		}
		if named := guideToolMentions()[topic.name]; len(named) > 0 {
			t.Errorf("topic %q names tools (%v) but declares no subject, so it can never be withdrawn",
				topic.name, named)
		}
	}
}

// The "tools" topic names every tool there is, so a read-restricted
// caller would otherwise be handed a note longer than the answer.
func TestTheNoteIsCapped(t *testing.T) {
	var many []string
	for i := range guideNoteMaxNames + 5 {
		many = append(many, string(rune('a'+i))+"_tool")
	}
	note := guideWithheldNote(many)
	if !strings.Contains(note, "and 5 more") {
		t.Errorf("the note is not capped: %q", note)
	}
	if strings.Contains(note, many[len(many)-1]) {
		t.Errorf("the note lists past the cap: %q", note)
	}
}
