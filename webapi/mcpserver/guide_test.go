package mcpserver

import (
	"context"
	"io/fs"
	"strings"
	"testing"
)

// TestGuideTopicsMatchFiles: every indexed topic has a file, and every file
// is indexed -- a file that is not is text no agent can reach.
func TestGuideTopicsMatchFiles(t *testing.T) {
	files, err := fs.Glob(guideFS, "guide/*.md")
	if err != nil {
		t.Fatal(err)
	}
	indexed := map[string]bool{}
	for _, topic := range guideTopicNames() {
		indexed[topic] = true
		if text, ok := guideText(topic); !ok || strings.TrimSpace(text) == "" {
			t.Errorf("guide topic %q has no text", topic)
		}
	}
	for _, f := range files {
		name := strings.TrimSuffix(strings.TrimPrefix(f, "guide/"), ".md")
		if !indexed[name] {
			t.Errorf("%s is not in guideTopics, so doc_guide cannot serve it", f)
		}
	}
}

func TestDocGuideServesTopicAndIndex(t *testing.T) {
	s := &Server{}

	got, err := s.toolDocGuide(context.Background(), map[string]interface{}{"topic": "dag"})
	if err != nil {
		t.Fatalf("topic dag: %v", err)
	}
	want, _ := guideText("dag")
	if sc := got.(map[string]interface{})["structuredContent"].(map[string]interface{}); sc["content"] != want {
		t.Errorf("topic dag returned %q, want the dag topic", sc["content"])
	}

	got, err = s.toolDocGuide(context.Background(), map[string]interface{}{})
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	index := got.(map[string]interface{})["structuredContent"].(map[string]interface{})["content"].(string)
	for _, topic := range guideTopicNames() {
		if !strings.Contains(index, topic) {
			t.Errorf("the index does not list %q", topic)
		}
	}

	if _, err := s.toolDocGuide(context.Background(), map[string]interface{}{"topic": "nope"}); err == nil ||
		!strings.Contains(err.Error(), "workflow") {
		t.Errorf("unknown topic: got %v, want an error naming the topics", err)
	}
}
