package mcpserver

import (
	"context"
	"embed"
	"fmt"
	"strings"
)

// The agent guide: the long-form "how to use these tools" text, served by
// doc_guide one topic at a time.
//
// It lives here rather than in the initialize instructions because clients
// do not always pass the whole of those to the model -- Claude Code keeps
// about the first 2 KB -- so the instructions carry only the mistakes an
// agent makes most often and name these topics for the rest. Unlike the
// HTCondor manual pages behind the other doc_* tools, the guide is always
// compiled in: it describes this server, not the upstream docs.

//go:embed guide/*.md
var guideFS embed.FS

type guideTopic struct {
	name    string
	summary string
}

// guideTopics is the guide's index, in the order it is listed. Every entry
// has a guide/<name>.md, and every file has an entry (see guide_test.go).
var guideTopics = []guideTopic{
	{"workflow", "the submit, upload, wait, collect sequence; moving large inputs and outputs by URL"},
	{"submit_files", "a minimal submit file, transfer_executable, $(...) macros, environment"},
	{"monitoring", "job states, waiting without polling, live vs finished output, attributes, constraints, history"},
	{"troubleshooting", "jobs stuck idle, held jobs and their causes, credentials, restarts"},
	{"dag", "multi-step workflows with DAGMan"},
	{"interactive", "interactive sessions, and one command in a running job"},
	{"containers", "building Apptainer images with build_container"},
	{"tools", "every tool, grouped by task"},
}

func guideTopicNames() []string {
	names := make([]string, len(guideTopics))
	for i, t := range guideTopics {
		names[i] = t.name
	}
	return names
}

func guideText(topic string) (string, bool) {
	for _, t := range guideTopics {
		if t.name == topic {
			b, err := guideFS.ReadFile("guide/" + topic + ".md")
			if err != nil {
				return "", false
			}
			return string(b), true
		}
	}
	return "", false
}

func guideIndex() string {
	var b strings.Builder
	b.WriteString("Topics in the agent guide (call doc_guide with one):\n")
	for _, t := range guideTopics {
		fmt.Fprintf(&b, "- %s -- %s\n", t.name, t.summary)
	}
	return b.String()
}

func docGuideTool() Tool {
	return Tool{
		Name: "doc_guide",
		Description: "Read a topic of the guide to this server's tools: how to submit, wait for and " +
			"diagnose jobs, and the mistakes to avoid. Call with no topic for the list. " +
			strings.TrimSuffix(strings.ReplaceAll(guideIndex(), "\n- ", " | "), "\n"),
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"topic": map[string]interface{}{
					"type":        "string",
					"enum":        guideTopicNames(),
					"description": "The topic to read. Omit it to list the topics.",
				},
			},
		},
	}
}

// toolDocGuide answers doc_guide: one topic in full, or the index.
func (s *Server) toolDocGuide(_ context.Context, args map[string]interface{}) (interface{}, error) {
	topic, _ := args["topic"].(string)
	topic = strings.TrimSpace(topic)

	topics := make([]map[string]interface{}, 0, len(guideTopics))
	for _, t := range guideTopics {
		topics = append(topics, map[string]interface{}{"name": t.name, "summary": t.summary})
	}

	if topic == "" {
		index := guideIndex()
		return structuredTextResult(index, map[string]interface{}{
			"topic": "", "content": index, "topics": topics,
		}), nil
	}
	text, ok := guideText(topic)
	if !ok {
		return nil, fmt.Errorf("no guide topic %q; topics are: %s", topic, strings.Join(guideTopicNames(), ", "))
	}
	return structuredTextResult(text, map[string]interface{}{"topic": topic, "content": text}), nil
}
