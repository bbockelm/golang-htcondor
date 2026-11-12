package mcpserver

import (
	"context"
	"embed"
	"fmt"
	"strings"

	"github.com/bbockelm/golang-htcondor/webapi/agentguide"
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
	// needs names the tools the topic is ABOUT, so that a topic whose
	// subject this access point does not offer can be withdrawn rather
	// than left teaching calls that will be refused (guide_offered.go).
	//
	// Declared rather than read out of the text, which the note beside
	// it is: "which tools does this paragraph name" and "what is this
	// topic for" are different questions, and the first answers the
	// second badly. The interactive topic mentions whoami in an aside
	// about multi-AP; reading that as a subject keeps the topic alive
	// on a site with no sessions at all, which is the one case it has
	// to be withdrawn in. guide_offered_test.go checks that every name
	// here is a real tool and does appear in the topic's text.
	//
	// Empty means a topic that is never withdrawn -- "tools" is the
	// catalogue overview, and what it should say about a withheld tool
	// is said by the note.
	needs []string
}

// guideTopics is the guide's index, in the order it is listed. Every entry
// has a guide/<name>.md, and every file has an entry (see guide_test.go).
var guideTopics = []guideTopic{
	{"workflow", "the submit, upload, wait, collect sequence; moving large inputs and outputs by URL", []string{"submit_job"}},
	{"submit_files", "a minimal submit file, transfer_executable, $(...) macros, environment", []string{"submit_job"}},
	{"monitoring", "job states, waiting without polling, live vs finished output, attributes, constraints, history", []string{"query_jobs"}},
	{"troubleshooting", "jobs stuck idle, held jobs and their causes, credentials, restarts", []string{"analyze_issues", "get_job"}},
	{"dag", "multi-step workflows with DAGMan", []string{"submit_dag"}},
	{"interactive", "interactive sessions, and one command in a running job", []string{"interactive_session_start", "exec_in_job"}},
	{"containers", "building Apptainer images with build_container", []string{"build_container"}},
	{"tools", "every tool, grouped by task", nil},
}

func guideTopicNames() []string {
	names := make([]string, len(guideTopics))
	for i, t := range guideTopics {
		names[i] = t.name
	}
	return names
}

// guideAppendix is the text a topic ends with that is shared with the
// other agent surface on this server rather than written here.
//
// The browser chat assistant on the submission page writes submit
// descriptions too, and the rules it must follow are the same ones an MCP
// agent must follow. Keeping those in agentguide and appending them means
// a correction lands on both surfaces at once; the alternative, which this
// replaces, was two copies that drifted until one of them was missing the
// rule entirely.
var guideAppendix = map[string]func() string{
	"submit_files": agentguide.SubmitOutput,
}

func guideText(topic string) (string, bool) {
	for _, t := range guideTopics {
		if t.name == topic {
			b, err := guideFS.ReadFile("guide/" + topic + ".md")
			if err != nil {
				return "", false
			}
			text := string(b)
			if appendix, ok := guideAppendix[topic]; ok {
				text = strings.TrimRight(text, "\n") + "\n\n" + appendix()
			}
			return text, true
		}
	}
	return "", false
}

// guideIndex lists the topics given, which are the ones this caller is
// served -- see guide_offered.go.
func guideIndex(topics []guideTopic) string {
	var b strings.Builder
	b.WriteString("Topics in the agent guide (call doc_guide with one):\n")
	for _, t := range topics {
		fmt.Fprintf(&b, "- %s -- %s\n", t.name, t.summary)
	}
	return b.String()
}

func topicNames(topics []guideTopic) []string {
	names := make([]string, len(topics))
	for i, t := range topics {
		names[i] = t.name
	}
	return names
}

// docGuideTool declares the tool over the topics this caller is served,
// so the enum a client validates against and the index in the
// description name the same topics doc_guide will answer.
func docGuideTool(topics []guideTopic) Tool {
	return Tool{
		Name: "doc_guide",
		Description: "Read a topic of the guide to this server's tools: how to submit, wait for and " +
			"diagnose jobs, and the mistakes to avoid. Call with no topic for the list. " +
			strings.TrimSuffix(strings.ReplaceAll(guideIndex(topics), "\n- ", " | "), "\n"),
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"topic": map[string]interface{}{
					"type":        "string",
					"enum":        topicNames(topics),
					"description": "The topic to read. Omit it to list the topics.",
				},
			},
		},
	}
}

// toolDocGuide answers doc_guide: one topic in full, or the index.
func (s *Server) toolDocGuide(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	topic, _ := args["topic"].(string)
	topic = strings.TrimSpace(topic)

	// What this caller is served, which is what the guide is filtered
	// against. See guide_offered.go.
	offered := s.offeredToolNames(ctx)
	shown := guideTopicsFor(offered)

	topics := make([]map[string]interface{}, 0, len(shown))
	for _, t := range shown {
		topics = append(topics, map[string]interface{}{"name": t.name, "summary": t.summary})
	}

	if topic == "" {
		index := guideIndex(shown)
		return structuredTextResult(index, map[string]interface{}{
			"topic": "", "content": index, "topics": topics,
		}), nil
	}
	text, ok := guideTextFor(topic, offered)
	if !ok {
		return nil, fmt.Errorf("no guide topic %q; topics are: %s", topic, strings.Join(topicNames(shown), ", "))
	}
	return structuredTextResult(text, map[string]interface{}{"topic": topic, "content": text}), nil
}
