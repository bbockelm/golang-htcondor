package mcpserver

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Keeping the guide honest about what this access point offers.
//
// The guide is compiled in, so it describes every tool this server can
// serve. What it serves is narrower and decided per site and per
// caller: HTTP_API_MCP_DISABLED_TOOLS withdraws tools a site cannot
// offer, a read-only token sees no write tools, and a tool whose
// dependency is absent (no credd, no collector, no database) is never
// offered at all.
//
// Left alone, the guide talks an agent into the one failure the
// withholding exists to prevent. "interactive_session_start -- name the
// session" is read as an instruction, the call is refused, and the
// agent spends its turn discovering what the catalogue already said.
// Worse, the text reads as authoritative: an agent that has been told
// how to do something tends to believe the refusal is a transient
// error and try again.
//
// So the guide is filtered against the catalogue the caller is actually
// served -- not against a second list of what each topic needs, which
// would be another thing to keep in step. A topic whose every tool is
// withheld is withdrawn; a topic that has lost some of them is served
// with a note naming them.

// guideToolMentions maps a guide topic to the tools its text names.
//
// Derived from the text rather than declared beside it, so a topic that
// gains a paragraph about a tool is covered without anybody remembering
// to update a table. Computed once: the files are embedded and cannot
// change under a running server.
var guideToolMentions = sync.OnceValue(func() map[string][]string {
	known := make(map[string]bool, len(toolAnnotations))
	for name := range toolAnnotations {
		known[name] = true
	}

	out := make(map[string][]string, len(guideTopics))
	for _, t := range guideTopics {
		b, err := guideFS.ReadFile("guide/" + t.name + ".md")
		if err != nil {
			// Unreachable: guide_test.go asserts every topic has a
			// file. Treated as "mentions nothing", which leaves the
			// topic offered -- the direction that cannot hide a
			// working topic.
			continue
		}
		seen := map[string]bool{}
		var names []string
		for _, word := range strings.FieldsFunc(string(b), notIdentifierRune) {
			if known[word] && !seen[word] {
				seen[word] = true
				names = append(names, word)
			}
		}
		sort.Strings(names)
		out[t.name] = names
	}
	return out
})

// notIdentifierRune splits the text into the words a tool name could
// be: letters, digits and underscore.
func notIdentifierRune(r rune) bool {
	return r != '_' &&
		(r < 'a' || r > 'z') &&
		(r < 'A' || r > 'Z') &&
		(r < '0' || r > '9')
}

// offeredToolNames is the set of tools this caller is served.
//
// Read from toolsFor, which is the catalogue itself, so the guide
// cannot disagree with tools/list about what exists. It costs building
// the catalogue, which doc_guide can afford: it is called once or twice
// in a conversation, against a tools/list on every reconnect.
func (s *Server) offeredToolNames(ctx context.Context) map[string]bool {
	tools := s.toolsFor(ctx)
	out := make(map[string]bool, len(tools))
	for _, t := range tools {
		out[t.Name] = true
	}
	return out
}

// guideTopicsFor is the index this caller is shown: every topic that
// still has a tool behind it.
//
// Withdrawn on the topic's `needs`, not on everything its text names: a
// topic that mentions a withheld tool in an aside is still worth
// reading, and gets the note instead.
func guideTopicsFor(offered map[string]bool) []guideTopic {
	out := make([]guideTopic, 0, len(guideTopics))
	for _, t := range guideTopics {
		if topicWithdrawn(t, offered) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// topicWithdrawn reports whether none of a topic's subject tools are
// offered. A topic that declares none is never withdrawn.
func topicWithdrawn(t guideTopic, offered map[string]bool) bool {
	return len(t.needs) > 0 && len(withheldFrom(t.needs, offered)) == len(t.needs)
}

// topicByName finds a topic in the index.
func topicByName(name string) (guideTopic, bool) {
	for _, t := range guideTopics {
		if t.name == name {
			return t, true
		}
	}
	return guideTopic{}, false
}

// withheldFrom is the subset of names this caller is not served.
func withheldFrom(names []string, offered map[string]bool) []string {
	var out []string
	for _, n := range names {
		if !offered[n] {
			out = append(out, n)
		}
	}
	return out
}

// guideNoteMaxNames caps how many withdrawn tools a note lists. The
// "tools" topic names every tool there is, so under a read-only token
// the honest list is most of the catalogue -- which would bury the
// topic the agent asked for under a list it can read from tools/list
// itself.
const guideNoteMaxNames = 8

// guideWithheldNote heads a topic that has lost some of its tools.
func guideWithheldNote(withheld []string) string {
	shown := withheld
	var more string
	if len(shown) > guideNoteMaxNames {
		shown = shown[:guideNoteMaxNames]
		more = fmt.Sprintf(" and %d more", len(withheld)-len(shown))
	}
	return fmt.Sprintf(
		"NOTE: this access point does not offer %s%s. The text below describes them anyway, because it describes this server in general; "+
			"tools/list is what you have. Do not call a tool that is not in it -- the refusal is a decision, not a transient error.\n",
		strings.Join(shown, ", "), more)
}

// guideWithdrawnTopic is what a topic reads as when every tool it
// describes is withheld.
//
// Answered rather than refused: the initialize instructions name the
// topics, and a client that read them before the setting changed should
// be told what happened rather than handed an error about a topic that
// does exist.
func guideWithdrawnTopic(topic string, withheld []string) string {
	shown := withheld
	var more string
	if len(shown) > guideNoteMaxNames {
		shown = shown[:guideNoteMaxNames]
		more = fmt.Sprintf(" and %d more", len(withheld)-len(shown))
	}
	return fmt.Sprintf(
		"The %q topic is not available on this access point: it describes %s%s, which this access point does not offer. "+
			"Nothing it says applies here. Use doc_guide with no topic for the topics that do.\n",
		topic, strings.Join(shown, ", "), more)
}

// guideTextFor is the topic as this caller should read it.
func guideTextFor(topic string, offered map[string]bool) (string, bool) {
	text, ok := guideText(topic)
	if !ok {
		return "", false
	}
	withheld := withheldFrom(guideToolMentions()[topic], offered)
	t, _ := topicByName(topic)
	switch {
	case topicWithdrawn(t, offered):
		return guideWithdrawnTopic(topic, withheld), true
	case len(withheld) > 0:
		return guideWithheldNote(withheld) + "\n" + text, true
	default:
		return text, true
	}
}
