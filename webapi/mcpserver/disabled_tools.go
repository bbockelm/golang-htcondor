package mcpserver

import (
	"fmt"
	"path"
	"strings"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Disabling tools by name.
//
// A site can be unable to offer a tool for reasons this server cannot
// see: CHTC's policy forbids condor_ssh_to_job, so the tools built on it
// can never work there however the pool is configured. Offering them
// anyway is worse than not having them, because an agent spends a turn
// discovering that, and the failure it gets back describes a permission
// problem rather than a decision somebody made.
//
// Patterns are matched with path.Match, so "interactive_session_*"
// disables a family and a bare name disables one tool. A disabled tool is
// both withheld from tools/list and refused when called: a client may
// hold a catalogue from before the change, and the SDK transport caches
// one per scope set.

// disabledToolMatcher holds the operator's patterns.
//
// Stored as the parsed list rather than the raw string so a malformed
// pattern is reported once, when it is set, instead of silently matching
// nothing on every call.
type disabledToolMatcher struct {
	patterns []string
}

// matches reports whether a tool name is disabled.
func (m *disabledToolMatcher) matches(name string) bool {
	if m == nil {
		return false
	}
	for _, p := range m.patterns {
		// The error case is a pattern that did not parse, which was
		// already reported when it was set; treat it as matching
		// nothing rather than failing the call.
		if ok, err := path.Match(p, name); err == nil && ok {
			return true
		}
	}
	return false
}

// parseDisabledTools splits an operator's setting into patterns.
//
// Comma or whitespace separated, because HTCondor configuration is
// written both ways and a list that silently ignored one of them would
// look like the setting had not taken.
func parseDisabledTools(spec string) ([]string, []string) {
	var patterns, bad []string
	for _, field := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		// Validate now: path.Match reports a bad pattern only when it is
		// used, where it would be indistinguishable from "matched
		// nothing" -- and the operator would be told their tool was
		// disabled when it was not.
		if _, err := path.Match(field, "x"); err != nil {
			bad = append(bad, field)
			continue
		}
		patterns = append(patterns, field)
	}
	return patterns, bad
}

// SetDisabledTools installs the operator's disabled-tool patterns. It is
// the dynamic half of HTTP_API_MCP_DISABLED_TOOLS: a reconfigure calls this, and
// an empty string re-enables everything.
//
// The catalogue is invalidated because the SDK transport caches a built
// server per scope set. Without that a reconfigure would change what this
// server answers and not what most callers are served -- the failure the
// reconfigure table exists to prevent.
func (s *Server) SetDisabledTools(spec string) {
	patterns, bad := parseDisabledTools(spec)
	for _, p := range bad {
		s.logger.Error(logging.DestinationMCP,
			"Ignoring an unparseable HTTP_API_MCP_DISABLED_TOOLS pattern; the tools it was meant to disable are still offered",
			"pattern", p)
	}
	s.disabledTools.Store(&disabledToolMatcher{patterns: patterns})
	if len(patterns) > 0 {
		s.logger.Info(logging.DestinationMCP, "MCP tools disabled by configuration", "patterns", strings.Join(patterns, " "))
	}
	s.InvalidateCatalog()
}

// toolDisabled reports whether the operator has disabled a tool.
func (s *Server) toolDisabled(name string) bool {
	return s.disabledTools.Load().matches(name)
}

// errToolDisabled is what a caller gets for a tool the site has turned
// off. It names the setting, because the operator reading the agent's
// transcript is the one who can change it, and says the tool is not
// merely failing -- an agent told "permission denied" retries.
func errToolDisabled(name string) error {
	return fmt.Errorf("the %q tool is disabled on this access point (HTTP_API_MCP_DISABLED_TOOLS); it is not available to any caller, so do not retry it", name)
}
