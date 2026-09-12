package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bbockelm/golang-htcondor/version"
)

// The get_version tool exists so an operator (or an agent acting for
// one) can ask the running server what it is, rather than infer it. The
// HTTP /api/v1/version endpoint answers the same question, but it is
// behind the browser login flow; an MCP client is already authenticated
// to this server, so exposing the build here means "did my redeploy
// take?" is a single tool call instead of a round trip through the UI.
//
// It reports version.GetBuild(), not just version.Get(): the git commit
// and dirty flag are what actually distinguish two builds of the same
// tag, and the linked classad/cedar versions matter when triaging a
// wire-compat problem that a bare app version cannot explain.

// versionTool describes the get_version tool. It takes no arguments and
// is read-only.
func versionTool() Tool {
	return Tool{
		Name: "get_version",
		Description: "Report the build identity of the running htcondor-api server: its version, the git commit it was built " +
			"from (and whether that tree was dirty), and the versions of the golang-htcondor, ClassAd, and CEDAR libraries " +
			"linked into it. Use this to confirm which code is actually deployed — for example, after a redeploy, to check " +
			"that the commit you expect is the one now serving.",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	}
}

// toolGetVersion returns the running binary's build information as a
// human-readable summary followed by the exact JSON, so an agent can
// both read it and compare fields programmatically.
func (s *Server) toolGetVersion(_ context.Context, _ map[string]interface{}) (interface{}, error) {
	b := version.GetBuild()

	var sb strings.Builder
	fmt.Fprintf(&sb, "htcondor-api %s\n", b.Describe())
	if b.Module != "" {
		fmt.Fprintf(&sb, "module: %s\n", b.Module)
	}
	if r := b.Revision; r != "" {
		fmt.Fprintf(&sb, "commit: %s", r)
		if b.Dirty {
			sb.WriteString(" (dirty)")
		}
		sb.WriteString("\n")
	}
	if stack := b.Stack.String(); stack != "" {
		fmt.Fprintf(&sb, "stack: %s\n", stack)
	}
	if !b.Stamped() {
		sb.WriteString("note: this binary was built without version or VCS stamps, " +
			"so it cannot say what commit it came from.\n")
	}

	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal build info: %w", err)
	}
	fmt.Fprintf(&sb, "\n%s", raw)

	return textResult(sb.String()), nil
}
