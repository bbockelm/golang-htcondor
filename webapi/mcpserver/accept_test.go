package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryMCPCallerSendsAccept: a caller that posts to the MCP endpoint
// without an Accept naming both media types works today and is answered 400
// the day the SDK transport becomes the default.
//
// Nothing else catches that. The built-in transport ignores the header, so a
// new caller written without it passes every test until the switch, and then
// fails somewhere far from where it was written. This walks the module for
// files that build a request aimed at the MCP protocol endpoint and requires
// each to name AcceptHeader.
//
// File-level rather than line-level on purpose: matching the exact request a
// header belongs to means parsing Go, and a check that mis-attributes is
// worse than one that is coarse. A file that makes a protocol call and never
// sets Accept is the signal.
//
// The cost of that coarseness, stated so it is not mistaken for coverage: a
// file that already sets the header on one request and adds a second without
// it passes. This catches the new FILE, which is how a new caller normally
// arrives.
func TestEveryMCPCallerSendsAccept(t *testing.T) {
	root := ".."
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == "node_modules" || name == "frontend" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		body, err := os.ReadFile(path) //nolint:gosec // walking this module's own tree
		if err != nil {
			return err
		}
		src := string(body)

		// A protocol call is a POST at the MCP endpoint. Both halves
		// matter: the OAuth2 endpoints under /mcp/oauth2/ never reach the
		// SDK, and a GET that only checks which listener serves a path is
		// not a protocol call either -- it stays correct when the answer
		// changes from 404 to 405.
		//
		// The body is NOT the test, though it looks like the obvious one.
		// The largest caller here builds its request from a Go struct, so
		// the literal "jsonrpc" never appears in it -- a check for the
		// body silently skipped the file with the most call sites.
		aimedAtMCP := strings.Contains(src, `"/mcp/message"`) ||
			strings.Contains(src, `+"/mcp/message"`) ||
			strings.Contains(src, `"/mcp"`) ||
			strings.Contains(src, `+"/mcp"`)
		buildsRequest := strings.Contains(src, "NewRequest")
		posts := strings.Contains(src, "MethodPost") || strings.Contains(src, `"POST"`)
		if !aimedAtMCP || !buildsRequest || !posts {
			return nil
		}
		// The server side routes these paths; it does not call them.
		if strings.Contains(src, "func (h *Handler) handleMCPMessage") ||
			strings.Contains(src, "mux.HandleFunc(mcpPath") {
			return nil
		}
		// Look for the call, not the name: the comment beside each of
		// these says "see mcpserver.AcceptHeader", so matching the name
		// would be satisfied by the explanation of the thing rather than
		// the thing. Found by mutation -- deleting a Set left the file
		// passing on its own comment.
		if strings.Contains(src, `Header.Set("Accept"`) {
			return nil
		}
		offenders = append(offenders, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("these post to the MCP endpoint without naming AcceptHeader, so they break "+
			"when the SDK transport becomes the default:\n  %s", strings.Join(offenders, "\n  "))
	}
}
