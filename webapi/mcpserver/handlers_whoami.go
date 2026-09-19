package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Who the caller is, and what that gets them.
//
// Every read tool already appends an owner-scope note, but only after doing
// work, and only about that call. An agent starting a session has no way to ask
// the plain question -- who am I here, and am I an admin -- and a person
// debugging an access problem has to infer it from whether a query came back
// empty. Both answers already exist inside the server; this exposes them.
//
// The values are read through the same functions the enforcement uses
// (ownerScope, isAdmin), not recomputed. A whoami that derived admin status
// separately could report one thing while the tools did another, which is worse
// than not having it.

// whoamiTool describes the whoami tool. It takes no arguments and is read-only.
func whoamiTool() Tool {
	return Tool{
		Name: "whoami",
		Description: "Report who this server has authenticated you as, whether you are treated as an administrator, " +
			"and what that means for the other tools: an admin sees every user's jobs, while everyone else is confined " +
			"to their own. Also reports the access point you are talking to and the OAuth scopes your token carries. " +
			"Use this when a query returns nothing unexpected, or before assuming a tool will act on somebody else's jobs.",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	}
}

// whoamiReport is the structured half of the answer.
type whoamiReport struct {
	// Authenticated is the identity the server resolved, empty when the
	// caller could not be identified at all.
	Authenticated string `json:"authenticated_user"`
	// Admin reports whether this identity is in MCP_ADMIN_USERS.
	Admin bool `json:"admin"`
	// Scope is what the other tools will confine this caller to.
	Scope string `json:"job_visibility"`
	// Owner is the job owner reads and mutations are limited to, empty for
	// an admin.
	Owner string `json:"confined_to_owner,omitempty"`
	// AccessPoint is the schedd this server submits to.
	AccessPoint string `json:"access_point,omitempty"`
	// Scopes are the OAuth scopes the caller's token carries, when the
	// transport supplied them.
	Scopes []string `json:"oauth_scopes,omitempty"`
}

// toolWhoami answers the question directly, as prose plus the same facts in
// JSON so an agent can branch on them.
func (s *Server) toolWhoami(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)

	rep := whoamiReport{
		Authenticated: actor,
		Admin:         s.isAdmin(actor),
	}
	if sc := s.getSchedd(); sc != nil {
		rep.AccessPoint = sc.Name()
	}
	if scopes := grantedScopesFromContext(ctx); scopes != nil {
		rep.Scopes = append([]string(nil), scopes...)
		sort.Strings(rep.Scopes)
	}

	// Ask the same function the tools ask, so this cannot describe a
	// confinement the tools do not apply.
	scope, ok := s.ownerScope(ctx)
	switch {
	case !ok:
		rep.Scope = "none: the server could not identify you, so owner-scoped tools will refuse"
	case scope.AllUsers:
		rep.Scope = "all users"
	default:
		rep.Scope = "your own jobs"
		rep.Owner = scope.Owner
	}

	var sb strings.Builder
	if actor == "" {
		sb.WriteString("You are not authenticated: this server could not resolve an identity for this call.\n")
	} else {
		fmt.Fprintf(&sb, "You are %s.\n", actor)
	}
	if rep.Admin {
		sb.WriteString("You are an administrator here (listed in MCP_ADMIN_USERS): tools act across every user's jobs, " +
			"so a query or a removal is not limited to your own.\n")
	} else if actor != "" {
		sb.WriteString("You are not an administrator here: every tool is confined to your own jobs.\n")
	}
	if rep.AccessPoint != "" {
		fmt.Fprintf(&sb, "Access point: %s\n", rep.AccessPoint)
	}
	if len(rep.Scopes) > 0 {
		fmt.Fprintf(&sb, "Token scopes: %s\n", strings.Join(rep.Scopes, " "))
	}

	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal whoami: %w", err)
	}
	fmt.Fprintf(&sb, "\n%s", raw)

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": sb.String()},
		},
	}, nil
}
