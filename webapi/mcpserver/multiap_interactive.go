package mcpserver

import (
	"context"
	"maps"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Interactive sessions in multi-AP mode.
//
// The session manager is told how to reach the access points
// (interactive.APs): a new session goes to the AP the caller's assignment
// names (kind "interactive", the explicit-target rules every submission
// follows), and an existing one is reached on the AP its record names.
// The four tools themselves run unchanged; every schedd call they make
// goes through the manager, which routes it.

// multiAPInteractiveTools are served in multi-AP mode as they are on a
// single-AP server: the manager routes each call to the session's AP.
var multiAPInteractiveTools = map[string]bool{
	"interactive_session_start": true,
	"interactive_session_exec":  true,
	"interactive_session_list":  true,
	"interactive_session_stop":  true,
}

// interactiveAPs is interactive.APs over this server's AP set.
type interactiveAPs struct{ s *Server }

func (a interactiveAPs) user(caller interactive.Caller) (string, error) {
	return a.s.multi.UserFor(caller.Actor)
}

// Assign is AP assignment for a new session: the caller's home AP, or an
// alternate they name, admitted and identifying the caller as themselves
// there.
func (a interactiveAPs) Assign(ctx context.Context, caller interactive.Caller, explicit string) (string, context.Context, error) {
	user, err := a.user(caller)
	if err != nil {
		return "", nil, err
	}
	m, _, err := a.s.multi.SubmitTarget(ctx, a.s.assignRequest(ctx, user, apassign.KindInteractive), explicit)
	if err != nil {
		return "", nil, err
	}
	routed := multiap.WithTarget(ctx, multiap.Target{Member: m})
	if v := a.s.multi.VerifyCaller; v != nil {
		if err := v(routed, m, user); err != nil {
			return "", nil, err
		}
	}
	return m.Name, routed, nil
}

// Route reaches the AP an existing session is on: the member as the
// registry knows it now, the AP's own verdict on the caller, and the
// identity it reports. Never another AP.
func (a interactiveAPs) Route(ctx context.Context, caller interactive.Caller, ap string) (context.Context, error) {
	user, err := a.user(caller)
	if err != nil {
		return nil, err
	}
	m, err := a.s.multi.Member(ap)
	if err != nil {
		return nil, err
	}
	if err := a.s.multi.AdmitTo(ctx, m, user); err != nil {
		return nil, err
	}
	routed := multiap.WithTarget(ctx, multiap.Target{Member: m})
	if v := a.s.multi.VerifyCaller; v != nil {
		if _, ok := htcondor.GetSecurityConfigFromContext(ctx); ok {
			if err := v(routed, m, user); err != nil {
				return nil, err
			}
		}
	}
	return routed, nil
}

// Locate asks the federation hub where the caller's sessions are.
func (a interactiveAPs) Locate(ctx context.Context, caller interactive.Caller, constraint string, projection []string) ([]interactive.LocatedAd, error) {
	user, err := a.user(caller)
	if err != nil {
		return nil, err
	}
	rows, _, err := a.s.multi.FindOwn(ctx, user, constraint, projection, 0)
	if err != nil {
		return nil, err
	}
	out := make([]interactive.LocatedAd, 0, len(rows))
	for _, r := range rows {
		out = append(out, interactive.LocatedAd{AP: r.ID.Schedd, Ad: r.Ad})
	}
	return out, nil
}

func (a interactiveAPs) JobID(ap string, cluster, proc int) string {
	return a.s.multi.Codec.Format(jobid.ID{Schedd: ap, Cluster: int64(cluster), Proc: int64(proc)})
}

// Wrote keeps a bulk action from skipping the AP on the hub's word until
// the hub has seen the change.
func (a interactiveAPs) Wrote(ap string) { a.s.multi.NoteWrite(ap) }

// multiAPInteractiveToolDef adapts an interactive tool's definition:
// interactive_session_start gains schedd, and every one says where
// sessions live.
func multiAPInteractiveToolDef(t Tool) Tool {
	if !multiAPInteractiveTools[t.Name] {
		return t
	}
	t.Description += " On this server, which fronts several access points, a new session starts on your home access " +
		"point (whoami names it) unless schedd names one of your alternates; an existing session stays on the access " +
		"point it started on, and its name is unique across all of them."
	if t.Name != "interactive_session_start" {
		return t
	}
	schema := maps.Clone(t.InputSchema)
	props, _ := schema["properties"].(map[string]interface{})
	props = maps.Clone(props)
	if props == nil {
		props = map[string]interface{}{}
	}
	props["schedd"] = map[string]interface{}{
		"type": "string",
		"description": "The access point to start the session on, by schedd name. Default: your home access point. " +
			"Only your home access point or one of its alternates is accepted (whoami lists them).",
	}
	schema["properties"] = props
	t.InputSchema = schema
	return t
}
