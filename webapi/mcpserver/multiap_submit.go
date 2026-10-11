package mcpserver

import (
	"context"
	"fmt"
	"maps"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Submission and credentials over MCP in multi-AP mode.
//
// A submitting tool is routed to the AP the caller's assignment names
// (or an allowed explicit schedd), and then runs as it does on a
// single-AP server against that AP: the job, its spooled input and the
// credential bootstrap all land there. Its answer names the AP and
// carries complete job ids, which every later tool call -- the input
// upload above all -- is routed by. Nothing re-assigns.
//
// A credential tool acts on one AP's credd: the caller's home AP's, or
// the one the schedd argument names.

// multiAPSubmitTools place new work, with the kind of work each is.
var multiAPSubmitTools = map[string]string{
	"submit_job":      apassign.KindJob,
	"submit_dag":      apassign.KindDAG,
	"build_container": apassign.KindContainerBuild,
}

// multiAPCredentialTools act on one AP's credd.
var multiAPCredentialTools = map[string]bool{
	"list_service_credentials":  true,
	"get_credential_status":     true,
	"store_service_credential":  true,
	"delete_service_credential": true,
}

var submitScheddArgSchema = map[string]interface{}{
	"type": "string",
	"description": "The access point to submit to, by schedd name. Default: your home access point. " +
		"Only your home access point or one of its alternates is accepted (whoami lists them).",
}

var credentialScheddArgSchema = map[string]interface{}{
	"type": "string",
	"description": "The access point whose credential service to use, by schedd name (list_access_points names them). " +
		"Default: your home access point. Credentials are per access point: a job only sees those stored on its own.",
}

// multiAPSubmitNote is appended to a submitting tool's description.
const multiAPSubmitNote = " On this server, which fronts several access points, the work goes to your home access point " +
	"(whoami names it) unless schedd names one of your alternates; the answer carries the complete job ids to use from then on."

// jobIDText is how a tool's answer names a job: cluster.proc, or in
// multi-AP mode the complete id of the AP the call was routed to.
func (s *Server) jobIDText(ctx context.Context, cluster, proc int64) string {
	if s.multi != nil {
		if t, ok := multiap.TargetFrom(ctx); ok {
			return s.multi.Codec.Format(jobid.ID{Schedd: t.Member.Name, Cluster: cluster, Proc: proc})
		}
	}
	return fmt.Sprintf("%d.%d", cluster, proc)
}

// clusterArgsText is the argument list naming a whole cluster to a tool
// that takes one: job_id="123", plus the schedd in multi-AP mode.
func (s *Server) clusterArgsText(ctx context.Context, cluster int64) string {
	if s.multi != nil {
		if t, ok := multiap.TargetFrom(ctx); ok {
			return fmt.Sprintf("job_id=%q, schedd=%q", fmt.Sprint(cluster), t.Member.Name)
		}
	}
	return fmt.Sprintf("job_id=\"%d\"", cluster)
}

// waitStepText is the submit answer's advice on waiting for a job.
// Watches are not served in multi-AP mode, so it does not recommend them
// there.
func (s *Server) waitStepText() string {
	if s.multi != nil {
		return "To check on the job, call get_job with its complete job_id; job watches are not available on this server."
	}
	return "To wait for the job to finish, register a watch with watch_jobs (event=\"done\") and collect it with " +
		"check_watches — do not poll query_jobs in a loop. The watch fires even if the job has already finished. " +
		"Use query_jobs for a one-off status check."
}

// assignRequest is the assignment question for this call's caller.
func (s *Server) assignRequest(ctx context.Context, user, kind string) apassign.Request {
	c, ok := apassign.CallerFrom(ctx)
	if !ok {
		c.Subject = htcondor.GetAuthenticatedUserFromContext(ctx)
	}
	return apassign.Request{User: user, Subject: c.Subject, Groups: c.Groups, Kind: kind}
}

// multiSubmitTool runs a submitting tool on the AP the caller's
// assignment names.
func (s *Server) multiSubmitTool(ctx context.Context, name, kind string, args map[string]interface{}) (interface{}, error) {
	user, err := s.multiCaller(ctx)
	if err != nil {
		return nil, err
	}
	m, a, err := s.multi.SubmitTarget(ctx, s.assignRequest(ctx, user, kind), stringArg(args, "schedd"))
	if err != nil {
		return nil, err
	}
	ctx = multiap.WithTarget(ctx, multiap.Target{Member: m})
	// The identity the job is owned by is the one this AP reports.
	if s.multi.VerifyCaller != nil {
		if err := s.multi.VerifyCaller(ctx, m, user); err != nil {
			return nil, err
		}
	}
	// Until the hub has seen the new job, a bulk action must not skip
	// this AP on the hub's word.
	s.multi.NoteWrite(m.Name)
	defer s.multi.NoteWrite(m.Name)

	routed := maps.Clone(args)
	delete(routed, "schedd")
	var tool func(context.Context, map[string]interface{}) (interface{}, error)
	switch name {
	case "submit_job":
		tool = s.toolSubmitJob
	case "submit_dag":
		tool = s.toolSubmitDag
	case "build_container":
		tool = s.toolBuildContainer
	default:
		return nil, errMultiAPTool(name)
	}
	result, err := tool(ctx, routed)
	if err != nil {
		return nil, err
	}
	return s.noteSubmitted(result, m.Name, a), nil
}

// noteSubmitted adds where the work went to a submitting tool's answer:
// schedd and the assignment in the structured content, job ids made
// complete, and a line naming the AP in the text.
func (s *Server) noteSubmitted(result interface{}, schedd string, a apassign.Assignment) interface{} {
	m, ok := result.(map[string]interface{})
	if !ok {
		return result
	}
	complete := func(v string) string {
		id, err := s.multi.Codec.Parse(v)
		if err != nil || id.Complete() {
			return v
		}
		return s.multi.Codec.Format(id.WithSchedd(schedd))
	}
	var first string
	for _, key := range []string{"structuredContent", "metadata"} {
		sc, ok := m[key].(map[string]interface{})
		if !ok {
			continue
		}
		sc["schedd"] = schedd
		sc["assignment"] = map[string]interface{}{"schedd": a.Schedd, "alternates": nonNilStrings(a.Alternates), "source": a.Source}
		if v, ok := sc["job_id"].(string); ok && v != "" {
			sc["job_id"] = complete(v)
			first = sc["job_id"].(string)
		}
		if ids, ok := sc["job_ids"].([]string); ok {
			out := make([]string, len(ids))
			for i, v := range ids {
				out[i] = complete(v)
			}
			sc["job_ids"] = out
			if len(out) > 0 {
				first = out[0]
			}
		}
	}
	if content, ok := m["content"].([]map[string]interface{}); ok && len(content) > 0 {
		if t, ok := content[0]["text"].(string); ok {
			line := fmt.Sprintf("\n[submitted to access point %s", schedd)
			if a.Source != "" {
				line += fmt.Sprintf(", from your %s access point assignment", a.Source)
			}
			if first != "" {
				line += fmt.Sprintf("; name this job as %s in other tools, since a bare cluster.proc is refused here", first)
			}
			content[0]["text"] = t + line + "]"
		}
	}
	return m
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// multiCredentialTool runs a credential tool against one AP's credd.
func (s *Server) multiCredentialTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	user, err := s.multiCaller(ctx)
	if err != nil {
		return nil, err
	}
	m, err := s.multi.CredentialTarget(ctx, s.assignRequest(ctx, user, apassign.KindJob), stringArg(args, "schedd"))
	if err != nil {
		return nil, err
	}
	ctx = multiap.WithTarget(ctx, multiap.Target{Member: m})
	if s.getCreddFor(ctx) == nil {
		return nil, fmt.Errorf("access point %s advertises no credential service (credd)", m.Name)
	}
	routed := maps.Clone(args)
	delete(routed, "schedd")
	var tool func(context.Context, map[string]interface{}) (interface{}, error)
	switch name {
	case "list_service_credentials":
		tool = s.toolListServiceCredentials
	case "get_credential_status":
		tool = s.toolGetCredentialStatus
	case "store_service_credential":
		tool = s.toolStoreServiceCredential
	case "delete_service_credential":
		tool = s.toolDeleteServiceCredential
	default:
		return nil, errMultiAPTool(name)
	}
	result, err := tool(ctx, routed)
	if err != nil {
		return nil, err
	}
	return noteCredentialAP(result, m), nil
}

// noteCredentialAP names the AP whose credd a credential tool used.
func noteCredentialAP(result interface{}, m apregistry.Member) interface{} {
	r, ok := result.(map[string]interface{})
	if !ok {
		return result
	}
	for _, key := range []string{"structuredContent", "metadata"} {
		if sc, ok := r[key].(map[string]interface{}); ok {
			sc["schedd"] = m.Name
		}
	}
	if content, ok := r["content"].([]map[string]interface{}); ok && len(content) > 0 {
		if t, ok := content[0]["text"].(string); ok {
			content[0]["text"] = t + fmt.Sprintf("\n[credential service of access point %s]", m.Name)
		}
	}
	return r
}

// multiAPSubmitToolDef adapts a submitting or credential tool's
// definition: the schedd argument, and what it means here.
func multiAPSubmitToolDef(t Tool) Tool {
	var arg map[string]interface{}
	switch {
	case multiAPSubmitTools[t.Name] != "":
		t.Description += multiAPSubmitNote
		arg = submitScheddArgSchema
	case multiAPCredentialTools[t.Name]:
		t.Description += " On this server each access point has its own credential service; this uses your home " +
			"access point's unless schedd names another."
		arg = credentialScheddArgSchema
	default:
		return t
	}
	schema := maps.Clone(t.InputSchema)
	props, _ := schema["properties"].(map[string]interface{})
	props = maps.Clone(props)
	if props == nil {
		props = map[string]interface{}{}
	}
	props["schedd"] = arg
	schema["properties"] = props
	t.InputSchema = schema
	return t
}

// multiHomeAP reports the caller's assignment, for whoami.
func (s *Server) multiHomeAP(ctx context.Context) (apassign.Assignment, error) {
	user, err := s.multiCaller(ctx)
	if err != nil {
		return apassign.Assignment{}, err
	}
	return s.multi.Assignment(ctx, s.assignRequest(ctx, user, apassign.KindJob))
}
