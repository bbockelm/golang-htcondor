package mcpserver

import (
	"context"
	"fmt"
	"maps"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/appolicy"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// get_access_point_policy: the access point's own rules, for an agent
// that cannot read its configuration.
//
// Without it an agent meets each rule by breaking it: a submission over
// MAX_JOBS_PER_SUBMISSION refused whole, a job missing an attribute some
// SUBMIT_REQUIREMENT insists on, a job held at a runtime cap by
// SYSTEM_PERIODIC_HOLD. The values come from the schedd, through the
// cache every submission takes its request defaults from, so what this
// reports and what submit_job does cannot disagree.

func accessPointPolicyTool() Tool {
	return Tool{
		Name: "get_access_point_policy",
		Description: "Report this access point's rules for jobs, as its schedd is configured: how many jobs one submission " +
			"and one user may have, the submit requirements that refuse jobs (with their messages), the transforms that " +
			"change jobs at submit, what a job that omits request_cpus/request_memory/request_disk/request_gpus gets, the " +
			"system policies that hold, remove or release jobs (with their reasons), file transfer limits, DAGMan " +
			"throttles, and whether late materialization, ssh into jobs, epoch history and token services are available. " +
			"Each value says whether this site changed it from HTCondor's default. " +
			"Call it before a large submission, and when a job is refused at submit or held by a policy you did not write.",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	}
}

// policyScheddArgSchema is get_access_point_policy's schedd argument in
// multi-AP mode.
var policyScheddArgSchema = map[string]interface{}{
	"type": "string",
	"description": "The access point to describe, by schedd name (list_access_points names them). " +
		"Default: your home access point. Each access point has its own policy.",
}

// multiAPPolicyToolDef adds the schedd argument in multi-AP mode.
func multiAPPolicyToolDef(t Tool) Tool {
	if t.Name != "get_access_point_policy" {
		return t
	}
	t.Description += " On this server, which fronts several access points, it describes your home access point " +
		"unless schedd names another."
	schema := maps.Clone(t.InputSchema)
	props, _ := schema["properties"].(map[string]interface{})
	props = maps.Clone(props)
	if props == nil {
		props = map[string]interface{}{}
	}
	props["schedd"] = policyScheddArgSchema
	schema["properties"] = props
	t.InputSchema = schema
	return t
}

// policySource is the schedd a call's policy is read from, and the name
// it is cached and reported under. In multi-AP mode that is the AP the
// call was routed to.
func (s *Server) policySource(ctx context.Context) (appolicy.ConfigSource, string) {
	if s.policySourceFn != nil {
		return s.policySourceFn(ctx)
	}
	schedd := s.scheddFor(ctx)
	if schedd == nil {
		return nil, ""
	}
	name := routedSchedd(ctx)
	if name == "" {
		name = schedd.Name()
	}
	if name == "" {
		name = schedd.Address()
	}
	return schedd, name
}

// toolGetAccessPointPolicy implements get_access_point_policy.
func (s *Server) toolGetAccessPointPolicy(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	src, name := s.policySource(ctx)
	if src == nil {
		return nil, fmt.Errorf("get_access_point_policy needs a schedd, and this server has none configured")
	}
	snap, err := s.apPolicy.Get(ctx, name, src)
	if err != nil {
		return nil, err
	}
	report := appolicy.Render(snap, appolicy.RenderOptions{DagmanEnv: s.dagmanEnv})
	return structuredTextResult(report.Text(s.apPolicy.TTL()), report.Structured()), nil
}

// multiAPPolicyTool routes get_access_point_policy to one AP: the
// caller's home AP, or the one schedd names. Any AP the caller may use
// can be described, as with the credential tools.
func (s *Server) multiAPPolicyTool(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	user, err := s.multiCaller(ctx)
	if err != nil {
		return nil, err
	}
	m, err := s.multi.CredentialTarget(ctx, s.assignRequest(ctx, user, apassign.KindJob), stringArg(args, "schedd"))
	if err != nil {
		return nil, err
	}
	ctx = multiap.WithTarget(ctx, multiap.Target{Member: m})
	routed := maps.Clone(args)
	delete(routed, "schedd")
	result, err := s.toolGetAccessPointPolicy(ctx, routed)
	if err != nil {
		return nil, err
	}
	if r, ok := result.(map[string]interface{}); ok {
		if sc, ok := r["structuredContent"].(map[string]interface{}); ok {
			sc["schedd"] = m.Name
		}
	}
	return result, nil
}

// withSubmitDefaults returns ctx carrying the JOB_DEFAULT_REQUEST* values
// of the access point the submission goes to, read through the same cache
// get_access_point_policy reports from. When that schedd cannot be asked,
// this server's own configuration and then HTCondor's built-in defaults
// apply: the lookup is a convenience, and a submission is never refused
// because it failed.
func (s *Server) withSubmitDefaults(ctx context.Context) context.Context {
	src, name := s.policySource(ctx)
	out, err := s.apPolicy.SubmitContext(ctx, name, src, s.htcondorConfig)
	if err != nil && s.logger != nil {
		s.logger.Warn(logging.DestinationMCP,
			"could not read the access point's request defaults; submitting with this server's",
			"access_point", name, "error", err)
	}
	return out
}
