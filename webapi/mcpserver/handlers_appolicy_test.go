package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/appolicy"
)

// policyAPs stands in for the schedds a policy is read from: one map of
// knobs per access point, a count of reads, and the AP each call was
// routed to.
type policyAPs struct {
	mu     sync.Mutex
	values map[string]map[string]string
	down   bool
	reads  atomic.Int64
	routed []string
}

type policyAPSource struct {
	aps *policyAPs
	ap  string
}

func (p policyAPSource) ConfigVal(_ context.Context, name string) (string, bool, error) {
	p.aps.reads.Add(1)
	p.aps.mu.Lock()
	defer p.aps.mu.Unlock()
	if p.aps.down {
		return "", false, errors.New("connection refused")
	}
	v, ok := p.aps.values[p.ap][strings.ToUpper(name)]
	return v, ok, nil
}

// source is a Server.policySourceFn: the routed AP in multi-AP mode,
// otherwise the one access point "ap.example.org".
func (p *policyAPs) source(ctx context.Context) (appolicy.ConfigSource, string) {
	ap := routedSchedd(ctx)
	if ap == "" {
		ap = "ap.example.org"
	}
	p.mu.Lock()
	p.routed = append(p.routed, ap)
	p.mu.Unlock()
	return policyAPSource{aps: p, ap: ap}, ap
}

func policyServer(t *testing.T, values map[string]string) (*Server, *policyAPs) {
	t.Helper()
	aps := &policyAPs{values: map[string]map[string]string{"ap.example.org": upperKeys(values)}}
	s := contractServer(t)
	s.apPolicy = appolicy.NewCache()
	s.policySourceFn = aps.source
	return s, aps
}

func upperKeys(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[strings.ToUpper(k)] = v
	}
	return out
}

func callPolicy(ctx context.Context, t *testing.T, s *Server, args map[string]any) (interface{}, error) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": "get_access_point_policy", "arguments": args})
	return s.handleCallTool(ctx, params)
}

// The answer through the dispatcher, converted as the SDK transport
// converts it: one text block, and structuredContent that satisfies the
// published schema.
func TestAccessPointPolicyResultShape(t *testing.T) {
	s, _ := policyServer(t, map[string]string{
		"MAX_JOBS_PER_SUBMISSION":          "5000",
		"SUBMIT_REQUIREMENT_NAMES":         "MinMem",
		"SUBMIT_REQUIREMENT_MinMem":        "RequestMemory >= 512",
		"SUBMIT_REQUIREMENT_MinMem_REASON": `"Ask for at least 512 MB"`,
		"JOB_DEFAULT_REQUESTMEMORY":        "128",
		"SCHEDD_ALLOW_LATE_MATERIALIZE":    "true",
		"JOB_EPOCH_HISTORY":                "/var/lib/condor/spool/epoch_history",
		"SYSTEM_PERIODIC_HOLD":             "JobStatus == 2 && time() - JobCurrentStartDate > 86400",
		"SYSTEM_PERIODIC_HOLD_REASON":      `"Over the 24 hour runtime limit"`,
		"DAGMAN_MAX_JOBS_IDLE":             "1000",
	})
	res, err := callPolicy(context.Background(), t, s, map[string]any{})
	if err != nil {
		t.Fatalf("get_access_point_policy: %v", err)
	}

	text := skillResultText(t, res)
	for _, want := range []string{
		"Policy of access point ap.example.org",
		"- MAX_JOBS_PER_SUBMISSION = 5000 [site]: One submission",
		`A job is refused with the message "Ask for at least 512 MB" unless ` + "`RequestMemory >= 512`",
		`with the reason "Over the 24 hour runtime limit"`,
		"## Resource requests of a job that omits request_*",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "/var/lib/condor") {
		t.Error("the epoch history path reached the answer")
	}

	out, err := toSDKResult(res)
	if err != nil {
		t.Fatal(err)
	}
	if out.StructuredContent == nil {
		t.Fatal("no structuredContent")
	}
	validateStructured(t, "get_access_point_policy", out.StructuredContent)
	sc, _ := out.StructuredContent.(map[string]any)
	if sc["access_point"] != "ap.example.org" || sc["fetched_at"] == "" {
		t.Errorf("structured header = %v / %v", sc["access_point"], sc["fetched_at"])
	}
	groups, _ := sc["groups"].([]any)
	if len(groups) != 8 {
		t.Errorf("%d groups, want 8", len(groups))
	}
}

// The catalogue offers the tool read-only, with its schema, to a token
// that may only read.
func TestAccessPointPolicyIsAReadTool(t *testing.T) {
	if !IsReadOnlyTool("get_access_point_policy") {
		t.Error("get_access_point_policy is not classified read-only")
	}
	tools := (&Server{}).toolsFor(WithGrantedScopes(context.Background(), []string{"mcp:read"}))
	for _, tool := range tools {
		if tool.Name == "get_access_point_policy" {
			if tool.OutputSchema == nil || tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				t.Errorf("served without schema or read-only annotation: %+v", tool)
			}
			return
		}
	}
	t.Error("a read-only grant is not offered get_access_point_policy")
}

// Repeated calls are answered from one reading.
func TestAccessPointPolicyIsCached(t *testing.T) {
	s, aps := policyServer(t, map[string]string{"MAX_JOBS_PER_OWNER": "10"})
	if _, err := callPolicy(context.Background(), t, s, nil); err != nil {
		t.Fatal(err)
	}
	once := aps.reads.Load()
	for i := 0; i < 3; i++ {
		if _, err := callPolicy(context.Background(), t, s, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := aps.reads.Load(); n != once {
		t.Errorf("%d reads after four calls, want one reading's %d", n, once)
	}
}

// A schedd that cannot be reached at all is an error the caller sees;
// the tool does not invent a policy.
func TestAccessPointPolicyUnreachable(t *testing.T) {
	s, aps := policyServer(t, nil)
	aps.down = true
	_, err := callPolicy(context.Background(), t, s, nil)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v", err)
	}
}

// In multi-AP mode the tool describes the caller's home AP, or the one
// schedd names, and refuses one outside the set.
func TestMultiAPAccessPointPolicyFollowsTheAP(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d "+mAP2+"\n")
	aps := &policyAPs{values: map[string]map[string]string{
		mAP1: {"MAX_JOBS_PER_SUBMISSION": "100"},
		mAP2: {"MAX_JOBS_PER_SUBMISSION": "200"},
		mAP3: {"MAX_JOBS_PER_SUBMISSION": "300"},
	}}
	a.srv.policySourceFn = aps.source
	ctx := callerCtx(t)

	perEntry := func(sc map[string]any) string {
		groups, _ := sc["groups"].([]any)
		for _, g := range groups {
			for _, e := range g.(map[string]any)["entries"].([]any) {
				if e.(map[string]any)["name"] == "MAX_JOBS_PER_SUBMISSION" {
					return e.(map[string]any)["value"].(string)
				}
			}
		}
		return ""
	}

	sc, err := a.call(ctx, t, "get_access_point_policy", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if sc["schedd"] != mAP2 || sc["access_point"] != mAP2 || perEntry(sc) != "200" {
		t.Errorf("home AP answer: schedd=%v access_point=%v value=%v", sc["schedd"], sc["access_point"], perEntry(sc))
	}
	sc, err = a.call(ctx, t, "get_access_point_policy", map[string]any{"schedd": mAP3})
	if err != nil {
		t.Fatal(err)
	}
	if sc["schedd"] != mAP3 || perEntry(sc) != "300" {
		t.Errorf("explicit AP answer: schedd=%v value=%v", sc["schedd"], perEntry(sc))
	}
	if _, err := a.call(ctx, t, "get_access_point_policy", map[string]any{"schedd": "nowhere.example.org"}); err == nil {
		t.Error("described an AP outside the set")
	}
	for _, ap := range aps.routed {
		if ap != mAP2 && ap != mAP3 {
			t.Errorf("read the policy of %q", ap)
		}
	}
	if n := a.srv.MultiAPScheddCalls(); n != 0 {
		t.Errorf("the single-schedd accessor was reached %d times", n)
	}

	var def *Tool
	for _, tool := range a.srv.toolsFor(ctx) {
		if tool.Name == "get_access_point_policy" {
			tool := tool
			def = &tool
		}
	}
	if def == nil {
		t.Fatal("the multi-AP catalogue does not offer get_access_point_policy")
	}
	if props, _ := def.InputSchema["properties"].(map[string]interface{}); props["schedd"] == nil {
		t.Error("the multi-AP definition takes no schedd argument")
	}
}

// What submission uses is what the tool reports: the request defaults
// come from the same reading, and a job built with them carries them.
func TestSubmitDefaultsComeFromTheAccessPoint(t *testing.T) {
	s, aps := policyServer(t, map[string]string{
		"MAX_JOBS_PER_SUBMISSION":   "20000",
		"JOB_DEFAULT_REQUESTMEMORY": "2GB",
		"JOB_DEFAULT_REQUESTCPUS":   "1",
		"JOB_DEFAULT_REQUESTDISK":   "4GB",
	})
	local := config.NewEmpty()
	local.Set("JOB_DEFAULT_REQUESTMEMORY", "999")
	s.htcondorConfig = local

	ctx := s.withSubmitDefaults(context.Background())
	params := htcondor.SubmitParamsFromContext(ctx)
	if params == nil {
		t.Fatal("the submit context carries no request defaults")
	}
	sf, err := htcondor.ParseSubmitFileWithOptions(strings.NewReader("executable = /bin/true\nqueue\n"),
		htcondor.SubmitParseOptions{Params: params})
	if err != nil {
		t.Fatal(err)
	}
	ad, err := sf.MakeJobAd(htcondor.JobID{Cluster: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := ad.EvaluateAttrInt("RequestMemory"); v != 2048 {
		t.Errorf("RequestMemory = %d, want the access point's 2048", v)
	}
	if v, _ := ad.EvaluateAttrInt("RequestDisk"); v != 4*1024*1024 {
		t.Errorf("RequestDisk = %d, want the access point's 4 GiB", v)
	}

	reads := aps.reads.Load()
	res, err := callPolicy(context.Background(), t, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if aps.reads.Load() != reads {
		t.Error("the tool read the schedd again instead of the reading submission used")
	}
	if text := skillResultText(t, res); !strings.Contains(text, "- JOB_DEFAULT_REQUESTMEMORY = 2GB [site]") {
		t.Errorf("the tool does not report the value submission used:\n%s", text)
	}
}

// When the schedd cannot be asked, a submission goes ahead with this
// server's configuration.
func TestSubmitDefaultsFallBackToLocalConfig(t *testing.T) {
	s, aps := policyServer(t, nil)
	aps.down = true
	local := config.NewEmpty()
	local.Set("JOB_DEFAULT_REQUESTMEMORY", "999")
	s.htcondorConfig = local

	params := htcondor.SubmitParamsFromContext(s.withSubmitDefaults(context.Background()))
	if v, ok := params.Get("JOB_DEFAULT_REQUESTMEMORY"); v != "999" || !ok {
		t.Errorf("JOB_DEFAULT_REQUESTMEMORY = %q, %v; want the local 999", v, ok)
	}
}

// The interactive sessions this server starts take the same defaults.
func TestInteractiveSessionsTakeSubmitDefaults(t *testing.T) {
	srv, err := NewServer(Config{Schedd: htcondor.NewSchedd("ap.example.org", "<127.0.0.1:1>")})
	if err != nil {
		t.Fatal(err)
	}
	if !srv.InteractiveManager().HasSubmitContextForTest() {
		t.Error("the interactive manager was built without the submit defaults hook")
	}
}
