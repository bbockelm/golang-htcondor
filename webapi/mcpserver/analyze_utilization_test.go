package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

func TestParseUtilizationArgs(t *testing.T) {
	a, err := parseUtilizationArgs(map[string]interface{}{}, 1000000)
	if err != nil || a.days != 7 || a.limit != utilizationToolDefaultLimit {
		t.Fatalf("defaults: %+v %v", a, err)
	}

	for name, args := range map[string]map[string]interface{}{
		"days outside 1/7/30":      {"days": float64(14)},
		"fractional days":          {"days": 7.5},
		"days as text":             {"days": "7"},
		"unparseable":              {"constraint": "Owner == "},
		"zero limit":               {"limit": float64(0)},
		"fractional limit":         {"limit": 2.5},
		"owners of the wrong type": {"owners": float64(3)},
		"owners with a non-name":   {"owners": []interface{}{"alice", 7.0}},
	} {
		if _, err := parseUtilizationArgs(args, 1000000); err == nil {
			t.Errorf("%s: accepted %v", name, args)
		}
	}

	a, err = parseUtilizationArgs(map[string]interface{}{
		"days": float64(30), "limit": float64(5000000),
		"owners":     []interface{}{" bob", "alice", "bob", ""},
		"constraint": `JobBatchName == "sweep"`,
	}, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	if a.days != 30 || a.limit != 1000000 {
		t.Errorf("days %d, limit %d: want 30 and the ceiling", a.days, a.limit)
	}
	if strings.Join(a.owners, ",") != "alice,bob" {
		t.Errorf("owners %v, want sorted and distinct", a.owners)
	}
	// A comma-separated string is accepted too.
	a, _ = parseUtilizationArgs(map[string]interface{}{"owners": "carol, dave"}, 1000000)
	if strings.Join(a.owners, ",") != "carol,dave" {
		t.Errorf("owners from a string: %v", a.owners)
	}
}

// The selection can only narrow the caller's scope: a constraint is
// ANDed on after being re-serialized, so an attempt to close the scope's
// parentheses early is refused, and naming another user narrows "mine"
// to nothing rather than widening it to theirs.
func TestUtilizationSelectionCannotWidenTheScope(t *testing.T) {
	if _, err := parseUtilizationArgs(map[string]interface{}{"constraint": `true) || (true`}, 1000000); err == nil {
		t.Fatal("an unbalanced constraint that would escape the scope was accepted")
	}
	a, err := parseUtilizationArgs(map[string]interface{}{
		"owners": []interface{}{"bob"}, "constraint": `RequestGpus > 0 || true`,
	}, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	sel := utilizationSelection(`Owner == "alice"`, a)
	for _, ad := range []string{
		`[Owner = "bob"; RequestGpus = 1]`,
		`[Owner = "carol"; RequestGpus = 1]`,
	} {
		if matches(t, sel, ad) {
			t.Errorf("alice's selection %q matched someone else's job %s", sel, ad)
		}
	}
	a.owners = nil
	if !matches(t, utilizationSelection(`Owner == "alice"`, a), `[Owner = "alice"; RequestGpus = 0]`) {
		t.Error("alice's own job did not match her selection")
	}
}

func matches(t *testing.T, constraint, ad string) bool {
	t.Helper()
	expr, err := classad.ParseExpr(constraint)
	if err != nil {
		t.Fatalf("selection does not parse: %q: %v", constraint, err)
	}
	parsed, err := classad.Parse(ad)
	if err != nil {
		t.Fatal(err)
	}
	v := parsed.EvaluateExprWithTarget(expr, nil)
	b, ok := v.BoolValue()
	return ok == nil && b
}

// A user with hundreds of workflows still gets an answer that fits: the
// text stays under its stated bound, says how much it left out, and the
// structured content is cut the same way.
func TestRenderUtilizationIsBounded(t *testing.T) {
	resp := &utilization.Response{Days: 30, JobsConsidered: 90000, Limit: 50000, MaxLimit: 1000000, Truncated: true}
	resp.Overall = utilization.Overall{Jobs: 90000, WallHours: 120000}
	for i := 0; i < 300; i++ {
		w := utilization.Workflow{
			Key: fmt.Sprintf("k%03d", i), Name: fmt.Sprintf("workflow-%03d", i), Executable: "run.sh",
			Jobs: 300, WallHours: float64(1000 - i),
		}
		for _, r := range []string{utilization.ResourceMemory, utilization.ResourceCPU} {
			w.Advice = append(w.Advice, utilization.Advice{
				ID: r, Resource: r, Severity: utilization.SeveritySuggest,
				Title: "Request less " + r, Detail: strings.Repeat("Most jobs used far less than they asked for. ", 3),
				Submit:     []string{"request_memory = 2 GB", "retry_request_memory = 4 GB"},
				Saves:      &utilization.Savings{Unit: utilization.UnitGiBHours, Amount: 1234},
				Confidence: "high",
			})
		}
		resp.Workflows = append(resp.Workflows, w)
	}
	text, sc := RenderUtilization(utilization.Summarize(resp), DetailFromResponse(resp), UtilizationView{})
	if len(text) > UtilizationTextLimit {
		t.Fatalf("text is %d bytes, over the %d bound", len(text), UtilizationTextLimit)
	}
	if !strings.Contains(text, "more suggestion(s) not shown") || !strings.Contains(text, "limited to 16 KiB") {
		t.Error("the text does not say how many suggestions it left out, or what the bound is")
	}
	if !strings.Contains(text, "Only the most recent 90,000 jobs") {
		t.Error("the text does not say the window held more jobs than were analysed")
	}
	if n := len(sc["workflows"].([]map[string]interface{})); n != utilizationTopWorkflows {
		t.Errorf("%d workflows in the structured content, want the top %d", n, utilizationTopWorkflows)
	}
	shown := len(sc["advice"].([]map[string]interface{}))
	if total := sc["advice_total"].(int); total != 600 || shown >= total || shown == 0 {
		t.Errorf("advice: %d shown of %d; want some, not all, of 600", shown, total)
	}
	// The longest-running workflow leads.
	if !strings.Contains(text, "workflow-000 -- key k000") {
		t.Error("the top workflow is not in the answer")
	}
}

// Asking for one workflow adds its distributions as percentiles and its
// own suggestions, and finds it by part of its name.
func TestRenderUtilizationOneWorkflow(t *testing.T) {
	d := &utilization.Distribution{N: 40, P10: 600, P50: 1800, P90: 3600, P95: 4000, Max: 7200}
	mem := &utilization.Distribution{N: 40, P10: 300, P50: 900, P90: 1500, P95: 1700, Max: 2100}
	resp := &utilization.Response{Days: 7, Overall: utilization.Overall{Jobs: 40, WallHours: 20}}
	resp.Workflows = []utilization.Workflow{
		{Key: "a", Name: "align-genomes", Executable: "bwa", Jobs: 40, WallHours: 20, Wall: d,
			Memory: utilization.MemoryStats{PeakMiB: mem, Request: &utilization.Request{Typical: 4096}},
			Advice: []utilization.Advice{{Resource: "memory", Severity: "suggest", Title: "Request less memory",
				Submit: []string{"request_memory = 2 GB"}, Confidence: "high"}}},
		{Key: "b", Name: "plot", Executable: "plot.py", Jobs: 3, WallHours: 1},
	}
	text, sc := RenderUtilization(utilization.Summarize(resp), DetailFromResponse(resp), UtilizationView{Workflow: "genome"})
	for _, want := range []string{"align-genomes", "run time: 10m / 30m / 1h00m / 1h06m / 2h00m (n=40)",
		"peak memory: 300 MiB / 900 MiB / 1.5 GiB / 1.7 GiB / 2.1 GiB (n=40)", "request_memory = 2 GB"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "plot") {
		t.Error("the other workflow appears in a one-workflow answer")
	}
	w := sc["workflows"].([]map[string]interface{})
	if len(w) != 1 || w[0]["distributions"].(map[string]interface{})["memory_peak_mib"] == nil {
		t.Errorf("structured workflow detail: %v", w)
	}

	text, _ = RenderUtilization(utilization.Summarize(resp), DetailFromResponse(resp), UtilizationView{Workflow: "nothing-like-this"})
	if !strings.Contains(text, `No workflow matches "nothing-like-this"`) {
		t.Errorf("an unmatched workflow is not reported: %s", text)
	}
}

// utilizationAd is a finished job as history records it.
func utilizationAd(cluster int, owner string, now int64, memReq, memUsed int64) *classad.ClassAd {
	ad := fakeschedd.JobAd(cluster, 0, owner, 4)
	ad.InsertAttr("EnteredHistoryTime", now-3600)
	ad.InsertAttr("CompletionDate", now-3600)
	ad.InsertAttr("QDate", now-9000)
	ad.InsertAttr("JobStartDate", now-7200)
	ad.InsertAttr("JobUniverse", 5)
	ad.InsertAttr("ExitCode", 0)
	ad.InsertAttrString("Cmd", "/home/"+owner+"/simulate.sh")
	ad.InsertAttrString("JobBatchName", owner+"-sweep")
	ad.InsertAttr("RequestCpus", 1)
	ad.InsertAttr("RequestMemory", memReq)
	ad.InsertAttr("MemoryUsage", memUsed)
	ad.InsertAttr("RequestDisk", 1048576)
	ad.InsertAttr("DiskUsage", 102400)
	ad.InsertAttr("RemoteWallClockTime", 3600)
	ad.InsertAttr("RemoteUserCpu", 3000)
	ad.InsertAttr("RemoteSysCpu", 100)
	ad.InsertAttr("NumJobStarts", 1)
	return ad
}

// utilizationCall runs analyze_utilization through the server's tool-call
// path and returns its text and structured content.
func utilizationCall(ctx context.Context, t *testing.T, s *Server, args map[string]interface{}) (string, map[string]interface{}) {
	t.Helper()
	params, err := json.Marshal(map[string]interface{}{"name": "analyze_utilization", "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp := s.HandleMessage(ctx, &MCPMessage{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params})
	if resp.Error != nil {
		t.Fatalf("protocol error %v", resp.Error)
	}
	var parsed struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Structured map[string]interface{} `json:"structuredContent"`
		IsError    bool                   `json:"isError"`
	}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	var text strings.Builder
	for _, c := range parsed.Content {
		text.WriteString(c.Text)
	}
	if parsed.IsError {
		t.Fatalf("tool failed: %s", text.String())
	}
	return text.String(), parsed.Structured
}

// Through the server against a schedd's history: alice sees her own jobs
// only, naming bob gets her nothing, and an MCP admin can name him.
func TestAnalyzeUtilizationOverMCPIsOwnerScoped(t *testing.T) {
	f := newActionScopeFixture(t)
	now := time.Now().Unix()
	// alice asks for 8 GiB and peaks under 1; bob's jobs are sized right.
	var ads []*classad.ClassAd
	for i := 0; i < 30; i++ {
		ads = append(ads, utilizationAd(100+i, "alice", now, 8192, 700+int64(i)*5))
		ads = append(ads, utilizationAd(200+i, "bob", now, 1024, 900))
	}
	f.schedd.AddHistory(ads...)

	alice := f.as(t, "alice", "mcp:read")
	text, sc := utilizationCall(alice, t, f.server, map[string]interface{}{"days": float64(1)})
	if got := sc["jobs_considered"]; got != float64(30) {
		t.Fatalf("alice's analysis read %v jobs, want her 30:\n%s", got, text)
	}
	t.Logf("alice's answer:\n%s", text)
	if !strings.Contains(text, "alice-sweep") || strings.Contains(text, "bob-sweep") {
		t.Errorf("alice's answer is not only her workflow:\n%s", text)
	}
	if !strings.Contains(text, "request_memory") {
		t.Errorf("no memory suggestion for jobs using a tenth of their request:\n%s", text)
	}
	if !strings.Contains(text, `[scope: only jobs owned by "alice"]`) {
		t.Errorf("the answer does not say whose jobs it covers:\n%s", text)
	}

	// Naming bob narrows alice's own jobs to none -- it does not widen.
	text, sc = utilizationCall(alice, t, f.server, map[string]interface{}{"days": float64(1), "owners": []interface{}{"bob"}})
	if got := sc["jobs_considered"]; got != float64(0) {
		t.Fatalf("alice naming bob read %v jobs, want none:\n%s", got, text)
	}
	if !strings.Contains(text, `the owner "bob" matches nothing`) {
		t.Errorf("alice is not told why naming bob found nothing:\n%s", text)
	}

	admin := f.as(t, "admin", "mcp:read", "mcp:admin")
	text, sc = utilizationCall(admin, t, f.server, map[string]interface{}{"days": float64(1), "owners": []interface{}{"bob"}})
	if got := sc["jobs_considered"]; got != float64(30) {
		t.Fatalf("an admin naming bob read %v jobs, want his 30:\n%s", got, text)
	}
	if !strings.Contains(text, "bob-sweep") || strings.Contains(text, "alice-sweep") {
		t.Errorf("the admin's answer for bob is not bob's:\n%s", text)
	}

	// One workflow in detail, by part of its name.
	text, _ = utilizationCall(alice, t, f.server, map[string]interface{}{"days": float64(1), "workflow": "sweep"})
	if !strings.Contains(text, "peak memory: ") || !strings.Contains(text, "(n=30)") {
		t.Errorf("no percentiles in the one-workflow answer:\n%s", text)
	}
}

// A request written as a formula over the job's usage is described by
// where it starts and when it grows, not as a fixed number.
func TestRenderUtilizationAdaptiveRequest(t *testing.T) {
	expr := "ifThenElse(MemoryUsage isnt undefined, max({2048, 3 * MemoryUsage / 2}), 2048)"
	resp := &utilization.Response{Days: 7, Overall: utilization.Overall{Jobs: 30, WallHours: 10}}
	resp.Workflows = []utilization.Workflow{{
		Key: "a", Name: "grow", Executable: "grow.sh", Jobs: 30, WallHours: 10,
		Memory: utilization.MemoryStats{Request: &utilization.Request{Typical: 2048, Adaptive: true, Expression: expr}},
		CPU:    utilization.CPUStats{Request: &utilization.Request{Typical: 1}},
	}}
	sum := utilization.Summarize(resp)
	text, _ := RenderUtilization(sum, DetailFromResponse(resp), UtilizationView{})
	if !strings.Contains(text, "memory request starts at 2.0 GiB and grows after a memory hold") {
		t.Errorf("the workflow line does not say the request is a formula:\n%s", text)
	}
	text, _ = RenderUtilization(sum, DetailFromResponse(resp), UtilizationView{Workflow: "grow"})
	for _, want := range []string{"memory starts at 2.0 GiB and grows after a memory hold", "CPUs 1", "RequestMemory = " + expr} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}

// Rendering from the compact form alone still lists every suggestion's
// title, savings and confidence when a workflow's detail cannot be read.
func TestRenderUtilizationWithoutDetail(t *testing.T) {
	resp := &utilization.Response{Days: 7, Overall: utilization.Overall{Jobs: 30, WallHours: 10}}
	resp.Workflows = []utilization.Workflow{{
		Key: "a", Name: "sweep", Executable: "run.sh", Jobs: 30, WallHours: 10,
		Advice: []utilization.Advice{{ID: "memory", Resource: "memory", Severity: "suggest", Title: "Request 1 GB of memory",
			Submit: []string{"request_memory = 1 GB"}, Confidence: "medium"}},
	}}
	none := func(string) (*utilization.Workflow, bool) { return nil, false }
	text, sc := RenderUtilization(utilization.Summarize(resp), none, UtilizationView{})
	if !strings.Contains(text, "sweep -- Request 1 GB of memory") || !strings.Contains(text, "Confidence medium") {
		t.Errorf("the suggestion is missing without its detail:\n%s", text)
	}
	if len(sc["advice"].([]map[string]interface{})) != 1 {
		t.Errorf("structured advice: %v", sc["advice"])
	}
}
