package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
	"github.com/bbockelm/golang-htcondor/webapi/issues"
)

// gpuHeldAd is a job held a minute ago. gpus > 0 sets RequestGPUs; zero
// leaves it undefined, as on a job that never asked for a GPU.
func gpuHeldAd(cluster int, owner string, gpus int, reason string) *classad.ClassAd {
	ad := fakeschedd.JobAd(cluster, 0, owner, 5)
	ad.InsertAttrString("HoldReason", reason)
	ad.InsertAttr("HoldReasonCode", int64(34))
	ad.InsertAttr("HoldReasonSubCode", int64(0))
	ad.InsertAttr("EnteredCurrentStatus", time.Now().Add(-time.Minute).Unix())
	if gpus > 0 {
		ad.InsertAttr("RequestGPUs", int64(gpus))
	}
	return ad
}

// issuesFixture is the two-owner schedd plus held jobs: alice's 31.0
// (asked for a GPU) and 32.0 (did not), and bob's 33.0 (asked for one).
func issuesFixture(t *testing.T) *twoOwnerFixture {
	t.Helper()
	f := twoOwnerScheddServer(t)
	// Three unrelated reasons, so each is its own problem and every job is
	// an example the answer names.
	f.schedd.AddJobs(
		gpuHeldAd(31, "alice", 1, "Error from slot1@node: Job has gone over memory limit of 2048 megabytes."),
		gpuHeldAd(32, "alice", 0, "Transfer input files failure at access point"),
		gpuHeldAd(33, "bob", 2, "Failed to execute '/home/bob/run.sh': permission denied (errno 13) while starting the job on the execute point"),
	)
	return f
}

// chatIssues runs the chat's analyze_issues as who would from the page.
func chatIssues(t *testing.T, f *twoOwnerFixture, who, args string, groups ...string) (map[string]any, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/chat", nil)
	f.session(t, who, groups...)(req)
	authCtx, _, err := f.s.requireAuthentication(req)
	if err != nil {
		t.Fatalf("authenticating %s: %v", who, err)
	}
	for _, tool := range f.s.buildChatTools() {
		if tool.Name() != "analyze_issues" {
			continue
		}
		out, err := tool.Execute(context.WithValue(authCtx, chatRequestKey{}, req), who, json.RawMessage(args))
		if err != nil {
			return nil, err
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("analyze_issues returned something other than JSON: %v\n%s", err, out)
		}
		return got, nil
	}
	t.Fatal("the chat offers no analyze_issues")
	return nil, nil
}

// exampleJobs lists the example job ids across every problem in a chat
// answer, sorted.
func exampleJobs(answer map[string]any) []string {
	var ids []string
	sections, _ := answer["sections"].([]any)
	for _, sec := range sections {
		shown, _ := sec.(map[string]any)["shown"].([]any)
		for _, c := range shown {
			exs, _ := c.(map[string]any)["examples"].([]any)
			for _, ex := range exs {
				ids = append(ids, ex.(map[string]any)["job_id"].(string))
			}
		}
	}
	slices.Sort(ids)
	return ids
}

// restIssueJobs is the same for GET /api/v1/issues.
func restIssueJobs(t *testing.T, f *twoOwnerFixture, query url.Values, auth func(*http.Request)) []string {
	t.Helper()
	w := f.do(t, http.MethodGet, "/api/v1/issues?"+query.Encode(), "", auth)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/issues?%s: status %d: %s", query.Encode(), w.Code, w.Body.String())
	}
	var resp IssuesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", w.Body.String(), err)
	}
	var ids []string
	for _, sec := range resp.Sections {
		for _, c := range sec.Clusters {
			for _, ex := range c.Examples {
				ids = append(ids, (&jobActionArgs{ClusterID: int(ex.Cluster), ProcID: int(ex.Proc)}).jobID())
			}
		}
	}
	slices.Sort(ids)
	return ids
}

// A non-administrator's analyze_issues is their own jobs, whether or not
// they ask for everyone's, and a constraint naming someone else narrows to
// nothing rather than reaching them.
func TestChatAnalyzeIssuesIsTheCallersOwn(t *testing.T) {
	f := issuesFixture(t)

	for _, args := range []string{`{}`, `{"everyone":true}`} {
		got, err := chatIssues(t, f, "alice", args)
		if err != nil {
			t.Fatalf("alice %s: %v", args, err)
		}
		if ids := exampleJobs(got); !slices.Equal(ids, []string{"31.0", "32.0"}) {
			t.Errorf("alice %s saw jobs %v, want only her own [31.0 32.0]", args, ids)
		}
		if scope, _ := got["scope"].(string); !strings.HasPrefix(scope, "your own jobs") {
			t.Errorf("alice %s: scope %q, want her own", args, scope)
		}
	}

	got, err := chatIssues(t, f, "alice", `{"constraint":"Owner == \"bob\""}`)
	if err != nil {
		t.Fatal(err)
	}
	if ids := exampleJobs(got); len(ids) != 0 {
		t.Errorf("alice naming bob in a constraint reached jobs %v", ids)
	}

	if _, err := chatIssues(t, f, "alice", `{"constraint":"true) || (true"}`); err == nil {
		t.Error("an expression that tries to escape the owner scope was accepted")
	}
}

// An administrator gets everyone's problems when they ask for them, and
// their own otherwise -- what the page's scope toggle does.
func TestChatAnalyzeIssuesAdminMatchesREST(t *testing.T) {
	f := issuesFixture(t)

	got, err := chatIssues(t, f, "root", `{"everyone":true}`, "condor-admins")
	if err != nil {
		t.Fatal(err)
	}
	if ids := exampleJobs(got); !slices.Equal(ids, []string{"31.0", "32.0", "33.0"}) {
		t.Errorf("admin everyone=true saw %v, want every user's held jobs", ids)
	}
	rest := restIssueJobs(t, f, url.Values{"owned_by_me": {"false"}}, f.session(t, "root", "condor-admins"))
	if !slices.Equal(rest, exampleJobs(got)) {
		t.Errorf("chat answered %v where the REST endpoint answered %v", exampleJobs(got), rest)
	}

	got, err = chatIssues(t, f, "root", `{}`, "condor-admins")
	if err != nil {
		t.Fatal(err)
	}
	if ids := exampleJobs(got); len(ids) != 0 {
		t.Errorf("admin's own view saw %v; root holds no jobs", ids)
	}
}

// "Only jobs that asked for a GPU" narrows inside the owner scope: a job
// with no RequestGPUs at all is not matched (the comparison is undefined),
// and another user's GPU job is not reached.
func TestIssuesConstraintNarrowsWithinOwnerScope(t *testing.T) {
	f := issuesFixture(t)
	gpu := `{"constraint":"RequestGPUs >= 1"}`

	got, err := chatIssues(t, f, "alice", gpu)
	if err != nil {
		t.Fatal(err)
	}
	if ids := exampleJobs(got); !slices.Equal(ids, []string{"31.0"}) {
		t.Errorf("alice's GPU-only chat answer saw %v, want [31.0]", ids)
	}
	if c, _ := got["constraint"].(string); c == "" {
		t.Error("the answer does not say which constraint it applied")
	}

	q := url.Values{"constraint": {"RequestGPUs >= 1"}, "owned_by_me": {"false"}}
	if ids := restIssueJobs(t, f, q, f.session(t, "alice")); !slices.Equal(ids, []string{"31.0"}) {
		t.Errorf("alice's GPU-only REST answer saw %v, want [31.0]", ids)
	}
	if ids := restIssueJobs(t, f, q, f.session(t, "root", "condor-admins")); !slices.Equal(ids, []string{"31.0", "33.0"}) {
		t.Errorf("admin's GPU-only REST answer saw %v, want [31.0 33.0]", ids)
	}

	w := f.do(t, http.MethodGet, "/api/v1/issues?constraint="+url.QueryEscape("true) || (true"), "", f.session(t, "alice"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("an unbalanced constraint: status %d, want 400: %s", w.Code, w.Body.String())
	}
}

// However big the page's answer, what reaches the model is bounded: a
// few problems per section, a couple of examples each, and every message
// cut short -- well under the engine's per-result cap, so the engine
// never has to cut the JSON mid-value.
func TestChatIssuesSummaryIsBounded(t *testing.T) {
	long := strings.Repeat("Transfer of /home/user/really/long/path/output.dat failed: ", 200)
	cluster := func(i int) issues.Cluster {
		c := issues.Cluster{
			Kind: issues.KindHold, Template: long, Count: 1000 - i, Users: 40,
			LastSeen: time.Now().Unix(),
		}
		for u := 0; u < 5; u++ {
			c.TopUsers = append(c.TopUsers, issues.OwnerCount{Owner: strings.Repeat("u", 32), Count: 10})
		}
		for k := 0; k < 6; k++ {
			c.Codes = append(c.Codes, issues.CodeCount{Code: 12, SubCode: int64(k), Label: "TransferOutputError", Count: 3})
		}
		for _, name := range []string{"resource", "site", "other"} {
			spread := issues.FacetSpread{Name: name, Distinct: 30}
			for v := 0; v < 10; v++ {
				spread.Top = append(spread.Top, issues.FacetValue{Value: strings.Repeat("x", 500), Count: 3})
			}
			c.Facets = append(c.Facets, spread)
		}
		for e := 0; e < 25; e++ {
			c.Examples = append(c.Examples, issues.Example{Cluster: int64(e), Owner: "alice", Batch: long, Message: long})
		}
		return c
	}
	var resp IssuesResponse
	resp.OwnedByMe = true
	resp.WindowSeconds = 86400
	for _, kind := range []string{issues.KindHold, issues.KindRunFailure} {
		sec := IssueSection{Kind: kind, Title: kind, Total: 50000, Users: 40}
		for i := 0; i < 200; i++ {
			sec.Clusters = append(sec.Clusters, cluster(i))
		}
		resp.Sections = append(resp.Sections, sec)
	}
	resp.Notes = []string{long, long}

	out, err := json.Marshal(chatIssuesSummary(resp, false))
	if err != nil {
		t.Fatal(err)
	}
	// Three quarters of the cap leaves room for the engine's own framing.
	if len(out) > chat.MaxToolResultBytes*3/4 {
		t.Errorf("the worst-case answer is %d bytes, over three quarters of the engine's %d-byte cap", len(out), chat.MaxToolResultBytes)
	}
	var got struct {
		Sections []chatIssueSection `json:"sections"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	for _, sec := range got.Sections {
		if sec.Problems != 200 || len(sec.Shown) != chatIssuesMaxClusters {
			t.Errorf("section %q: %d of %d problems shown, want the first %d of 200", sec.Title, len(sec.Shown), sec.Problems, chatIssuesMaxClusters)
		}
		for _, c := range sec.Shown {
			if len(c.Examples) > chatIssuesMaxExamples || len(c.Message) > chatIssuesMaxMessage+len("…") {
				t.Errorf("a problem carries %d examples and a %d-byte message", len(c.Examples), len(c.Message))
			}
		}
	}
}
