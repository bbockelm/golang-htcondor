package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// Run-attempt and transfer history, and match analysis, in multi-AP
// mode: from the hub's epoch_history when it federates it, else routed
// to the one AP a job id or ?schedd= names -- and never to another.

// epochsHub is multiAPHub with epoch_history federated: alice's 7.0 ran
// on both APs (an EPOCH record each, and an INPUT transfer on ap2), and
// bob's 9.0 on ap1.
func epochsHub(t *testing.T) *multiaptest.DB {
	t.Helper()
	hub := multiAPHub(t)
	hub.EnableEpochHistory()
	now := time.Now().Unix()
	hub.PutEpoch(ap1, "alice@d", 7, 0, "EPOCH", now-20, `Marker = "a1"`)
	hub.PutEpoch(ap2, "alice@d", 7, 0, "EPOCH", now-10, `Marker = "a2"`)
	hub.PutEpoch(ap2, "alice@d", 7, 0, "INPUT", now-5, `Marker = "a2-in"`+"\nTransferProtocol = \"https\"")
	hub.PutEpoch(ap1, "bob@d", 9, 0, "EPOCH", now, `Marker = "b1"`)
	for _, ap := range []string{ap1, ap2} {
		hub.PutSourceAd(ap, fmt.Sprintf("ScheddName = %q\nState = \"fresh\"\nJobsConnected = true\nStalenessSeconds = 1\nEpochHistoryConnected = true", ap))
	}
	return hub
}

func epochMarkers(t *testing.T, srv http.Handler, target string) []string {
	t.Helper()
	b := decodeList(t, doAs(t, srv, "alice", http.MethodGet, target))
	var out []string
	for _, a := range b.Ads {
		if a["schedd"] == "" || a["job_id"] == "" {
			t.Errorf("%s: record without its AP: %v", target, a)
		}
		out = append(out, fmt.Sprint(a["Marker"]))
	}
	return out
}

func TestMultiAPEpochsFromTheHub(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, epochsHub(t), multiaptest.NewRegistry(ap1, ap2)))
	q := url.Values{"projection": {"Marker,EpochAdType"}}.Encode()
	got := epochMarkers(t, srv, "/api/v1/jobs/epochs?"+q)
	if strings.Join(got, ",") != "a2-in,a2,a1" {
		t.Errorf("epochs = %v, want alice's three records newest first, not bob's", got)
	}
	got = epochMarkers(t, srv, "/api/v1/jobs/epochs?job_id="+url.QueryEscape("7.0@"+ap2)+"&"+q)
	if strings.Join(got, ",") != "a2-in,a2" {
		t.Errorf("epochs for 7.0@%s = %v, want that AP's records only", ap2, got)
	}
	got = epochMarkers(t, srv, "/api/v1/jobs/transfers?"+q)
	if strings.Join(got, ",") != "a2-in" {
		t.Errorf("transfers = %v, want the INPUT record only", got)
	}
	// A bare 7.0 is on both APs: the caller is asked to name one.
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/epochs?job_id=7.0"); rec.Code != http.StatusConflict {
		t.Errorf("bare 7.0 = %d %s, want 409", rec.Code, rec.Body.String())
	}
	// The caller's constraint cannot reach bob's records.
	c := url.Values{"constraint": {`User == "bob@d" || true`}}.Encode()
	if got := epochMarkers(t, srv, "/api/v1/jobs/epochs?"+c+"&"+q); strings.Contains(strings.Join(got, ","), "b1") {
		t.Errorf("a crafted constraint read bob's records: %v", got)
	}
}

// TestMultiAPEpochsRoutedWithoutFederation: with the hub not federating
// epoch_history, a read names one job or one AP and goes to that AP's
// schedd alone; one naming neither is refused.
func TestMultiAPEpochsRoutedWithoutFederation(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)

	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/epochs")
	if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), multiap.ReasonEpochsNotFederated) {
		t.Errorf("unscoped epochs = %d %s, want 501 naming the reason", rec.Code, rec.Body.String())
	}
	for _, c := range []struct {
		path, want string
	}{
		{"/api/v1/jobs/epochs?job_id=" + url.QueryEscape("1.0@"+ap2), ap2},
		{"/api/v1/jobs/transfers?job_id=" + url.QueryEscape("1.0@"+ap2), ap2},
		{"/api/v1/jobs/epochs?schedd=" + ap1, ap1},
		// A bare id one AP holds (alice's 2.0 is on ap1 only).
		{"/api/v1/jobs/transfers?job_id=2.0", ap1},
	} {
		before := aps.counts()
		doAs(t, srv, "alice", http.MethodGet, c.path)
		after := aps.counts()
		for _, ap := range []string{ap1, ap2} {
			reached := after[ap] > before[ap]
			if reached != (ap == c.want) {
				t.Errorf("%s: %s reached=%v, want only %s", c.path, ap, reached, c.want)
			}
		}
	}
	if n := srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// TestMultiAPMatchAnalysisRoutes: the job ad is read from the AP its id
// names, and from no other.
func TestMultiAPMatchAnalysisRoutes(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	srv.collector = htcondor.NewCollector("<127.0.0.1:1>")

	before := aps.counts()
	doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/1.0@"+ap2+"/match-analysis")
	after := aps.counts()
	if after[ap2] == before[ap2] || after[ap1] != before[ap1] {
		t.Errorf("match-analysis for 1.0@%s reached %v -> %v, want %s only", ap2, before, after, ap2)
	}
	// A bare id is not guessed.
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/1.0/match-analysis"); rec.Code != http.StatusBadRequest {
		t.Errorf("bare 1.0 = %d %s, want 400 with candidates", rec.Code, rec.Body.String())
	}

	// And over MCP.
	before = aps.counts()
	mcpCallAs(t, srv, "alice", "analyze_job_match", map[string]any{"job_id": "1.0@" + ap1})
	after = aps.counts()
	if after[ap1] == before[ap1] || after[ap2] != before[ap2] {
		t.Errorf("analyze_job_match for 1.0@%s reached %v -> %v, want %s only", ap1, before, after, ap1)
	}
	before = aps.counts()
	mcpCallAs(t, srv, "alice", "query_job_epochs", map[string]any{"job_id": "1.0@" + ap2})
	after = aps.counts()
	if after[ap2] == before[ap2] || after[ap1] != before[ap1] {
		t.Errorf("query_job_epochs for 1.0@%s reached %v -> %v, want %s only", ap2, before, after, ap2)
	}
	if sc, text := mcpCallAs(t, srv, "alice", "query_transfer_history", map[string]any{}); sc != nil ||
		!strings.Contains(text, "epoch_history") {
		t.Errorf("unscoped query_transfer_history without federation = %v %s, want a refusal", sc, text)
	}
}

// TestMultiAPEpochsMCPFromTheHub: the MCP tools read the hub when it
// federates epoch_history.
func TestMultiAPEpochsMCPFromTheHub(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, epochsHub(t), multiaptest.NewRegistry(ap1, ap2)))
	sc, text := mcpCallAs(t, srv, "alice", "query_transfer_history", map[string]any{"projection": []any{"Marker"}})
	if sc == nil {
		t.Fatalf("query_transfer_history: %s", text)
	}
	b, _ := json.Marshal(sc["records"])
	if !strings.Contains(string(b), `"a2-in"`) || strings.Contains(string(b), `"a2"`) || sc["source"] != "hub" {
		t.Errorf("records %s (source %v), want the INPUT record from the hub", b, sc["source"])
	}
}
