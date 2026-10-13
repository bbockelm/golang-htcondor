package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// The issues view in multi-AP mode, from an in-process hub: held jobs on
// both APs and, where the hub federates it, run attempts -- every
// example and cluster naming its AP, nobody else's jobs.

func issuesHub(t *testing.T, epochs bool) *multiaptest.DB {
	t.Helper()
	now := time.Now().Unix()
	hub := multiaptest.NewHub(t)
	held := func(n int64) string {
		return fmt.Sprintf("JobStatus = 5\nHoldReasonCode = 13\nHoldReason = \"Transfer input files failure at node %d\"\nEnteredCurrentStatus = %d", n, now)
	}
	hub.PutJob(ap1, "alice@d", 1, 0, held(1))
	hub.PutJob(ap2, "alice@d", 1, 0, held(2))
	hub.PutJob(ap1, "bob@d", 4, 0, held(3))
	src := func(schedd string) string {
		ad := fmt.Sprintf("ScheddName = %q\nState = \"fresh\"\nJobsConnected = true\nStalenessSeconds = 1\nHistoryConnected = true", schedd)
		if epochs {
			ad += "\nEpochHistoryConnected = true"
		}
		return ad
	}
	hub.PutSourceAd(ap1, src(ap1))
	hub.PutSourceAd(ap2, src(ap2))
	if epochs {
		hub.EnableEpochHistory()
		vac := `VacateReasonCode = 1003` + "\n" + `VacateReason = "The shadow lost its connection to the starter"`
		hub.PutEpoch(ap2, "alice@d", 9, 0, "EPOCH", now, vac)
		hub.PutEpoch(ap1, "bob@d", 9, 0, "EPOCH", now, vac)
	}
	return hub
}

type issuesBody struct {
	Notes    []string `json:"notes"`
	Sections []struct {
		Kind     string `json:"kind"`
		Total    int    `json:"total"`
		Clusters []struct {
			Schedds []struct {
				Schedd string `json:"schedd"`
				Count  int    `json:"count"`
			} `json:"schedds"`
			Examples []struct {
				Cluster int64  `json:"cluster_id"`
				Schedd  string `json:"schedd"`
				Owner   string `json:"owner"`
			} `json:"examples"`
		} `json:"clusters"`
	} `json:"sections"`
	Sources *struct {
		APs int `json:"aps"`
	} `json:"sources"`
}

func TestMultiAPIssuesFromTheHub(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, issuesHub(t, true), multiaptest.NewRegistry(ap1, ap2)))
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/issues")
	var b issuesBody
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &b) != nil {
		t.Fatalf("issues: %d %s", rec.Code, rec.Body.String())
	}
	if b.Sources == nil || b.Sources.APs != 2 {
		t.Errorf("sources %+v", b.Sources)
	}
	kinds := map[string]int{}
	for _, sec := range b.Sections {
		kinds[sec.Kind] = sec.Total
		for _, c := range sec.Clusters {
			for _, ex := range c.Examples {
				if ex.Schedd == "" || ex.Owner != "alice" {
					t.Errorf("%s example %+v: want alice's, with its AP", sec.Kind, ex)
				}
			}
		}
	}
	if kinds["hold"] != 2 || kinds["run_failure"] != 1 {
		t.Fatalf("sections %+v: want alice's two holds (one per AP) and her one run failure", kinds)
	}
	for _, sec := range b.Sections {
		if sec.Kind != "hold" {
			continue
		}
		aps := map[string]int{}
		for _, c := range sec.Clusters {
			for _, s := range c.Schedds {
				aps[s.Schedd] += s.Count
			}
		}
		if aps[ap1] != 1 || aps[ap2] != 1 {
			t.Errorf("holds per AP %v, want one on each", aps)
		}
	}

	// Over MCP too.
	sc, text := mcpCallAs(t, srv, "alice", "analyze_issues", map[string]any{})
	if sc == nil || !strings.Contains(text, "@"+ap2) || strings.Contains(text, "bob") {
		t.Errorf("analyze_issues: %s", text)
	}
	if n := srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// TestMultiAPIssuesWithoutFederatedEpochs: with no epoch_history on the
// hub the holds are still answered, and the answer says what is missing.
func TestMultiAPIssuesWithoutFederatedEpochs(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, issuesHub(t, false), multiaptest.NewRegistry(ap1, ap2)))
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/issues")
	var b issuesBody
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &b) != nil {
		t.Fatalf("issues: %d %s", rec.Code, rec.Body.String())
	}
	if len(b.Sections) != 1 || b.Sections[0].Total != 2 {
		t.Errorf("sections %+v: want alice's two holds", b.Sections)
	}
	if len(b.Notes) == 0 || !strings.Contains(strings.Join(b.Notes, " "), "epoch_history") {
		t.Errorf("notes %v: want the missing epoch_history named", b.Notes)
	}
}

// TestMultiAPIssuesConstraintNarrowsOnly: the page's constraint narrows
// the hub read inside the caller's scope and cannot reach another user's
// jobs; a malformed one is a 400.
func TestMultiAPIssuesConstraintNarrowsOnly(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, issuesHub(t, false), multiaptest.NewRegistry(ap1, ap2)))
	total := func(constraint string) int {
		t.Helper()
		rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/issues?constraint="+url.QueryEscape(constraint))
		var b issuesBody
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &b) != nil {
			t.Fatalf("issues?constraint=%s: %d %s", constraint, rec.Code, rec.Body.String())
		}
		n := 0
		for _, sec := range b.Sections {
			n += sec.Total
		}
		return n
	}
	if n := total("ScheddName == \"" + ap2 + "\""); n != 1 {
		t.Errorf("holds on %s = %d, want alice's one", ap2, n)
	}
	if n := total(`ClusterId == 4 || Owner == "bob" || User == "bob@d"`); n != 0 {
		t.Errorf("a constraint naming bob read %d of his holds", n)
	}
	if rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/issues?constraint="+url.QueryEscape("true) || (true")); rec.Code != http.StatusBadRequest {
		t.Errorf("a malformed constraint = %d %s, want 400", rec.Code, rec.Body.String())
	}
}
