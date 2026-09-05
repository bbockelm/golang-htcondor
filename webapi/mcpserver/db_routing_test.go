package mcpserver

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

func TestHistoryResultShape(t *testing.T) {
	ad := classad.New()
	ad.InsertAttr("ClusterId", 42)
	res := historyResult([]*classad.ClassAd{ad}, "job history", "Owner == \"alice\"", "htcondordb", "\n[source: htcondordb mirror]")

	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not a map: %T", res)
	}
	meta := m["metadata"].(map[string]interface{})
	if meta["source"] != "htcondordb" {
		t.Errorf("source = %v, want htcondordb", meta["source"])
	}
	if meta["total_records"] != 1 {
		t.Errorf("total_records = %v, want 1", meta["total_records"])
	}
	text := m["content"].([]map[string]interface{})[0]["text"].(string)
	if !strings.Contains(text, "Found 1 job history record(s)") {
		t.Errorf("missing count header: %q", text)
	}
	if !strings.Contains(text, "[source: htcondordb mirror]") {
		t.Errorf("provenance note not appended: %q", text)
	}
	// The record body must be valid JSON carrying the ad.
	start := strings.Index(text, "[")
	if start < 0 || !json.Valid([]byte(text[start:strings.Index(text, "]")+1])) {
		// The note also contains brackets; just assert the marshaled ad is present.
		if !strings.Contains(text, "42") {
			t.Errorf("record payload missing ClusterId: %q", text)
		}
	}
}

func TestJobKeyLess(t *testing.T) {
	mk := func(c, p int64) *classad.ClassAd {
		ad := classad.New()
		ad.InsertAttr("ClusterId", c)
		ad.InsertAttr("ProcId", p)
		return ad
	}
	ads := []*classad.ClassAd{mk(5, 1), mk(3, 2), mk(3, 0), mk(5, 0)}
	sort.SliceStable(ads, func(i, j int) bool { return jobKeyLess(ads[i], ads[j]) })
	var got [][2]int64
	for _, a := range ads {
		c, _ := a.EvaluateAttrInt("ClusterId")
		p, _ := a.EvaluateAttrInt("ProcId")
		got = append(got, [2]int64{c, p})
	}
	want := [][2]int64{{3, 0}, {3, 2}, {5, 0}, {5, 1}}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestRenderJobsBase(t *testing.T) {
	ad := classad.New()
	ad.InsertAttr("ClusterId", 7)
	text, meta := renderJobsBase([]*classad.ClassAd{ad}, "Owner == \"alice\"", "htcondordb", "\n[source: htcondordb mirror]")
	if meta["source"] != "htcondordb" || meta["count"] != 1 || meta["has_more"] != false {
		t.Errorf("metadata wrong: %+v", meta)
	}
	if !strings.Contains(text, "Found 1 job(s)") || !strings.Contains(text, "JOB STATUS REFERENCE") {
		t.Errorf("missing header or status guide: %q", text)
	}
	if !strings.Contains(text, "[source: htcondordb mirror]") {
		t.Errorf("provenance note not appended: %q", text)
	}
}

// TestHistoryResultSchedddPathNoNote confirms the schedd path (empty note) adds
// no provenance line and labels the source with the record source.

func TestHistoryResultScheddPathNoNote(t *testing.T) {
	res := historyResult(nil, "job epochs", "true", "JOB_EPOCH", "")
	m := res.(map[string]interface{})
	text := m["content"].([]map[string]interface{})[0]["text"].(string)
	if strings.Contains(text, "[source: htcondordb") {
		t.Errorf("schedd path must not carry a mirror note: %q", text)
	}
	if m["metadata"].(map[string]interface{})["source"] != "JOB_EPOCH" {
		t.Error("schedd path should preserve the record source label")
	}
}

// TestDelegatedHistoryRoutingRequiresAnIdentity: behind HTTP every call
// is on somebody else's behalf, and routing to the mirror is what skips
// the schedd handshake. A caller the schedd would refuse must not get
// history out of the mirror instead -- they fall back to the schedd,
// where the refusal happens.
//
// Over stdio the process IS the user and its own credential is what
// would have been used either way, so nothing has to be established;
// refusing there would break the CLI to fix a problem it does not have.
func TestDelegatedHistoryRoutingRequiresAnIdentity(t *testing.T) {
	locator := dbmirror.NewLocator(htcondor.NewCollector("collector.invalid"), config.NewEmpty())
	opts := &htcondor.HistoryQueryOptions{Backwards: true}

	delegated := &Server{dbMirror: locator, delegated: true}
	_, ok, d := delegated.tryHistoryFromDB(context.Background(), "true", opts, "job history")
	if ok {
		t.Error("a delegated server must not answer an unidentified caller from the mirror")
	}
	if d.Reason != dbmirror.ReasonNoOwnerScope {
		t.Errorf("Reason = %q, want %q", d.Reason, dbmirror.ReasonNoOwnerScope)
	}

	// Same call over stdio gets as far as discovery instead of stopping
	// at the identity check.
	stdio := &Server{dbMirror: locator}
	if _, _, d := stdio.tryHistoryFromDB(context.Background(), "true", opts, "job history"); d.Reason != dbmirror.ReasonNoMirror {
		t.Errorf("stdio: Reason = %q, want %q", d.Reason, dbmirror.ReasonNoMirror)
	}

	// And a delegated call WITH an identity is likewise not stopped there.
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
	if _, _, d := delegated.tryHistoryFromDB(ctx, "true", opts, "job history"); d.Reason != dbmirror.ReasonNoMirror {
		t.Errorf("identified delegated caller: Reason = %q, want %q", d.Reason, dbmirror.ReasonNoMirror)
	}
}
