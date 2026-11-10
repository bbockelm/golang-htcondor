package httpserver

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// A finished job whose memory request is a rule over its own usage, the
// shape condor_submit writes for request_memory = ifthenelse(...). The page
// showed "-" for its requested memory because the attribute reaches the
// client as "/Expr(...)/".
const exprRequestAd = `[
	RequestMemory = ifthenelse(MemoryUsage =!= undefined,max({ 2048,3 * MemoryUsage / 2 }),2048);
	MemoryUsage = ((ResidentSetSize + 1023) / 1024);
	ResidentSetSize = 7500000;
	MemoryProvisioned = 11008;
	RequestCpus = 1;
	RequestDisk = 6291456;
	RequestGPUs = 0
]`

func parseAd(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return ad
}

func marshalToMap(t *testing.T, ad *classad.ClassAd) map[string]any {
	t.Helper()
	b, err := json.Marshal(ad)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	return got
}

func TestEvaluatedRequestsCarryTheNumberAnExpressionComesTo(t *testing.T) {
	ad := parseAd(t, exprRequestAd)
	annotateEvaluatedRequests(ad)
	got := marshalToMap(t, ad)

	// The rule the user wrote is still on the ad, unevaluated.
	raw, _ := got["RequestMemory"].(string)
	if !strings.HasPrefix(raw, "/Expr(") {
		t.Errorf("RequestMemory = %v, want the expression left in place", got["RequestMemory"])
	}

	ev, ok := got[evaluatedRequestsKey].(map[string]any)
	if !ok {
		t.Fatalf("%q is %T (%v), want an object", evaluatedRequestsKey, got[evaluatedRequestsKey], got[evaluatedRequestsKey])
	}
	// (7500000 + 1023) / 1024 == 7325 under integer division, and
	// 3 * 7325 / 2 == 10987: about 10.7 GB.
	want := map[string]float64{
		"RequestMemory": 10987,
		"RequestCpus":   1,
		"RequestDisk":   6291456,
		"RequestGPUs":   0,
	}
	for name, w := range want {
		if n, ok := ev[name].(float64); !ok || n != w {
			t.Errorf("evaluated.%s = %v, want %v", name, ev[name], w)
		}
	}
	if len(ev) != len(want) {
		t.Errorf("evaluated = %v, want exactly %v", ev, want)
	}
}

// A job that has not run yet has no MemoryUsage, and the same rule then
// answers its floor.
func TestEvaluatedRequestBeforeTheFirstRun(t *testing.T) {
	ad := parseAd(t, `[RequestMemory = ifthenelse(MemoryUsage =!= undefined,max({ 2048,3 * MemoryUsage / 2 }),2048)]`)
	annotateEvaluatedRequests(ad)
	ev, _ := marshalToMap(t, ad)[evaluatedRequestsKey].(map[string]any)
	if n, _ := ev["RequestMemory"].(float64); n != 2048 {
		t.Errorf("evaluated.RequestMemory = %v, want 2048", ev["RequestMemory"])
	}
}

// A request that depends on the machine has no value in the job's own
// context; it is left out rather than reported as something it is not, and
// an ad with nothing to report gains no member.
func TestEvaluatedRequestsOmitWhatDoesNotEvaluate(t *testing.T) {
	ad := parseAd(t, `[RequestMemory = TARGET.Memory / 2; RequestCpus = 4]`)
	annotateEvaluatedRequests(ad)
	ev, _ := marshalToMap(t, ad)[evaluatedRequestsKey].(map[string]any)
	if _, ok := ev["RequestMemory"]; ok {
		t.Errorf("evaluated.RequestMemory = %v, want it absent", ev["RequestMemory"])
	}
	if n, _ := ev["RequestCpus"].(float64); n != 4 {
		t.Errorf("evaluated.RequestCpus = %v, want 4", ev["RequestCpus"])
	}

	none := parseAd(t, `[Owner = "someone"]`)
	annotateEvaluatedRequests(none)
	if _, ok := marshalToMap(t, none)[evaluatedRequestsKey]; ok {
		t.Error("an ad with no requests gained an evaluated member")
	}
	annotateEvaluatedRequests(nil) // must not panic
}

// An attribute spelled like the member is replaced rather than emitted
// beside it as a second spelling of one key.
func TestEvaluatedRequestsReplaceACollidingAttribute(t *testing.T) {
	ad := parseAd(t, `[Evaluated = "user value"; RequestCpus = 2]`)
	annotateEvaluatedRequests(ad)
	got := marshalToMap(t, ad)
	if _, ok := got["Evaluated"]; ok {
		t.Errorf("the colliding attribute survived: %v", got)
	}
	ev, _ := got[evaluatedRequestsKey].(map[string]any)
	if n, _ := ev["RequestCpus"].(float64); n != 2 {
		t.Errorf("evaluated.RequestCpus = %v, want 2", ev["RequestCpus"])
	}
}

// The archive page reads a job through the mirror with projection=*. Rows
// of a whole ad carry the evaluated requests; projected rows must not,
// because a rule evaluated without the attributes it reads gives a wrong
// number (here the floor, 2048, instead of 10987).
func TestMirrorRowsEvaluateRequestsOnlyForWholeAds(t *testing.T) {
	row := `RequestMemory = ifthenelse(MemoryUsage =!= undefined,max({ 2048,3 * MemoryUsage / 2 }),2048)
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
ResidentSetSize = 7500000
`
	for _, tc := range []struct {
		name    string
		wholeAd bool
		want    bool
	}{
		{"whole ad", true, true},
		{"projected", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			m := &mirrorRowStream{h: &Handler{}, w: rec, table: "history", key: "ads", limit: 10, wholeAd: tc.wholeAd}
			if !m.write(row) {
				t.Fatalf("write failed: %s", m.failure)
			}
			body := rec.Body.String()
			if got := strings.Contains(body, `"evaluated":{"RequestMemory":10987}`); got != tc.want {
				t.Errorf("evaluated member present = %v, want %v; body %s", got, tc.want, body)
			}
			// Usage is a number either way, as on the schedd-served paths.
			if !strings.Contains(body, `"MemoryUsage":7325`) {
				t.Errorf("MemoryUsage did not go out as a number: %s", body)
			}
		})
	}
}

func TestIsWholeAdProjection(t *testing.T) {
	for _, tc := range []struct {
		p    []string
		want bool
	}{
		{nil, false},
		{[]string{"*"}, true},
		{[]string{"ClusterId", "*"}, true},
		{[]string{"ClusterId", "RequestMemory"}, false},
	} {
		if got := isWholeAdProjection(tc.p); got != tc.want {
			t.Errorf("isWholeAdProjection(%v) = %v, want %v", tc.p, got, tc.want)
		}
	}
	if !multiWholeAd(nil) {
		t.Error("multiWholeAd(nil) = false; the hub reads whole ads without a projection")
	}
}
