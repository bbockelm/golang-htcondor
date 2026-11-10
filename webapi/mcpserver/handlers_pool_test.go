package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// fakePoolSource stands in for the collector. It does what the collector
// does with a query that matters to these tests: evaluates the constraint,
// honors the limit, and returns only the projected attributes -- so a
// summary that forgets to project an attribute it sums sees it absent, as
// it would against a real pool.
type fakePoolSource struct {
	ads []*classad.ClassAd
	err error

	mu    sync.Mutex
	calls []fakePoolCall
}

type fakePoolCall struct {
	adType     string
	constraint string
	projection []string
	limit      int
}

func (f *fakePoolSource) QueryAdsStream(_ context.Context, adType, constraint string, projection []string,
	limit int, _ *htcondor.StreamOptions) (<-chan htcondor.AdResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakePoolCall{adType, constraint, append([]string(nil), projection...), limit})
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	expr, err := classad.ParseExpr(constraint)
	if err != nil {
		return nil, err
	}
	ch := make(chan htcondor.AdResult, len(f.ads)+1)
	sent := 0
	for _, ad := range f.ads {
		if limit > 0 && sent >= limit {
			break
		}
		if b, err := expr.Eval(ad).BoolValue(); err != nil || !b {
			continue
		}
		out := classad.New()
		for _, name := range ad.GetAttributes() {
			if len(projection) > 0 && !slices.ContainsFunc(projection, func(p string) bool { return strings.EqualFold(p, name) }) {
				continue
			}
			e, _ := ad.Lookup(name)
			out.InsertExpr(name, e)
		}
		ch <- htcondor.AdResult{Ad: out}
		sent++
	}
	close(ch)
	return ch, nil
}

func (f *fakePoolSource) lastCall(t *testing.T) fakePoolCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("the collector was never queried")
	}
	return f.calls[len(f.calls)-1]
}

func mkAds(t *testing.T, texts ...string) []*classad.ClassAd {
	t.Helper()
	ads := make([]*classad.ClassAd, len(texts))
	for i, s := range texts {
		ad, err := classad.Parse(s)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		ads[i] = ad
	}
	return ads
}

func poolServer(t *testing.T, ads ...*classad.ClassAd) (*Server, *fakePoolSource) {
	t.Helper()
	src := &fakePoolSource{ads: ads}
	s := contractServer(t)
	s.poolAds = src
	return s, src
}

// callPool runs query_pool through the dispatcher -- scope check, handler,
// contract step -- validates the result against the published schema, and
// returns the structured content and text.
func callPool(t *testing.T, s *Server, args map[string]interface{}) (map[string]interface{}, string) {
	t.Helper()
	params, _ := json.Marshal(map[string]interface{}{"name": "query_pool", "arguments": args})
	res, err := s.handleCallTool(context.Background(), params)
	if err != nil {
		t.Fatalf("query_pool %v: %v", args, err)
	}
	m := res.(map[string]interface{})
	sc, ok := m["structuredContent"]
	if !ok {
		t.Fatal("query_pool returned no structuredContent")
	}
	validateStructured(t, "query_pool", sc)
	raw, _ := json.Marshal(sc)
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("structuredContent: %v", err)
	}
	text, _ := m["content"].([]map[string]interface{})[0]["text"].(string)
	return out, text
}

func callPoolErr(t *testing.T, s *Server, args map[string]interface{}) error {
	t.Helper()
	_, err := s.toolQueryPool(context.Background(), args)
	return err
}

// mixedPool is one partitionable machine with two dynamic slots carved
// from it and one static machine with two slots.
//
//	pslot: 4 Cpus, 4096 MiB, 0 GPUs left, Unclaimed (of 16 Cpus, 2 GPUs)
//	dslots: 8 Cpus/1 GPU and 4 Cpus/1 GPU, Claimed
//	static: 1 Cpu Unclaimed, 1 Cpu Owner; no GPUs advertised
func mixedPool(t *testing.T) []*classad.ClassAd {
	return mkAds(t,
		`[Name="slot1@p1"; Machine="p1"; SlotType="Partitionable"; PartitionableSlot=true; State="Unclaimed"; Activity="Idle";
		  Cpus=4; Memory=4096; GPUs=0; TotalSlotCpus=16; TotalSlotGPUs=2; OpSys="LINUX"; ClaimId="secret-p"]`,
		`[Name="slot1_1@p1"; Machine="p1"; SlotType="Dynamic"; DynamicSlot=true; State="Claimed"; Activity="Busy";
		  Cpus=8; Memory=8192; GPUs=1; OpSys="LINUX"; ClaimId="secret-d1"]`,
		`[Name="slot1_2@p1"; Machine="p1"; SlotType="Dynamic"; DynamicSlot=true; State="Claimed"; Activity="Busy";
		  Cpus=4; Memory=4096; GPUs=1; OpSys="LINUX"]`,
		`[Name="slot1@s1"; Machine="s1"; SlotType="Static"; State="Unclaimed"; Activity="Idle"; Cpus=1; Memory=1024]`,
		`[Name="slot2@s1"; Machine="s1"; SlotType="Static"; State="Owner"; Activity="Idle"; Cpus=1; Memory=1024]`,
	)
}

func resource(t *testing.T, sc map[string]interface{}, attr string) map[string]interface{} {
	t.Helper()
	res, _ := sc["resources"].(map[string]interface{})
	r, ok := res[attr].(map[string]interface{})
	if !ok {
		t.Fatalf("no resources.%s in %v", attr, sc["resources"])
	}
	return r
}

// TestPoolSummaryCountsPartitionableSlotsOnce: a partitionable slot
// advertises what it has left and its dynamic slots what they hold, so the
// pool's capacity is the sum of every slot's own Cpus. Adding the
// partitionable slot's TotalSlotCpus as well would count the 12 claimed
// Cpus twice.
func TestPoolSummaryCountsPartitionableSlotsOnce(t *testing.T) {
	s, _ := poolServer(t, mixedPool(t)...)
	sc, text := callPool(t, s, nil)

	if sc["mode"] != "summary" || sc["ad_type"] != "slots" {
		t.Errorf("default should be a slots summary, got mode=%v ad_type=%v", sc["mode"], sc["ad_type"])
	}
	if sc["count"] != 5.0 || sc["machines"] != 2.0 {
		t.Errorf("count=%v machines=%v, want 5 slots on 2 machines", sc["count"], sc["machines"])
	}

	cpus := resource(t, sc, "Cpus")
	want := map[string]float64{"total": 18, "claimed": 12, "unclaimed": 5, "other": 1}
	for k, v := range want {
		if cpus[k] != v {
			t.Errorf("Cpus.%s = %v, want %v (resources: %v)", k, cpus[k], v, cpus)
		}
	}
	mem := resource(t, sc, "Memory")
	if mem["total"] != 18432.0 || mem["claimed"] != 12288.0 || mem["unclaimed"] != 5120.0 {
		t.Errorf("Memory = %v", mem)
	}
	gpus := resource(t, sc, "GPUs")
	if gpus["total"] != 2.0 || gpus["claimed"] != 2.0 || gpus["unclaimed"] != 0.0 {
		t.Errorf("GPUs = %v, want 2 total, both claimed", gpus)
	}

	types, _ := sc["slot_types"].(map[string]interface{})
	if types["Partitionable"] != 1.0 || types["Dynamic"] != 2.0 || types["Static"] != 2.0 {
		t.Errorf("slot_types = %v", types)
	}

	for _, want := range []string{"5 slot ad(s) on 2 machine(s)", "Cpus: 18 total, 12 claimed, 5 unclaimed, 1 in other states"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
}

// TestPoolSummaryReportsMissingAttributesRatherThanZero: a slot that does
// not advertise an attribute is counted as not advertising it. The static
// slots carry no GPUs attribute, which is what a GPU-less slot looks like;
// a slot with no Cpus is something else, and either way the summary says
// how many there were instead of quietly adding zero. The odd slot also
// omits SlotType.
func TestPoolSummaryReportsMissingAttributesRatherThanZero(t *testing.T) {
	ads := append(mixedPool(t), mkAds(t, `[Name="slot1@odd"; Machine="odd"; State="Unclaimed"; Activity="Idle"]`)...)
	s, _ := poolServer(t, ads...)
	sc, text := callPool(t, s, nil)

	missing, _ := sc["missing"].(map[string]interface{})
	if missing["GPUs"] != 3.0 {
		t.Errorf("missing.GPUs = %v, want 3 (two static slots and the odd one)", missing["GPUs"])
	}
	if missing["Cpus"] != 1.0 || missing["Memory"] != 1.0 {
		t.Errorf("missing = %v, want Cpus and Memory each missing on one slot", missing)
	}
	if !strings.Contains(text, "1 slot(s) do not advertise Cpus") {
		t.Errorf("text does not say a slot lacks Cpus:\n%s", text)
	}
	// Nor is a slot that does not say what type it is assumed static.
	if types, _ := sc["slot_types"].(map[string]interface{}); types["(not advertised)"] != 1.0 || types["Static"] != 2.0 {
		t.Errorf("slot_types = %v, want the odd slot reported as not advertised", types)
	}
}

// TestPoolSummaryProjectsWhatItSums: the summary must ask the collector for
// every attribute it reads. An empty projection would get the library's
// six-attribute default, and an incomplete one would make every slot look
// as though it had no GPUs; both are invisible in the totals unless the
// query itself is checked.
func TestPoolSummaryProjectsWhatItSums(t *testing.T) {
	s, src := poolServer(t, mixedPool(t)...)
	sc, _ := callPool(t, s, map[string]interface{}{"group_by": []interface{}{"OpSys"}})

	call := src.lastCall(t)
	if call.adType != htcondor.StartdAdType {
		t.Errorf("queried %q, want startd ads", call.adType)
	}
	for _, want := range []string{"Cpus", "Memory", "GPUs", "State", "SlotType", "Machine", "OpSys"} {
		if !slices.Contains(call.projection, want) {
			t.Errorf("summary projection %v lacks %s", call.projection, want)
		}
	}
	if call.limit != maxPoolSummaryAds+1 {
		t.Errorf("summary scan limit = %d, want %d", call.limit, maxPoolSummaryAds+1)
	}
	if missing, _ := sc["missing"].(map[string]interface{}); missing["Cpus"] != 0.0 {
		t.Errorf("with the right projection no slot should lack Cpus, got missing=%v", missing)
	}
}

// TestPoolSummaryGroups: the default grouping is State/Activity, a caller's
// grouping replaces it, an ad without the attribute gets its own group, and
// an explicit empty list is one total.
func TestPoolSummaryGroups(t *testing.T) {
	s, _ := poolServer(t, mixedPool(t)...)

	groupMap := func(sc map[string]interface{}) map[string]float64 {
		out := map[string]float64{}
		groups, _ := sc["groups"].([]interface{})
		for _, g := range groups {
			gm := g.(map[string]interface{})
			var key []string
			for _, k := range gm["key"].([]interface{}) {
				key = append(key, k.(string))
			}
			out[strings.Join(key, "/")] = gm["count"].(float64)
		}
		return out
	}

	sc, _ := callPool(t, s, nil)
	if got := groupMap(sc); got["Claimed/Busy"] != 2 || got["Unclaimed/Idle"] != 2 || got["Owner/Idle"] != 1 {
		t.Errorf("default State/Activity groups = %v", got)
	}
	// Each group carries its own totals.
	var claimed map[string]interface{}
	for _, g := range sc["groups"].([]interface{}) {
		if gm := g.(map[string]interface{}); gm["key"].([]interface{})[0] == "Claimed" {
			claimed = gm["totals"].(map[string]interface{})
		}
	}
	if claimed["Cpus"] != 12.0 || claimed["GPUs"] != 2.0 {
		t.Errorf("Claimed group totals = %v, want 12 Cpus and 2 GPUs", claimed)
	}

	sc, _ = callPool(t, s, map[string]interface{}{"group_by": []interface{}{"OpSys"}})
	if got := groupMap(sc); got["LINUX"] != 3 || got[undefinedGroup] != 2 {
		t.Errorf("OpSys groups = %v, want 3 LINUX and 2 %s", got, undefinedGroup)
	}

	sc, _ = callPool(t, s, map[string]interface{}{"group_by": []interface{}{}})
	if got := groupMap(sc); len(got) != 1 || got[""] != 5 {
		t.Errorf("an empty group_by should be one total of 5, got %v", got)
	}
}

// TestPoolSummaryCapsGroups: grouping on a near-unique attribute would be a
// listing by another route, so the groups are capped and the answer says so.
func TestPoolSummaryCapsGroups(t *testing.T) {
	var texts []string
	for i := 0; i < maxPoolGroups+50; i++ {
		texts = append(texts, fmt.Sprintf(`[Name="slot%d@m"; Machine="m%d"; State="Unclaimed"; Cpus=1; Memory=1; GPUs=0]`, i, i))
	}
	s, _ := poolServer(t, mkAds(t, texts...)...)
	sc, text := callPool(t, s, map[string]interface{}{"group_by": []interface{}{"Name"}})

	if n := len(sc["groups"].([]interface{})); n != maxPoolGroups {
		t.Errorf("returned %d groups, want the cap %d", n, maxPoolGroups)
	}
	if sc["groups_truncated"] != true || sc["groups_total"] != float64(maxPoolGroups+50) {
		t.Errorf("groups_truncated=%v groups_total=%v", sc["groups_truncated"], sc["groups_total"])
	}
	if !strings.Contains(text, "50 more groups not shown") {
		t.Errorf("text does not say groups were cut:\n%s", text)
	}
	// The cap limits what is shown, not what is counted.
	if sc["count"] != float64(maxPoolGroups+50) {
		t.Errorf("count = %v", sc["count"])
	}
}

// TestPoolSummaryScanCeiling: past maxPoolSummaryAds the summary stops
// counting and says its numbers are partial.
func TestPoolSummaryScanCeiling(t *testing.T) {
	agg := newPoolAggregator(&poolAdKinds[0], nil)
	agg.count = maxPoolSummaryAds
	agg.add(mkAds(t, `[Name="x"; Cpus=1]`)[0])
	if !agg.truncated || agg.count != maxPoolSummaryAds {
		t.Errorf("truncated=%v count=%d", agg.truncated, agg.count)
	}
	if !strings.Contains(agg.text("true"), "PARTIAL") {
		t.Error("a truncated summary does not say it is partial")
	}
}

// TestPoolListBoundsRowsAndSaysMoreMatch: a listing asks for one more row
// than it returns, so "more match" is observed, and says so in both the
// text and has_more.
func TestPoolListBoundsRowsAndSaysMoreMatch(t *testing.T) {
	s, src := poolServer(t, mixedPool(t)...)

	sc, text := callPool(t, s, map[string]interface{}{"mode": "list", "limit": 3.0})
	if src.lastCall(t).limit != 4 {
		t.Errorf("asked the collector for %d rows, want limit+1 = 4", src.lastCall(t).limit)
	}
	if sc["count"] != 3.0 || sc["has_more"] != true {
		t.Errorf("count=%v has_more=%v, want 3 and true", sc["count"], sc["has_more"])
	}
	if !strings.Contains(text, "Stopped at the requested limit of 3; more match") {
		t.Errorf("text does not report truncation:\n%s", text)
	}

	sc, text = callPool(t, s, map[string]interface{}{"mode": "list", "limit": 5.0})
	if sc["count"] != 5.0 || sc["has_more"] != false || strings.Contains(text, "more match") {
		t.Errorf("exactly 5 matches with limit 5 is not truncated: count=%v has_more=%v", sc["count"], sc["has_more"])
	}

	// The ceiling: a caller cannot ask for more than maxToolResults.
	callPool(t, s, map[string]interface{}{"mode": "list", "limit": 100000.0})
	if got := src.lastCall(t).limit; got != maxToolResults+1 {
		t.Errorf("asked for %d rows past the ceiling, want %d", got, maxToolResults+1)
	}
	callPool(t, s, map[string]interface{}{"mode": "list"})
	if got := src.lastCall(t).limit; got != defaultPoolListLimit+1 {
		t.Errorf("default listing asked for %d rows, want %d", got, defaultPoolListLimit+1)
	}
}

// TestPoolListProjection: the listing always sends an explicit projection
// -- the working set by default, the caller's otherwise -- and "*" is the
// one way to ask for everything.
func TestPoolListProjection(t *testing.T) {
	s, src := poolServer(t, mixedPool(t)...)

	sc, _ := callPool(t, s, map[string]interface{}{"mode": "list"})
	if got := src.lastCall(t).projection; !slices.Equal(got, poolAdKinds[0].listAttrs) {
		t.Errorf("default listing projection = %v, want the slots working set", got)
	}
	ads := sc["ads"].([]interface{})
	if first := ads[0].(map[string]interface{}); first["Cpus"] == nil || first["State"] == nil {
		t.Errorf("a default listing row lacks resource columns: %v", first)
	}
	// Ordered by Machine then Name, not the collector's hash order.
	if name := ads[0].(map[string]interface{})["Name"]; name != "slot1@p1" {
		t.Errorf("first row = %v, want slot1@p1", name)
	}

	callPool(t, s, map[string]interface{}{"mode": "list", "projection": []interface{}{"Name", "OpSys"}})
	if got := src.lastCall(t).projection; !slices.Equal(got, []string{"Name", "OpSys"}) {
		t.Errorf("caller projection = %v", got)
	}

	_, text := callPool(t, s, map[string]interface{}{"mode": "list", "projection": []interface{}{"*"}})
	if got := src.lastCall(t).projection; len(got) != 0 {
		t.Errorf("'*' should reach the collector as no projection, got %v", got)
	}
	if !strings.Contains(text, "Returning every attribute") {
		t.Errorf("'*' is not flagged as expensive:\n%s", text)
	}
}

// TestPoolNeverReturnsPrivateAttributes: claim ids are bearer credentials
// for a slot. The collector withholds them from an ordinary reader but may
// release them to this server's own credential, so they are stripped from
// every ad and refused in every argument -- including a constraint, which
// would otherwise be an oracle for a value never returned.
func TestPoolNeverReturnsPrivateAttributes(t *testing.T) {
	s, _ := poolServer(t, mixedPool(t)...)

	// The ads themselves, before anything serializes them: the JSON
	// encoder redacts private attributes too, but a payload that carried
	// them would be one serializer away from sending them.
	res, err := s.toolQueryPool(context.Background(), map[string]interface{}{"mode": "list", "projection": []interface{}{"*"}})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, ad := range res.(map[string]interface{})["structuredContent"].(map[string]interface{})["ads"].([]*classad.ClassAd) {
		for _, name := range ad.GetAttributes() {
			if isPrivatePoolAttr(name) {
				t.Errorf("%s is in a returned ad", name)
			}
		}
	}

	sc, text := callPool(t, s, map[string]interface{}{"mode": "list", "projection": []interface{}{"*"}})
	if strings.Contains(text, "secret-") {
		t.Errorf("a claim id reached the text:\n%s", text)
	}
	raw, _ := json.Marshal(sc)
	if strings.Contains(string(raw), "secret-") || strings.Contains(strings.ToLower(string(raw)), "claimid") {
		t.Errorf("a claim id reached structuredContent: %s", raw)
	}

	for _, args := range []map[string]interface{}{
		{"constraint": `ClaimId =!= undefined`},
		{"constraint": `substr(MY.ClaimId, 0, 1) == "a"`},
		{"constraint": `eval("Claim" + "Id") =!= undefined`},
		{"constraint": `_condor_privFoo == 1`},
		{"mode": "list", "projection": []interface{}{"Name", "Capability"}},
		{"group_by": []interface{}{"claimidlist"}},
	} {
		if err := callPoolErr(t, s, args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	// Not private: a GPU attribute that ends in "Capability", and a
	// string literal that happens to spell an attribute name.
	for _, c := range []string{`CUDACapability >= 7.0`, `Name != "ClaimId"`, `Name != "a\"ClaimId"`} {
		if err := callPoolErr(t, s, map[string]interface{}{"constraint": c}); err != nil {
			t.Errorf("constraint %s refused: %v", c, err)
		}
	}
}

// TestPoolAdTypes: each enum value queries its own ad type, the
// condor_status spellings are accepted, and anything else is refused with
// the list.
func TestPoolAdTypes(t *testing.T) {
	ads := mkAds(t,
		`[Name="ap1"; Machine="ap1"; MyType="Scheduler"; TotalRunningJobs=10; TotalIdleJobs=5; TotalHeldJobs=1]`,
		`[Name="ap2"; Machine="ap2"; MyType="Scheduler"; TotalRunningJobs=3; TotalIdleJobs=0]`,
	)
	s, src := poolServer(t, ads...)

	sc, text := callPool(t, s, map[string]interface{}{"ad_type": "schedd"})
	if src.lastCall(t).adType != htcondor.ScheddAdType {
		t.Errorf("schedd queried %q", src.lastCall(t).adType)
	}
	totals := sc["totals"].(map[string]interface{})
	if totals["TotalRunningJobs"] != 13.0 || totals["TotalIdleJobs"] != 5.0 || totals["TotalHeldJobs"] != 1.0 {
		t.Errorf("schedd totals = %v", totals)
	}
	if m := sc["missing"].(map[string]interface{}); m["TotalHeldJobs"] != 1.0 {
		t.Errorf("missing = %v, want ap2 counted as not advertising TotalHeldJobs", m)
	}
	if _, has := sc["resources"]; has {
		t.Error("a schedd summary carries slot resources")
	}
	if !strings.Contains(text, "TotalRunningJobs: 13") {
		t.Errorf("text:\n%s", text)
	}

	for arg, want := range map[string]string{
		"": htcondor.StartdAdType, "startd": htcondor.StartdAdType, "Slots": htcondor.StartdAdType,
		"submitters": htcondor.SubmitterAdType, "negotiator": htcondor.NegotiatorAdType,
		"collector": htcondor.CollectorAdType,
	} {
		callPool(t, s, map[string]interface{}{"ad_type": arg})
		if got := src.lastCall(t).adType; got != want {
			t.Errorf("ad_type %q queried %q, want %q", arg, got, want)
		}
	}

	err := callPoolErr(t, s, map[string]interface{}{"ad_type": "license"})
	if err == nil || !strings.Contains(err.Error(), "slots, schedd, submitter, negotiator, collector") {
		t.Errorf("unknown ad type: %v", err)
	}
	if err := callPoolErr(t, s, map[string]interface{}{"mode": "dump"}); err == nil {
		t.Error("an unknown mode was accepted")
	}
	if err := callPoolErr(t, s, map[string]interface{}{"constraint": "Cpus >"}); err == nil {
		t.Error("an unparseable constraint was accepted")
	}
}

// TestPoolEmptyAnswers: matching nothing is an ordinary answer, in either
// mode, and validates against the schema.
func TestPoolEmptyAnswers(t *testing.T) {
	s, _ := poolServer(t)
	sc, text := callPool(t, s, nil)
	if sc["count"] != 0.0 || !strings.Contains(text, "Nothing matched") {
		t.Errorf("empty summary: count=%v\n%s", sc["count"], text)
	}
	sc, _ = callPool(t, s, map[string]interface{}{"mode": "list"})
	if ads, ok := sc["ads"].([]interface{}); !ok || len(ads) != 0 {
		t.Errorf("empty listing ads = %v, want []", sc["ads"])
	}
}

func TestPoolCollectorError(t *testing.T) {
	s, src := poolServer(t)
	src.err = errors.New("connection refused")
	if err := callPoolErr(t, s, nil); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("collector failure: %v", err)
	}
}

// TestPoolToolOfferedWithACollectorOnly: without a collector every call
// would fail, so the tool is not offered; with one it is, to read-only
// tokens included.
func TestPoolToolOfferedWithACollectorOnly(t *testing.T) {
	listed := func(s *Server, ctx context.Context) bool {
		for _, tool := range s.toolsFor(ctx) {
			if tool.Name == "query_pool" {
				return true
			}
		}
		return false
	}
	if listed(&Server{}, context.Background()) {
		t.Error("query_pool offered by a server with no collector")
	}
	if (&Server{}).poolSource() != nil {
		t.Error("a server with no collector reports a pool source")
	}

	s, _ := poolServer(t)
	if !listed(s, context.Background()) {
		t.Error("query_pool not offered with a collector")
	}
	readOnly := WithGrantedScopes(context.Background(), []string{"mcp:read"})
	if !listed(s, readOnly) {
		t.Error("query_pool withheld from a read-only token")
	}
	if !IsReadOnlyTool("query_pool") {
		t.Error("query_pool is not in the read-only allowlist")
	}
	if ann := annotationsFor("query_pool"); ann == nil || !ann.ReadOnlyHint {
		t.Errorf("query_pool annotations = %+v, want read-only", ann)
	}

	s.collector = nil
	s.poolAds = nil
	if err := callPoolErr(t, s, nil); err == nil {
		t.Error("query_pool with no collector did not refuse")
	}
}
