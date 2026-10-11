package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// query_pool: what condor_status answers, for an agent that has no shell.
//
// Two modes. A summary is the default because the question is almost always
// "what does the pool look like", and on a pool the size of the OSPool
// (50k+ slots) a listing of ads is not an answer to that: it is either
// truncated at a few hundred rows, which describes nothing, or it is the
// whole pool, which does not fit in a context window. The summary instead
// streams every matching ad through a narrow projection and counts on this
// side, so what crosses into the model is a few dozen numbers.
//
// The listing exists for the questions a summary cannot answer -- which
// machines, which slot names -- and is bounded twice over like the job
// listings: a working-set projection, and maxToolResults rows.

// poolAdSource is the part of *htcondor.Collector query_pool reads through.
// An interface so the handler can be tested against a fake collector.
type poolAdSource interface {
	QueryAdsStream(ctx context.Context, adType string, constraint string, projection []string,
		limit int, streamOpts *htcondor.StreamOptions) (<-chan htcondor.AdResult, error)
}

// poolSource is where query_pool reads, or nil when this server has no
// collector. The nil check is on the concrete pointer: a nil
// *htcondor.Collector stored in the interface would not compare equal to
// nil, and the tool would be offered and then fail on every call.
func (s *Server) poolSource() poolAdSource {
	if s.poolAds != nil {
		return s.poolAds
	}
	if s.collector != nil {
		return s.collector
	}
	return nil
}

// poolAdKind is one ad type query_pool serves, and how it is summarized.
type poolAdKind struct {
	// name is the value of the ad_type argument.
	name string
	// noun names one ad in the text answer.
	noun string
	// adType is the collector query type.
	adType string
	// listAttrs is the listing's default projection.
	listAttrs []string
	// groupBy is the summary's default grouping. Empty is one total.
	groupBy []string
	// sums are the attributes the summary totals.
	sums []string
	// slots enables the slot-specific accounting: slot types, and each
	// summed resource split into claimed and unclaimed.
	slots bool
}

// poolAdKinds is the ad_type enum. Deliberately small: these are the ads
// condor_status shows with no option, -schedd, -submitters, -negotiator
// and -collector, which between them answer what the pool is, who is
// submitting to it, and whether its central manager is healthy.
var poolAdKinds = []poolAdKind{
	{
		name: "slots", noun: "slot", adType: htcondor.StartdAdType,
		listAttrs: []string{
			"Name", "Machine", "SlotType", "State", "Activity",
			"Cpus", "Memory", "Disk", "GPUs", "LoadAvg",
			"OpSys", "OpSysAndVer", "Arch", "EnteredCurrentState",
		},
		groupBy: []string{"State", "Activity"},
		sums:    []string{"Cpus", "Memory", "GPUs"},
		slots:   true,
	},
	{
		name: "schedd", noun: "schedd", adType: htcondor.ScheddAdType,
		listAttrs: []string{
			"Name", "Machine", "TotalRunningJobs", "TotalIdleJobs", "TotalHeldJobs",
			"TotalJobAds", "NumUsers", "CondorVersion",
		},
		sums: []string{"TotalRunningJobs", "TotalIdleJobs", "TotalHeldJobs"},
	},
	{
		name: "submitter", noun: "submitter", adType: htcondor.SubmitterAdType,
		listAttrs: []string{"Name", "ScheddName", "RunningJobs", "IdleJobs", "HeldJobs"},
		sums:      []string{"RunningJobs", "IdleJobs", "HeldJobs"},
	},
	{
		name: "negotiator", noun: "negotiator", adType: htcondor.NegotiatorAdType,
		listAttrs: []string{
			"Name", "Machine", "CondorVersion",
			"LastNegotiationCycleEnd0", "LastNegotiationCycleDuration0",
			"LastNegotiationCycleMatches0", "LastNegotiationCycleRejections0",
		},
	},
	{
		name: "collector", noun: "collector", adType: htcondor.CollectorAdType,
		listAttrs: []string{
			"Name", "Machine", "CondorVersion",
			"HostsTotal", "HostsClaimed", "HostsUnclaimed", "HostsOwner",
			"RunningJobs", "IdleJobs", "SubmitterAds",
		},
	},
}

// poolAdKindAliases maps the other spellings of an ad type an agent is
// likely to try -- condor_status's own option names among them -- onto the
// enum. Accepted quietly; the enum in the schema is what is advertised.
var poolAdKindAliases = map[string]string{
	"slot": "slots", "startd": "slots", "startds": "slots", "machine": "slots", "machines": "slots",
	"schedds": "schedd", "scheduler": "schedd",
	"submitters": "submitter", "submittor": "submitter", "submittors": "submitter",
	"negotiators": "negotiator", "collectors": "collector",
}

func lookupPoolAdKind(name string) (*poolAdKind, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		n = "slots"
	}
	if alias, ok := poolAdKindAliases[n]; ok {
		n = alias
	}
	for i := range poolAdKinds {
		if poolAdKinds[i].name == n {
			return &poolAdKinds[i], nil
		}
	}
	return nil, fmt.Errorf("unknown ad_type %q: use one of %s", name, strings.Join(poolAdKindNames(), ", "))
}

func poolAdKindNames() []string {
	names := make([]string, len(poolAdKinds))
	for i, k := range poolAdKinds {
		names[i] = k.name
	}
	return names
}

// Limits on a summary. A summary has no row limit -- it is only an answer
// if it covers every matching ad -- so what bounds it is the scan and the
// size of the grouping.
const (
	// maxPoolSummaryAds stops a summary scan. Several times the largest
	// pool this has to describe (the OSPool's slots, dynamic ones
	// included), so reaching it means a runaway query, and the answer
	// says the counts are partial.
	maxPoolSummaryAds = 500000
	// maxPoolGroups is the most groups a summary returns. A group_by on
	// a near-unique attribute (Name, Machine) would otherwise be a
	// listing by another route.
	maxPoolGroups = 200
	// poolQueryTimeout bounds one collector query.
	poolQueryTimeout = 60 * time.Second
	// defaultPoolListLimit is the listing's row count when none is given.
	defaultPoolListLimit = 50
)

// isPrivatePoolAttr reports an attribute HTCondor treats as private: claim
// ids and capabilities, which are bearer credentials for a slot, and
// anything "_condor_priv"-prefixed. The collector withholds them from a
// query by an ordinary user, but it releases them to a client it
// authorizes at DAEMON level, and this server may query with a credential
// of its own. So they are refused here in every argument and stripped from
// every ad, whatever the collector sends: this tool answers what anonymous
// condor_status would, and never more.
//
// classad.IsPrivateAttribute mirrors HTCondor's ClassAdPrivateAttrs and
// is the list every serialization layer shares.
func isPrivatePoolAttr(name string) bool {
	return classad.IsPrivateAttribute(name)
}

// privateAttrInExpr reports the first private attribute a constraint
// names, by identifier, outside string literals -- so "CUDACapability"
// and a literal "ClaimId" are not mistaken for one. A constraint that
// tests a private attribute is an oracle for it even when the attribute
// is never returned, which is why this is checked rather than only the
// output being stripped. eval() is refused for the same reason: it
// builds an attribute reference out of a string.
func privateAttrInExpr(expr string) (string, bool) {
	ident := strings.Builder{}
	flush := func() (string, bool) {
		defer ident.Reset()
		if ident.Len() == 0 {
			return "", false
		}
		word := ident.String()
		if isPrivatePoolAttr(word) || strings.EqualFold(word, "eval") {
			return word, true
		}
		return "", false
	}
	inString := false
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inString {
			switch c {
			case '\\':
				i++
			case '"':
				inString = false
			}
			continue
		}
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			ident.WriteByte(c)
			continue
		}
		if w, bad := flush(); bad {
			return w, true
		}
		if c == '"' {
			inString = true
		}
	}
	return flush()
}

// stripPrivatePoolAttrs removes private attributes from an ad in place.
func stripPrivatePoolAttrs(ad *classad.ClassAd) {
	for _, name := range ad.GetAttributes() {
		if isPrivatePoolAttr(name) {
			ad.Delete(name)
		}
	}
}

func queryPoolTool() Tool {
	slots := &poolAdKinds[0]
	return Tool{
		Name: "query_pool",
		Description: "Describe the HTCondor pool this access point submits to: the execute slots and their state, " +
			"how many CPUs, GPUs and how much memory exist and how much is claimed or unclaimed, which machines there are, " +
			"and the pool's schedds, submitters, negotiator and collector -- what condor_status shows. " +
			"Use it to answer what resources exist before choosing a request, or whether the pool is busy. " +
			"The default answer is a summary (counts and totals over every matching ad), which is the right way to get an overview; " +
			"mode=list returns individual ads, at most " + strconv.Itoa(maxToolResults) + ", for questions about specific machines or slots. " +
			"For why one of your jobs does not match, use analyze_job_match instead.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"ad_type": map[string]interface{}{
					"type": "string",
					"enum": poolAdKindNames(),
					"description": "What to describe: 'slots' (default; execute slots, as plain condor_status), " +
						"'schedd' (access points), 'submitter' (users with jobs in the pool, per access point), " +
						"'negotiator' or 'collector' (the central manager).",
				},
				"mode": map[string]interface{}{
					"type": "string",
					"enum": []string{"summary", "list"},
					"description": "'summary' (default): counts and totals over every matching ad. " +
						"'list': the ads themselves, bounded by limit.",
				},
				"constraint": map[string]interface{}{
					"type": "string",
					"description": "ClassAd expression selecting ads (default: all). " +
						"Examples: 'GPUs > 0', 'State == \"Unclaimed\"', 'OpSys == \"LINUX\" && Arch == \"X86_64\"', " +
						"'Machine == \"node01.example.org\"'.",
				},
				"group_by": map[string]interface{}{
					"type":  "array",
					"items": map[string]interface{}{"type": "string"},
					"description": "Summary only: attributes to count by. Default for slots: " +
						strings.Join(slots.groupBy, ", ") + "; for other ad types, one total. " +
						"Examples: [\"OpSys\", \"Arch\"], [\"CUDADeviceName\"], [\"SlotType\"]. " +
						"At most " + strconv.Itoa(maxPoolGroups) + " groups are returned, largest first.",
				},
				"projection": map[string]interface{}{
					"type":  "array",
					"items": map[string]interface{}{"type": "string"},
					"description": "List only: attributes to return. Defaults to a working set per ad type (for slots: " +
						strings.Join(slots.listAttrs, ", ") + "). Use ['*'] for every attribute -- expensive: " +
						"a slot ad carries hundreds of attributes.",
				},
				"limit": map[string]interface{}{
					"type": "integer",
					"description": fmt.Sprintf("List only: maximum ads to return (default %d, hard ceiling %d). "+
						"Past that, narrow the constraint or use the summary.", defaultPoolListLimit, maxToolResults),
				},
			},
		},
	}
}

// toolQueryPool implements the query_pool tool.
//
// The collector is queried with the request's context, which is how every
// collector read in this server authenticates: as the caller where the
// transport established one, as this process otherwise.
func (s *Server) toolQueryPool(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	src := s.poolSource()
	if src == nil {
		return nil, fmt.Errorf("query_pool needs a collector, and this server has none configured")
	}

	adTypeArg, _ := args["ad_type"].(string)
	kind, err := lookupPoolAdKind(adTypeArg)
	if err != nil {
		return nil, err
	}

	mode, _ := args["mode"].(string)
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "summary"
	}
	if mode != "summary" && mode != "list" {
		return nil, fmt.Errorf("unknown mode %q: use 'summary' or 'list'", mode)
	}

	constraint, _ := args["constraint"].(string)
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		constraint = "true"
	}
	if name, bad := privateAttrInExpr(constraint); bad {
		return nil, fmt.Errorf("the constraint names %q, which this tool does not evaluate: "+
			"claim ids and capabilities are private to the pool's daemons", name)
	}
	if _, err := classad.ParseExpr(constraint); err != nil {
		return nil, fmt.Errorf("invalid constraint %q: %w", constraint, err)
	}

	ctx, cancel := context.WithTimeout(ctx, poolQueryTimeout)
	defer cancel()

	if mode == "list" {
		return s.queryPoolList(ctx, src, kind, constraint, args)
	}
	return s.queryPoolSummary(ctx, src, kind, constraint, args)
}

// privateAttrArg refuses a private attribute named in an attribute-list
// argument.
func privateAttrArg(arg string, attrs []string) error {
	for _, a := range attrs {
		if isPrivatePoolAttr(a) {
			return fmt.Errorf("%s names %q, which this tool does not return: "+
				"claim ids and capabilities are private to the pool's daemons", arg, a)
		}
	}
	return nil
}

func (s *Server) queryPoolList(ctx context.Context, src poolAdSource, kind *poolAdKind, constraint string,
	args map[string]interface{}) (interface{}, error) {
	requested := stringListArg(args, "projection")
	if err := privateAttrArg("projection", requested); err != nil {
		return nil, err
	}
	// Always an explicit projection: an empty one would mean the
	// library's default, which is six identity attributes, and every
	// resource column would come back absent. "*" is the one way to ask
	// for everything, and goes to the collector as no projection.
	projection, _ := projectionOrDefault(requested, kind.listAttrs)

	limit := defaultPoolListLimit
	if v, ok := args["limit"].(float64); ok {
		limit = int(v)
	}
	limit, capped := clampToolLimit(limit)

	// One more than will be returned, so that "more match" is something
	// observed rather than guessed from a full page.
	ads, err := collectPoolAds(ctx, src, kind.adType, constraint, projection, limit+1, nil)
	if err != nil {
		return nil, err
	}
	hasMore := len(ads) > limit
	if hasMore {
		ads = ads[:limit]
	}
	for _, ad := range ads {
		stripPrivatePoolAttrs(ad)
	}
	sortPoolAds(ads)

	text, structured := renderPoolList(kind, constraint, ads, hasMore)
	if hasMore {
		text += poolTruncationNote(limit, capped)
	}
	if wantsAllAttributes(requested) {
		text += "\n\nReturning every attribute, which is far larger than the default working set " +
			"(a slot ad carries hundreds). Name the attributes you need in `projection` " +
			"if this crowds out the rest of the answer."
	}
	return structuredTextResult(text, structured), nil
}

// poolTruncationNote explains a listing that stopped short. Unlike the job
// listings' note, the alternative it offers is this tool's own summary.
func poolTruncationNote(effective int, capped bool) string {
	if capped {
		return fmt.Sprintf("\n\nStopped at %d ads, the most this tool returns in one call -- more match. "+
			"Raising the limit will not return more. Narrow the constraint (Machine, State, SlotType), "+
			"or call query_pool with mode=summary to count every match.", effective)
	}
	return fmt.Sprintf("\n\nStopped at the requested limit of %d; more match. Raise limit (up to %d), "+
		"narrow the constraint, or call query_pool with mode=summary to count every match.",
		effective, maxToolResults)
}

// sortPoolAds orders a listing by Machine, then Name. The collector's own
// order is its hash table's, which differs call to call.
func sortPoolAds(ads []*classad.ClassAd) {
	key := func(ad *classad.ClassAd, attr string) string {
		v, _ := ad.EvaluateAttrString(attr)
		return v
	}
	sort.SliceStable(ads, func(i, j int) bool {
		mi, mj := key(ads[i], "Machine"), key(ads[j], "Machine")
		if mi != mj {
			return mi < mj
		}
		return key(ads[i], "Name") < key(ads[j], "Name")
	})
}

func renderPoolList(kind *poolAdKind, constraint string, ads []*classad.ClassAd, hasMore bool) (string, map[string]interface{}) {
	if ads == nil {
		ads = []*classad.ClassAd{}
	}
	raw, err := json.Marshal(ads)
	if err != nil {
		raw = []byte("[]")
	}
	text := fmt.Sprintf("Found %d %s ad(s) matching constraint '%s':\n%s", len(ads), kind.noun, constraint, raw)
	return text, map[string]interface{}{
		"ad_type":    kind.name,
		"mode":       "list",
		"constraint": constraint,
		"count":      len(ads),
		"ads":        ads,
		"has_more":   hasMore,
	}
}

func (s *Server) queryPoolSummary(ctx context.Context, src poolAdSource, kind *poolAdKind, constraint string,
	args map[string]interface{}) (interface{}, error) {
	groupBy := kind.groupBy
	if _, given := args["group_by"]; given {
		// An explicit empty list is a request for one total.
		groupBy = stringListArg(args, "group_by")
	}
	if err := privateAttrArg("group_by", groupBy); err != nil {
		return nil, err
	}

	agg := newPoolAggregator(kind, groupBy)
	_, err := collectPoolAds(ctx, src, kind.adType, constraint, agg.projection(), maxPoolSummaryAds+1, agg.add)
	if err != nil {
		return nil, err
	}
	structured := agg.structured(constraint)
	return structuredTextResult(agg.text(constraint), structured), nil
}

// collectPoolAds runs one collector query. With visit set, each ad is
// handed to it and not kept, so a summary over a large pool holds one ad
// at a time; without, the ads are returned.
func collectPoolAds(ctx context.Context, src poolAdSource, adType, constraint string, projection []string,
	limit int, visit func(*classad.ClassAd)) ([]*classad.ClassAd, error) {
	ch, err := src.QueryAdsStream(ctx, adType, constraint, projection, limit,
		&htcondor.StreamOptions{BufferSize: 1000, WriteTimeout: poolQueryTimeout})
	if err != nil {
		return nil, fmt.Errorf("querying the collector: %w", err)
	}
	var ads []*classad.ClassAd
	for r := range ch {
		if r.Err != nil {
			// An error is the stream's last message: the producer closes
			// the channel after sending it.
			return nil, fmt.Errorf("querying the collector: %w", r.Err)
		}
		if r.Ad == nil {
			continue
		}
		if visit != nil {
			visit(r.Ad)
			continue
		}
		ads = append(ads, r.Ad)
	}
	return ads, nil
}

// --- summary aggregation ---------------------------------------------------

// What a summary counts, for slots.
//
// Each slot contributes its own Cpus, Memory and GPUs. That is what makes
// the totals right for partitionable slots without special-casing them: a
// partitionable slot advertises only what it has left, and each dynamic
// slot carved from it advertises what it holds, so across a machine's
// partitionable slot and its dynamic slots the sum is the machine's
// capacity, counted once. (Summing TotalSlotCpus on the partitionable slot
// AND Cpus on the dynamic ones would count claimed resources twice.)
//
// Claimed and unclaimed follow State: a dynamic slot is Claimed, so what it
// holds is claimed; a partitionable slot is Unclaimed while it can still be
// carved, so its remainder is unclaimed; a static slot is whichever it is.
// Anything else -- Owner, Matched, Preempting, Drained, Backfill -- is
// reported as other, since it is neither in use by a job nor available to
// one.
//
// The consequence a caller has to know: a constraint that excludes dynamic
// slots excludes what they hold, so the totals then cover only what is
// left. The answer says this in its text.

// poolGroup is one row of a grouped summary.
type poolGroup struct {
	key    []string
	count  int
	totals map[string]float64
}

// poolResource splits one summed attribute by slot state.
type poolResource struct {
	Total     float64 `json:"total"`
	Claimed   float64 `json:"claimed"`
	Unclaimed float64 `json:"unclaimed"`
	Other     float64 `json:"other"`
}

type poolAggregator struct {
	kind    *poolAdKind
	groupBy []string

	count     int
	truncated bool
	machines  map[string]struct{}
	groups    map[string]*poolGroup
	totals    map[string]float64
	// missing counts, per summed attribute, the ads that did not carry it
	// as a number. Reported rather than read as zero: a slot that does
	// not advertise Cpus has not told us it has none, and a summary that
	// added it as zero would undercount without saying so.
	missing   map[string]int
	resources map[string]*poolResource
	slotTypes map[string]int
}

func newPoolAggregator(kind *poolAdKind, groupBy []string) *poolAggregator {
	a := &poolAggregator{
		kind:     kind,
		groupBy:  append([]string{}, groupBy...),
		machines: map[string]struct{}{},
		groups:   map[string]*poolGroup{},
		totals:   map[string]float64{},
		missing:  map[string]int{},
	}
	for _, attr := range kind.sums {
		a.totals[attr] = 0
		a.missing[attr] = 0
	}
	if kind.slots {
		a.resources = map[string]*poolResource{}
		for _, attr := range kind.sums {
			a.resources[attr] = &poolResource{}
		}
		a.slotTypes = map[string]int{}
	}
	return a
}

// projection is every attribute the summary reads and nothing else. Never
// empty: an empty projection is the library's six-attribute default, under
// which every summed attribute would be absent.
func (a *poolAggregator) projection() []string {
	var out []string
	seen := map[string]bool{}
	add := func(names ...string) {
		for _, n := range names {
			if k := strings.ToLower(n); !seen[k] {
				seen[k] = true
				out = append(out, n)
			}
		}
	}
	add("Name", "Machine")
	add(a.groupBy...)
	add(a.kind.sums...)
	if a.kind.slots {
		add("State", "SlotType", "PartitionableSlot", "DynamicSlot")
	}
	return out
}

// add folds one ad into the summary.
func (a *poolAggregator) add(ad *classad.ClassAd) {
	if a.count >= maxPoolSummaryAds {
		a.truncated = true
		return
	}
	a.count++

	if m, ok := ad.EvaluateAttrString("Machine"); ok && m != "" {
		a.machines[m] = struct{}{}
	}

	values := make(map[string]float64, len(a.kind.sums))
	for _, attr := range a.kind.sums {
		v, ok := ad.EvaluateAttrNumber(attr)
		if !ok {
			a.missing[attr]++
			continue
		}
		values[attr] = v
		a.totals[attr] += v
	}

	if a.kind.slots {
		a.slotTypes[slotTypeOf(ad)]++
		state, _ := ad.EvaluateAttrString("State")
		for attr, v := range values {
			r := a.resources[attr]
			r.Total += v
			switch state {
			case "Claimed":
				r.Claimed += v
			case "Unclaimed":
				r.Unclaimed += v
			default:
				r.Other += v
			}
		}
	}

	key := make([]string, len(a.groupBy))
	for i, attr := range a.groupBy {
		key[i] = groupValue(ad, attr)
	}
	id := strings.Join(key, "\x00")
	g := a.groups[id]
	if g == nil {
		g = &poolGroup{key: key, totals: map[string]float64{}}
		a.groups[id] = g
	}
	g.count++
	for attr, v := range values {
		g.totals[attr] += v
	}
}

// slotTypeOf classifies a slot. SlotType is what every current startd
// publishes; the two booleans are the older spelling. A slot that carries
// neither is reported as such rather than assumed static.
func slotTypeOf(ad *classad.ClassAd) string {
	if t, ok := ad.EvaluateAttrString("SlotType"); ok && t != "" {
		return t
	}
	if b, ok := ad.EvaluateAttrBool("PartitionableSlot"); ok && b {
		return "Partitionable"
	}
	if b, ok := ad.EvaluateAttrBool("DynamicSlot"); ok && b {
		return "Dynamic"
	}
	return "(not advertised)"
}

// undefinedGroup is the group key of an ad that does not carry the
// attribute. Its own group, never folded into a value's.
const undefinedGroup = "(undefined)"

// groupValue renders one attribute's value as a group key.
func groupValue(ad *classad.ClassAd, attr string) string {
	v := ad.EvaluateAttr(attr)
	switch {
	case v.IsUndefined():
		return undefinedGroup
	case v.IsString():
		s, _ := v.StringValue()
		return s
	default:
		return v.String()
	}
}

// sortedGroups returns the groups largest first, ties by key, and how many
// there were before maxPoolGroups cut the list.
func (a *poolAggregator) sortedGroups() ([]*poolGroup, int) {
	groups := make([]*poolGroup, 0, len(a.groups))
	for _, g := range a.groups {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].count != groups[j].count {
			return groups[i].count > groups[j].count
		}
		return strings.Join(groups[i].key, "\x00") < strings.Join(groups[j].key, "\x00")
	})
	total := len(groups)
	if total > maxPoolGroups {
		groups = groups[:maxPoolGroups]
	}
	return groups, total
}

func (a *poolAggregator) structured(constraint string) map[string]interface{} {
	groups, groupsTotal := a.sortedGroups()
	rows := make([]map[string]interface{}, 0, len(groups))
	for _, g := range groups {
		rows = append(rows, map[string]interface{}{
			"key":    g.key,
			"count":  g.count,
			"totals": g.totals,
		})
	}
	out := map[string]interface{}{
		"ad_type":          a.kind.name,
		"mode":             "summary",
		"constraint":       constraint,
		"count":            a.count,
		"machines":         len(a.machines),
		"group_by":         a.groupBy,
		"groups":           rows,
		"groups_total":     groupsTotal,
		"groups_truncated": groupsTotal > len(groups),
		"totals":           a.totals,
		"missing":          a.missing,
		"truncated":        a.truncated,
	}
	if a.kind.slots {
		out["resources"] = a.resources
		out["slot_types"] = a.slotTypes
	}
	return out
}

// text renders the summary for the model. Complete on its own: a client
// that shows the model only the text block must lose nothing.
func (a *poolAggregator) text(constraint string) string {
	var b strings.Builder
	noun := a.kind.noun
	fmt.Fprintf(&b, "Pool summary: %d %s ad(s)", a.count, noun)
	if a.kind.slots && len(a.machines) > 0 {
		fmt.Fprintf(&b, " on %d machine(s)", len(a.machines))
	}
	fmt.Fprintf(&b, " matching constraint '%s'.\n", constraint)
	if a.truncated {
		fmt.Fprintf(&b, "PARTIAL: the scan stopped at %d ads; every count below covers only those. Narrow the constraint.\n",
			maxPoolSummaryAds)
	}

	if a.kind.slots && a.count > 0 {
		b.WriteString("\nSlot types: " + formatCounts(a.slotTypes) + ".\n")
		b.WriteString("\nResources (each slot's own Cpus, Memory in MiB, GPUs; claimed/unclaimed by slot State):\n")
		for _, attr := range a.kind.sums {
			r := a.resources[attr]
			fmt.Fprintf(&b, "- %s: %s total, %s claimed, %s unclaimed, %s in other states",
				attr, formatNum(r.Total), formatNum(r.Claimed), formatNum(r.Unclaimed), formatNum(r.Other))
			if n := a.missing[attr]; n > 0 {
				fmt.Fprintf(&b, " (%d slot(s) do not advertise %s", n, attr)
				if attr == "GPUs" {
					b.WriteString("; they have none")
				}
				b.WriteString(")")
			}
			b.WriteString("\n")
		}
		b.WriteString("A partitionable slot advertises what it has left and each dynamic slot what it holds, " +
			"so these totals are the capacity of the matched machines as long as the constraint does not exclude dynamic slots.\n")
	} else if len(a.kind.sums) > 0 && a.count > 0 {
		b.WriteString("\nTotals:\n")
		for _, attr := range a.kind.sums {
			fmt.Fprintf(&b, "- %s: %s", attr, formatNum(a.totals[attr]))
			if n := a.missing[attr]; n > 0 {
				fmt.Fprintf(&b, " (%d ad(s) do not advertise it)", n)
			}
			b.WriteString("\n")
		}
	}

	if len(a.groupBy) > 0 && a.count > 0 {
		groups, total := a.sortedGroups()
		fmt.Fprintf(&b, "\nBy %s:\n", strings.Join(a.groupBy, ", "))
		for _, g := range groups {
			fmt.Fprintf(&b, "- %s: %d %s(s)", strings.Join(g.key, " / "), g.count, noun)
			for _, attr := range a.kind.sums {
				if v, ok := g.totals[attr]; ok {
					fmt.Fprintf(&b, ", %s %s", attr, formatNum(v))
				}
			}
			b.WriteString("\n")
		}
		if total > len(groups) {
			fmt.Fprintf(&b, "(%d more groups not shown: the %d largest are above. Group by fewer or coarser attributes.)\n",
				total-len(groups), len(groups))
		}
	}
	if a.count == 0 {
		b.WriteString("\nNothing matched.\n")
	}
	return b.String()
}

// formatCounts renders a count map largest first.
func formatCounts(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = fmt.Sprintf("%d %s", p.v, p.k)
	}
	return strings.Join(parts, ", ")
}

// formatNum prints a total without a spurious fraction.
func formatNum(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
