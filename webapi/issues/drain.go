// Package issues groups the things going wrong on an access point into a
// handful of problems a person can act on.
//
// The clustering is Drain (He et al., ICWS 2017), the algorithm Drain3
// implements: mask the per-occurrence detail out of each message, bucket
// what is left by token count and leading tokens, and inside a bucket
// merge a message into the first cluster it is similar enough to,
// widening that cluster's template with a wildcard wherever they differ.
// It is a single pass, no training step and no state carried between
// requests, which is what makes it usable behind a page that re-clusters
// whenever somebody moves the granularity slider.
//
// Why not group by HoldReasonCode: see mask.go. Why not by exact text:
// also mask.go. The short version is that one root cause on OSPool
// produces thousands of distinct hold reasons and a dozen codes cover
// everything that can go wrong, so both of the obvious groupings answer
// a question nobody asked.
package issues

import (
	"sort"
	"strings"
)

// Record is one occurrence of something going wrong: a job that was held,
// or one whose shadow threw an exception.
type Record struct {
	// Kind separates the sections of the page. Records of different
	// kinds never share a cluster, however alike their text.
	Kind    string
	Message string
	Owner   string
	Cluster int64
	Proc    int64
	Batch   string
	// At is when it happened, in Unix seconds.
	At int64
	// Code and SubCode are HTCondor's own classification, kept so a
	// cluster can still report it even though it did not group on it.
	Code    int64
	SubCode int64
}

// Example is one occurrence shown under a cluster.
type Example struct {
	Cluster int64  `json:"cluster_id"`
	Proc    int64  `json:"proc_id"`
	Owner   string `json:"owner,omitempty"`
	Batch   string `json:"batch,omitempty"`
	At      int64  `json:"at,omitempty"`
	Message string `json:"message,omitempty"`
}

// OwnerCount is how much of a cluster belongs to one user.
type OwnerCount struct {
	Owner string `json:"owner"`
	Count int    `json:"count"`
}

// CodeCount is one HoldReasonCode/SubCode pair inside a cluster, with
// HTCondor's own name for it.
type CodeCount struct {
	Code    int64  `json:"code"`
	SubCode int64  `json:"subcode"`
	Label   string `json:"label,omitempty"`
	Count   int    `json:"count"`
}

// Cluster is one problem: how big it is, who it is happening to, and
// enough examples to recognise it.
type Cluster struct {
	Kind string `json:"kind"`
	// Template is the masked, wildcarded form -- what the occurrences
	// have in common. Shown as the cluster's identity when the examples
	// disagree too much for any one of them to stand for the rest.
	Template string `json:"template"`
	Count    int    `json:"count"`
	// Users is how many distinct people this is happening to, which is
	// the difference between one user's broken submit file and a site
	// problem.
	Users     int          `json:"users"`
	TopUsers  []OwnerCount `json:"top_users,omitempty"`
	Codes     []CodeCount  `json:"codes,omitempty"`
	FirstSeen int64        `json:"first_seen,omitempty"`
	LastSeen  int64        `json:"last_seen,omitempty"`
	Examples  []Example    `json:"examples,omitempty"`
	// Variants are the distinct templates a coarse granularity folded
	// together, largest first. Present only when more than one was
	// merged, and shown in the expanded card: a cluster that quietly
	// merged two different problems under the larger one's name would
	// be worse than not merging at all.
	Variants []Variant `json:"variants,omitempty"`
}

// Variant is one template inside a merged cluster.
type Variant struct {
	Template string `json:"template"`
	Count    int    `json:"count"`
}

// Tunables. Depth is Drain's tree depth: the token count plus this many
// leading tokens select the bucket a message is compared within.
const (
	treeDepth   = 2
	maxExamples = 25
	maxTopUsers = 5
	// A cap on distinct clusters, so a pathological corpus (every
	// message unique after masking) cannot turn one page load into tens
	// of thousands of comparisons per record. Past it, records that
	// match nothing land in one overflow cluster.
	maxClusters = 2000
)

// Similarity returns the fraction of token positions two token sequences
// agree on. A wildcard in the template matches nothing: it is already
// known to vary, so counting it as agreement would let a template that
// had widened once keep swallowing everything it met.
func similarity(template, tokens []string) float64 {
	if len(template) != len(tokens) || len(tokens) == 0 {
		return 0
	}
	same := 0
	for i := range tokens {
		if template[i] != wildcard && template[i] == tokens[i] {
			same++
		}
	}
	return float64(same) / float64(len(tokens))
}

const wildcard = "<*>"

type node struct {
	children map[string]*node
	clusters []*group
}

type group struct {
	kind     string
	template []string
	records  []Record
}

// drainThreshold is Drain's similarity threshold for the first pass.
//
// Fixed rather than exposed, because on this corpus it does nothing.
// Measured against real ap40 hold reasons, every threshold from 0.2 to
// 0.8 produced exactly the same four clusters: masking removes the
// variation that the threshold would otherwise arbitrate, and messages
// from genuinely different problems land in different buckets of the
// parse tree, where no threshold can bring them together. Exposing it as
// the page's granularity control would have been a slider that did
// nothing. The granularity control is the merge pass below, which
// operates on whole templates and does have the range the name implies.
const drainThreshold = 0.5

// Clusterer is one pass of Drain over a set of records.
//
// Adding records and rendering them are separate so that re-rendering at
// a new granularity does not re-read the records: the expensive half is
// the scan that produced them, and a facilitator dragging the slider is
// asking a different question about the same scan.
type Clusterer struct {
	root     *node
	groups   []*group
	overflow map[string]*group
}

// NewClusterer returns an empty clusterer.
func NewClusterer() *Clusterer {
	return &Clusterer{
		root:     &node{children: map[string]*node{}},
		overflow: map[string]*group{},
	}
}

// Add files one record.
func (c *Clusterer) Add(rec Record) {
	tokens := tokenize(Mask(rec.Message))
	if len(tokens) == 0 {
		// Nothing to cluster on. Kept rather than dropped -- a hold with
		// an empty reason is itself worth seeing -- under a template
		// that says so.
		c.addToOverflow(rec, "(no message)")
		return
	}

	leaf := c.leafFor(rec.Kind, tokens)
	best, bestSim := (*group)(nil), 0.0
	for _, g := range leaf.clusters {
		if g.kind != rec.Kind {
			continue
		}
		if sim := similarity(g.template, tokens); sim > bestSim {
			best, bestSim = g, sim
		}
	}

	if best != nil && bestSim >= drainThreshold {
		// Widen the template wherever this message disagrees with it.
		for i := range best.template {
			if best.template[i] != tokens[i] {
				best.template[i] = wildcard
			}
		}
		best.records = append(best.records, rec)
		return
	}

	if len(c.groups) >= maxClusters {
		c.addToOverflow(rec, "(other)")
		return
	}
	g := &group{kind: rec.Kind, template: append([]string(nil), tokens...), records: []Record{rec}}
	leaf.clusters = append(leaf.clusters, g)
	c.groups = append(c.groups, g)
}

func (c *Clusterer) addToOverflow(rec Record, template string) {
	key := rec.Kind + "\x00" + template
	g := c.overflow[key]
	if g == nil {
		g = &group{kind: rec.Kind, template: []string{template}}
		c.overflow[key] = g
		c.groups = append(c.groups, g)
	}
	g.records = append(g.records, rec)
}

// leafFor walks (kind, token count, leading tokens) down to the list of
// clusters a message may join.
//
// Bucketing by token count is Drain's, and masking is what makes it
// work: the raw messages of one issue differ in length constantly, and
// their masked forms almost never do.
func (c *Clusterer) leafFor(kind string, tokens []string) *node {
	cur := c.root
	step := func(key string) {
		next := cur.children[key]
		if next == nil {
			next = &node{children: map[string]*node{}}
			cur.children[key] = next
		}
		cur = next
	}
	step(kind)
	step(itoa(len(tokens)))
	for i := 0; i < treeDepth && i < len(tokens); i++ {
		tok := tokens[i]
		// A leading token that is already a placeholder is not a useful
		// discriminator, and branching on it would put every occurrence
		// of the issue in its own subtree.
		if strings.HasPrefix(tok, "<") {
			tok = wildcard
		}
		step(tok)
	}
	return cur
}

// Clusters renders the result at the requested granularity, largest
// first.
//
// granularity runs 0 (coarsest) to 1 (finest). At 1 the Drain templates
// are returned as they are; below it, templates that share enough of
// their vocabulary are merged, so "Transfer output files failure ..." and
// "Transfer input files failure ..." become one row about file transfer
// while "memory usage exceeded request_memory" stays its own.
func (c *Clusterer) Clusters(granularity float64, labelCode func(code int64) string) []Cluster {
	merged := mergeGroups(c.groups, granularity)
	out := make([]Cluster, 0, len(merged))
	for _, m := range merged {
		if len(m) == 0 {
			continue
		}
		out = append(out, summarize(m, labelCode))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		// Ties broken on the template so a re-render of unchanged data
		// does not reshuffle the page.
		return out[i].Template < out[j].Template
	})
	return out
}

// mergeGroups is the granularity pass: agglomerate Drain's templates
// until nothing is similar enough to join.
//
// Similarity is Jaccard over the templates' non-placeholder tokens --
// the words, ignoring everything masking already called a variable. That
// is the right measure here because the templates being compared are
// short and their shared vocabulary is exactly what makes two of them
// "the same kind of problem" to a person reading the page.
//
// O(k^2) in the number of templates, which is fine: Drain has already
// reduced tens of thousands of messages to a handful of them, and this
// pass is what runs again when the slider moves.
func mergeGroups(groups []*group, granularity float64) [][]*group {
	if granularity >= 1 {
		out := make([][]*group, 0, len(groups))
		for _, g := range groups {
			out = append(out, []*group{g})
		}
		return out
	}
	if granularity < 0 {
		granularity = 0
	}
	// A cutoff of 1 would merge nothing and 0 would merge everything into
	// one row. The usable band is in between, and the ends of the slider
	// should still be usable settings rather than degenerate ones.
	cutoff := 0.15 + 0.7*granularity

	// Largest first, so a merged cluster's dominant template is the one
	// it gets named after and the result does not depend on parse order.
	ordered := append([]*group(nil), groups...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(ordered[i].records) > len(ordered[j].records)
	})

	var buckets [][]*group
	var vocabs []map[string]bool
	for _, g := range ordered {
		v := vocabulary(g.template)
		placed := false
		for i := range buckets {
			// Compared against the bucket's accumulated vocabulary, so
			// membership does not depend on which member happened to be
			// compared first.
			if jaccard(v, vocabs[i]) >= cutoff && buckets[i][0].kind == g.kind {
				buckets[i] = append(buckets[i], g)
				for tok := range v {
					vocabs[i][tok] = true
				}
				placed = true
				break
			}
		}
		if !placed {
			buckets = append(buckets, []*group{g})
			vocabs = append(vocabs, v)
		}
	}
	return buckets
}

// vocabulary is a template's set of real words: placeholders carry no
// meaning to compare, and a template that is mostly placeholders should
// not look similar to every other template that is.
func vocabulary(template []string) map[string]bool {
	v := map[string]bool{}
	for _, t := range template {
		if strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">") {
			continue
		}
		v[strings.ToLower(t)] = true
	}
	return v
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for tok := range a {
		if b[tok] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func summarize(bucket []*group, labelCode func(int64) string) Cluster {
	// Named after its dominant template: the bucket was ordered largest
	// first, so bucket[0] is the problem most of these records are.
	records := make([]Record, 0, len(bucket[0].records))
	cl := Cluster{
		Kind:     bucket[0].kind,
		Template: strings.Join(bucket[0].template, " "),
	}
	for _, g := range bucket {
		records = append(records, g.records...)
		if len(bucket) > 1 {
			cl.Variants = append(cl.Variants, Variant{
				Template: strings.Join(g.template, " "),
				Count:    len(g.records),
			})
		}
	}
	cl.Count = len(records)

	byOwner := map[string]int{}
	byCode := map[[2]int64]int{}
	for _, r := range records {
		if r.Owner != "" {
			byOwner[r.Owner]++
		}
		byCode[[2]int64{r.Code, r.SubCode}]++
		if cl.FirstSeen == 0 || (r.At > 0 && r.At < cl.FirstSeen) {
			cl.FirstSeen = r.At
		}
		if r.At > cl.LastSeen {
			cl.LastSeen = r.At
		}
	}
	cl.Users = len(byOwner)

	for owner, n := range byOwner {
		cl.TopUsers = append(cl.TopUsers, OwnerCount{Owner: owner, Count: n})
	}
	sort.Slice(cl.TopUsers, func(i, j int) bool {
		if cl.TopUsers[i].Count != cl.TopUsers[j].Count {
			return cl.TopUsers[i].Count > cl.TopUsers[j].Count
		}
		return cl.TopUsers[i].Owner < cl.TopUsers[j].Owner
	})
	if len(cl.TopUsers) > maxTopUsers {
		cl.TopUsers = cl.TopUsers[:maxTopUsers]
	}

	for key, n := range byCode {
		cc := CodeCount{Code: key[0], SubCode: key[1], Count: n}
		if labelCode != nil {
			cc.Label = labelCode(key[0])
		}
		cl.Codes = append(cl.Codes, cc)
	}
	sort.Slice(cl.Codes, func(i, j int) bool {
		if cl.Codes[i].Count != cl.Codes[j].Count {
			return cl.Codes[i].Count > cl.Codes[j].Count
		}
		if cl.Codes[i].Code != cl.Codes[j].Code {
			return cl.Codes[i].Code < cl.Codes[j].Code
		}
		return cl.Codes[i].SubCode < cl.Codes[j].SubCode
	})

	cl.Examples = pickExamples(records)
	return cl
}

// pickExamples takes the newest occurrence per user before taking a
// second from anyone.
//
// A facilitator reading a cluster of four thousand is deciding whether
// this is one person's broken submit file or everybody's problem, and a
// list of examples that happens to be one user's first twenty jobs
// answers that question wrongly.
func pickExamples(records []Record) []Example {
	byOwner := map[string][]Record{}
	owners := make([]string, 0, 8)
	for _, r := range records {
		if _, seen := byOwner[r.Owner]; !seen {
			owners = append(owners, r.Owner)
		}
		byOwner[r.Owner] = append(byOwner[r.Owner], r)
	}
	for _, o := range owners {
		rs := byOwner[o]
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].At > rs[j].At })
		byOwner[o] = rs
	}
	// Owners in descending share, so the representative example -- the
	// first one -- comes from whoever this is mostly happening to.
	sort.SliceStable(owners, func(i, j int) bool {
		return len(byOwner[owners[i]]) > len(byOwner[owners[j]])
	})

	out := make([]Example, 0, maxExamples)
	for round := 0; len(out) < maxExamples; round++ {
		added := false
		for _, o := range owners {
			rs := byOwner[o]
			if round >= len(rs) {
				continue
			}
			r := rs[round]
			out = append(out, Example{
				Cluster: r.Cluster,
				Proc:    r.Proc,
				Owner:   r.Owner,
				Batch:   r.Batch,
				At:      r.At,
				Message: r.Message,
			})
			added = true
			if len(out) >= maxExamples {
				break
			}
		}
		if !added {
			break
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// The kinds of record the page separates. Records of different kinds
// never share a cluster: they are different sections, and a row that
// meant both would belong to neither.
const (
	// KindHold is a job that was put on hold -- something about the job
	// or its files stopped it.
	KindHold = "hold"
	// KindRunFailure is a run attempt that ended without the job
	// finishing: the shadow threw an exception, the lease expired, the
	// execute point went away. The job is usually running again minutes
	// later, which is why nobody notices until it has happened a
	// thousand times.
	KindRunFailure = "run_failure"
)
