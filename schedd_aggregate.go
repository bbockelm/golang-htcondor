package htcondor

import (
	"context"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
)

// Counting jobs without shipping them.
//
// "How many jobs are idle, held, running?" is the question asked most
// often and answered worst: listing every matching ad to count it moves
// megabytes to produce a handful of integers, and against a schedd that
// means a full queue walk plus serializing every match.
//
// The schedd can do the grouping itself. Setting ProjectionIsGroupBy on
// a QUERY_JOB_ADS request routes it to command_query_job_aggregates
// (condor_schedd.V6/schedd.cpp), which walks the queue once and returns
// one ad per distinct combination of the projected attributes, carrying
// JobCount. Only the grouped rows cross the wire.

// AggregateRow is one group returned by an aggregate query: the values
// of the group-by attributes, and how many jobs fell into that group.
type AggregateRow struct {
	// Group holds the group-by attribute values, in the order the
	// attributes were requested. Empty for an ungrouped total.
	Group []string
	// Count is the number of jobs in the group.
	Count int64
}

// AggregateJobs counts jobs matching constraint, grouped by the given
// attributes. An empty groupBy returns a single total.
//
// The counting happens on the schedd; the wire carries one row per
// group rather than one ad per job.
func (s *Schedd) AggregateJobs(ctx context.Context, constraint string, groupBy []string, opts *QueryOptions) ([]AggregateRow, error) {
	effectiveOpts := &QueryOptions{}
	if opts != nil {
		effectiveOpts = opts
	}
	eo := effectiveOpts.ApplyDefaults()

	// Owner scoping rides in the constraint, as everywhere else: the
	// schedd's own MyJobs filter is not something it is obliged to
	// honor (see ErrPaginationUnsupported for the same reasoning).
	cmd := commands.QUERY_JOB_ADS
	if eo.FetchOpts&FetchMyJobs != 0 {
		cmd = commands.QUERY_JOB_ADS_WITH_AUTH
	}

	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, cmd, "CLIENT", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}
	hc, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", s.address, err)
	}
	defer func() { _ = hc.Close() }()

	stream := hc.GetStream()
	req := classad.New()
	if constraint == "" {
		constraint = "true"
	}
	expr, perr := classad.ParseExpr(constraint)
	if perr != nil {
		return nil, fmt.Errorf("invalid constraint %q: %w", constraint, perr)
	}
	req.InsertExpr("Requirements", expr)
	// The flag is what selects the aggregating handler; the projection
	// names the grouping columns rather than the attributes to return.
	req.InsertAttrBool("ProjectionIsGroupBy", true)

	// The projection must also carry every attribute the constraint
	// mentions.
	//
	// The schedd's aggregate handler evaluates the constraint against an
	// ad built from the PROJECTION, not against the job. An attribute
	// the constraint names but the grouping does not is therefore
	// undefined, the comparison is never true, and the query returns
	// nothing -- silently, and indistinguishably from "no jobs match".
	// Measured against a live schedd (HTCondor 25.8.0): grouping by
	// Owner, the constraint `Owner == "x"` matched, while
	// `JobStatus == 5`, `ClusterId >= 1` and `JobUniverse == 5` each
	// matched zero of four jobs that a plain query showed satisfied
	// them. Adding those attributes to the projection made all of them
	// match.
	//
	// Sending the union changes the grouping the schedd performs -- it
	// now groups by the wider tuple -- so the rows are folded back down
	// to the caller's grouping below.
	projection := aggregateProjection(groupBy, expr)
	if len(projection) > 0 {
		_ = req.Set("Projection", strings.Join(projection, ","))
	}
	if eo.Limit > 0 {
		_ = req.Set("LimitResults", int64(eo.Limit))
	}

	msg := message.NewMessageForStream(stream)
	if err := msg.PutClassAd(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to serialize aggregate query: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send aggregate query: %w", err)
	}

	var rows []AggregateRow
	for {
		resp := message.NewMessageFromStream(stream)
		ad, err := resp.GetClassAd(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read aggregate response: %w", err)
		}
		// The terminating ad carries Owner == 0, as in a job query.
		if owner, ok := ad.EvaluateAttrInt("Owner"); ok && owner == 0 {
			if code, ok := ad.EvaluateAttrInt("ErrorCode"); ok && code != 0 {
				msg := "unknown error"
				if s, ok := ad.EvaluateAttrString("ErrorString"); ok {
					msg = s
				}
				return nil, fmt.Errorf("schedd aggregate error %d: %s", code, msg)
			}
			return foldAggregateRows(rows), nil
		}

		count, _ := ad.EvaluateAttrInt("JobCount")
		row := AggregateRow{Count: count}
		for _, attr := range groupBy {
			row.Group = append(row.Group, attrToString(ad, attr))
		}
		rows = append(rows, row)
	}
}

// aggregateProjection returns the attributes to send as the aggregate
// query's projection: the caller's grouping, plus every attribute the
// constraint refers to that is not already in it.
//
// The grouping comes first and keeps its order, because that order is
// the caller's and the returned rows are read back against it.
func aggregateProjection(groupBy []string, constraint *classad.Expr) []string {
	projection := append([]string(nil), groupBy...)
	seen := make(map[string]struct{}, len(groupBy))
	for _, g := range groupBy {
		seen[strings.ToLower(g)] = struct{}{}
	}
	// An empty ad resolves nothing, so every attribute the expression
	// names comes back as an external reference -- which is exactly the
	// set the schedd needs in the projection.
	for _, ref := range classad.New().ExternalRefs(constraint) {
		if ref == "" || strings.Contains(ref, ".") {
			// Scoped references (MY.x, TARGET.x) are not job attributes
			// the projection can carry.
			continue
		}
		if _, dup := seen[strings.ToLower(ref)]; dup {
			continue
		}
		seen[strings.ToLower(ref)] = struct{}{}
		projection = append(projection, ref)
	}
	return projection
}

// foldAggregateRows collapses rows that share the caller's grouping.
//
// Widening the projection so the constraint can be evaluated also makes
// the schedd group by the wider tuple, so "count by Owner" constrained
// on JobStatus comes back split by (Owner, JobStatus). Summing the rows
// that share an Owner restores the grouping that was asked for. Order is
// the order each group was first seen, so it stays the schedd's.
//
// The grouping itself is not a parameter: each row's Group was already
// built from the caller's group-by attributes alone, so rows that belong
// together are exactly the rows whose Group is equal.
func foldAggregateRows(rows []AggregateRow) []AggregateRow {
	if len(rows) == 0 {
		return rows
	}
	folded := make([]AggregateRow, 0, len(rows))
	at := make(map[string]int, len(rows))
	for _, r := range rows {
		key := groupKey(r.Group)
		if i, ok := at[key]; ok {
			folded[i].Count += r.Count
			continue
		}
		at[key] = len(folded)
		folded = append(folded, r)
	}
	return folded
}

// attrToString renders a group-by value for display. The attribute may
// be any ClassAd type -- JobStatus is an integer, Owner a string -- and
// an absent one is reported as "undefined" rather than an empty cell,
// which would read as a group whose value is the empty string.
func attrToString(ad *classad.ClassAd, attr string) string {
	if v, ok := ad.EvaluateAttrString(attr); ok {
		return v
	}
	if v, ok := ad.EvaluateAttrInt(attr); ok {
		return fmt.Sprintf("%d", v)
	}
	if v, ok := ad.EvaluateAttrBool(attr); ok {
		return fmt.Sprintf("%t", v)
	}
	return "undefined"
}

// groupKey builds a collision-free map key from a group tuple.
//
// Joining on a separator is not enough on its own: any separator can in
// principle appear inside a value, and then ["a","b"] and ["a<sep>b"]
// are the same key and two distinct groups are silently summed into one.
// Length-prefixing each element removes the possibility rather than
// relying on a character being unusual.
func groupKey(group []string) string {
	var b strings.Builder
	for _, g := range group {
		fmt.Fprintf(&b, "%d:%s", len(g), g)
	}
	return b.String()
}
