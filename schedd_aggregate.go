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
	if len(groupBy) > 0 {
		_ = req.Set("Projection", strings.Join(groupBy, ","))
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
			return rows, nil
		}

		count, _ := ad.EvaluateAttrInt("JobCount")
		row := AggregateRow{Count: count}
		for _, attr := range groupBy {
			row.Group = append(row.Group, attrToString(ad, attr))
		}
		rows = append(rows, row)
	}
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
