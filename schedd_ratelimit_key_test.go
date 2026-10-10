package htcondor

import (
	"context"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// Two schedd clients sharing one configuration but keyed differently
// draw on separate rate-limit budgets: spending one leaves the other
// whole. Unkeyed clients keep sharing one budget.
func TestScheddRateLimitKeyPartitionsTheBudget(t *testing.T) {
	cfg := config.NewEmpty()
	// One request per thousand seconds, burst 1: the second query on a
	// budget is refused at once.
	cfg.Set("SCHEDD_QUERY_PER_USER_RATE_LIMIT", "0.001")
	ctx := WithAuthenticatedUser(WithDaemonCredential(context.Background(), "test"), "alice")

	// Nothing listens here; a query that passes the limiter fails to
	// dial instead, which is how the test tells the two apart.
	const dead = "<127.0.0.1:1>"
	ap1 := NewSchedd("ap1", dead).WithConfig(cfg).WithRateLimitKey("ap1")
	ap2 := NewSchedd("ap2", dead).WithConfig(cfg).WithRateLimitKey("ap2")

	limited := func(s *Schedd) bool {
		_, _, err := s.QueryWithOptions(ctx, "true", &QueryOptions{Limit: 1})
		return err != nil && strings.Contains(err.Error(), "rate limit")
	}
	if limited(ap1) {
		t.Fatal("ap1's first query was rate limited")
	}
	if !limited(ap1) {
		t.Fatal("ap1's second query was not rate limited")
	}
	if limited(ap2) {
		t.Fatal("ap2 was rate limited by ap1's traffic")
	}

	shared1 := NewSchedd("s1", dead).WithConfig(cfg)
	shared2 := NewSchedd("s2", dead).WithConfig(cfg)
	if limited(shared1) {
		t.Fatal("first unkeyed query was rate limited")
	}
	if !limited(shared2) {
		t.Fatal("unkeyed clients with one configuration no longer share a budget")
	}
}
