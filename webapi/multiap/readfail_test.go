package multiap

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/PelicanPlatform/classad/dbrpc"
)

type dataReadKey struct{}

// TestDataReadFailuresFailOver: hub A answers its federation_sources
// but every read of its data fails on the transport. Those failures
// count toward FailAfter like failed sources reads, so reads move to
// hub B instead of failing forever.
func TestDataReadFailuresFailOver(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	a.PutJob(ap1, "alice@d", 1, 0, "")
	b.PutJob(ap1, "alice@d", 1, 0, "")
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{FailAfter: 2})
	brokenA := func(ctx context.Context) (*dbrpc.Client, func(), error) {
		if ctx.Value(dataReadKey{}) != nil {
			return nil, nil, fmt.Errorf("reading the jobs table: %w", dbrpc.ErrConnClosed)
		}
		return a.Dial(ctx)
	}
	p.hub.Active().dial = brokenA // A sorts first
	p.refresh()
	s := pairService(p)
	ctx := context.WithValue(context.Background(), dataReadKey{}, true)
	list := func() error {
		_, err := s.ListJobs(ctx, ListRequest{User: "alice@d"}, func(Row) bool { return true })
		return err
	}
	for i := 0; i < 2; i++ {
		if err := list(); err == nil {
			t.Fatalf("read %d from hub A succeeded", i)
		}
	}
	p.refresh() // A's sources still answer
	if p.active() != hubB {
		t.Fatalf("active %q after two failed data reads, want %s", p.active(), hubB)
	}
	if err := list(); err != nil {
		t.Fatalf("read after the failover: %v", err)
	}
}

// TestDataReadFailureClassification: only the transport counts -- not a
// query the hub refused, nor a caller that went away.
func TestDataReadFailureClassification(t *testing.T) {
	bg := context.Background()
	canceled, cancel := context.WithCancel(bg)
	cancel()
	for _, tc := range []struct {
		name  string
		ctx   context.Context
		err   error
		count bool
	}{
		{"connection closed", bg, fmt.Errorf("x: %w", dbrpc.ErrConnClosed), true},
		{"timed out", bg, context.DeadlineExceeded, true},
		{"refused query", bg, &dbrpc.ServerError{Msg: "no such table"}, false},
		{"bad request", bg, dbrpc.ErrBadRequest, false},
		{"caller went away", canceled, fmt.Errorf("x: %w", dbrpc.ErrConnClosed), false},
		{"unparseable row", bg, errors.New("unparseable row"), false},
	} {
		if got := transportFailure(tc.ctx, tc.err); got != tc.count {
			t.Errorf("%s: counted %v, want %v", tc.name, got, tc.count)
		}
	}
}
