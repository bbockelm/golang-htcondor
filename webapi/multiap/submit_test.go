package multiap

import (
	"context"
	"net/http"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// fixedAssigner answers every question with one schedd.
type fixedAssigner struct{ schedd string }

func (f fixedAssigner) Resolve(context.Context, apassign.Request) (apassign.Assignment, error) {
	return apassign.Assignment{Schedd: f.schedd, Source: "test"}, nil
}

func (f fixedAssigner) Target(context.Context, apassign.Request, string) (string, apassign.Assignment, error) {
	return f.schedd, apassign.Assignment{Schedd: f.schedd, Source: "test"}, nil
}

// An AP that leaves the set between the assignment's validation and the
// submission is the server's problem: 503, not "no such AP" (404).
func TestSubmitTargetAPGoneIs503(t *testing.T) {
	s := &Service{Registry: multiaptest.NewRegistry("ap1.example.org"), Assign: fixedAssigner{"gone.example.org"}}
	_, _, err := s.SubmitTarget(context.Background(), apassign.Request{User: "alice@d"}, "")
	if StatusOf(err) != http.StatusServiceUnavailable || ReasonOf(err) != ReasonUnknownAP {
		t.Fatalf("got %d %q (%v), want 503 %s", StatusOf(err), ReasonOf(err), err, ReasonUnknownAP)
	}
}
