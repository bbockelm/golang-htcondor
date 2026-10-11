package multiap

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

func routeService(t *testing.T) (*Service, *testDB) {
	t.Helper()
	hub := hubDB(t)
	hub.PutJob("ap1", "alice@d", 1, 0, "")
	hub.PutJob("ap2", "alice@d", 1, 0, "")
	hub.PutJob("ap1", "alice@d", 2, 0, "")
	hub.PutJob("ap2", "bob@d", 3, 0, "")
	hub.PutSource("ap1", StateFresh, 1)
	hub.PutSource("ap2", StateFresh, 1)
	reg := newFakeRegistry("ap1", "ap2", "ap3", "gone").WithSchedds(func(n string) string { return "<10.0.0.1:9618?name=" + n + ">" })
	reg.Update("gone", func(m *apregistry.Member) { m.Present = false; m.LastSeen = time.Unix(1700000000, 0) })
	reg.Update("ap3", func(m *apregistry.Member) {
		m.Trust = apregistry.Trust{State: apregistry.TrustUntrusted, Reason: "reported nobody@elsewhere"}
	})
	return newService(t, hub, reg), hub
}

// A complete id routes to its own AP's schedd, and only that one.
func TestRouteCompleteID(t *testing.T) {
	s, _ := routeService(t)
	for _, ap := range []string{"ap1", "ap2", "AP2"} {
		m, err := s.Route(context.Background(), "alice@d", jobid.ID{Schedd: ap, Cluster: 1})
		if err != nil {
			t.Fatalf("Route(1.0@%s): %v", ap, err)
		}
		if !strings.EqualFold(m.Name, ap) || m.Schedd == nil || m.Schedd.Name() != m.Name {
			t.Errorf("Route(1.0@%s) = %s (schedd %v)", ap, m.Name, m.Schedd)
		}
	}
}

// A bare id on a mutation is a 400 naming the caller's candidates -- on
// both APs, and none of bob's -- never a guess.
func TestRouteBareIDNamesCandidates(t *testing.T) {
	s, _ := routeService(t)
	_, err := s.Route(context.Background(), "alice@d", jobid.ID{Cluster: 1})
	if StatusOf(err) != http.StatusBadRequest || ReasonOf(err) != ReasonIncompleteID {
		t.Fatalf("bare 1.0: %v (status %d, reason %q)", err, StatusOf(err), ReasonOf(err))
	}
	cands := CandidatesOf(err)
	if len(cands) != 2 || cands[0].JobID != "1.0@ap1" || cands[1].JobID != "1.0@ap2" {
		t.Errorf("candidates = %+v, want 1.0@ap1 and 1.0@ap2", cands)
	}
	if !strings.Contains(err.Error(), "1.0@ap1") {
		t.Errorf("message does not name the candidates: %v", err)
	}
	// Even exactly one match is not acted on: still a 400, with it named.
	_, err = s.Route(context.Background(), "alice@d", jobid.ID{Cluster: 2})
	if StatusOf(err) != http.StatusBadRequest || len(CandidatesOf(err)) != 1 || CandidatesOf(err)[0].JobID != "2.0@ap1" {
		t.Errorf("bare 2.0 (one match) = %v %+v", err, CandidatesOf(err))
	}
	// bob's job is not a candidate for alice.
	_, err = s.Route(context.Background(), "alice@d", jobid.ID{Cluster: 3})
	if StatusOf(err) != http.StatusBadRequest || len(CandidatesOf(err)) != 0 {
		t.Errorf("bare 3.0 (bob's) = %v %+v", err, CandidatesOf(err))
	}
	// No caller: nothing is routed, complete id or not.
	for _, id := range []jobid.ID{{Cluster: 1}, {Schedd: "ap1", Cluster: 1}} {
		if _, err := s.Route(context.Background(), "", id); StatusOf(err) != http.StatusUnauthorized {
			t.Errorf("%+v without a user = %v, want 401", id, err)
		}
	}
}

// Each way an AP cannot be acted on is its own error, never "no such job".
func TestRouteUnusableAPs(t *testing.T) {
	s, _ := routeService(t)
	for _, c := range []struct {
		schedd string
		status int
		reason string
		text   string
	}{
		{"ap9", http.StatusNotFound, ReasonUnknownAP, "not an access point this server serves"},
		{"gone", http.StatusServiceUnavailable, ReasonAPAbsent, "not advertised in the collector"},
		{"ap3", http.StatusServiceUnavailable, ReasonAPUntrusted, "does not trust this API server's tokens"},
	} {
		_, err := s.Route(context.Background(), "alice@d", jobid.ID{Schedd: c.schedd, Cluster: 1})
		if StatusOf(err) != c.status || ReasonOf(err) != c.reason || !strings.Contains(err.Error(), c.text) {
			t.Errorf("1.0@%s: %v (status %d reason %q), want %d %q", c.schedd, err, StatusOf(err), ReasonOf(err), c.status, c.reason)
		}
		if strings.Contains(strings.ToLower(err.Error()), "not found") && c.status != http.StatusNotFound {
			t.Errorf("1.0@%s reads as a missing job: %v", c.schedd, err)
		}
	}
}

func TestTargetContext(t *testing.T) {
	s, _ := routeService(t)
	m, err := s.Member("ap2")
	if err != nil {
		t.Fatal(err)
	}
	if ScheddFrom(context.Background()) != nil {
		t.Fatal("a context with no target names a schedd")
	}
	ctx := WithTarget(context.Background(), Target{Member: m, ID: jobid.ID{Schedd: "ap2", Cluster: 1}})
	if got := ScheddFrom(ctx); got != m.Schedd {
		t.Errorf("ScheddFrom = %v, want ap2's", got)
	}
}

// An AP that failed its trust probe is flagged in every sources block
// and in the AP list, and is not counted as fresh.
func TestUntrustedAPIsFlagged(t *testing.T) {
	s, hub := routeService(t)
	hub.PutSource("ap3", StateFresh, 1)
	if err := s.Hub.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	src := s.Sources()
	var flagged *Degraded
	for i, d := range src.Degraded {
		if d.Schedd == "ap3" {
			flagged = &src.Degraded[i]
		}
	}
	if flagged == nil || flagged.State != StateUntrusted || !strings.Contains(flagged.Reason, "does not trust") {
		t.Errorf("sources = %+v, want ap3 flagged untrusted", src)
	}
	if src.Fresh != 2 {
		t.Errorf("fresh = %d, want 2 (ap1, ap2; ap3 is untrusted, gone is absent)", src.Fresh)
	}
	for _, ap := range s.APs() {
		switch ap.Schedd {
		case "ap3":
			if ap.Trust.State != apregistry.TrustUntrusted || ap.Trust.Actions || !strings.Contains(ap.Trust.Reason, "nobody@elsewhere") {
				t.Errorf("ap3 trust = %+v", ap.Trust)
			}
		case "gone":
			if ap.Trust.Actions {
				t.Errorf("an absent AP is offered for actions: %+v", ap.Trust)
			}
		default:
			if !ap.Trust.Actions || ap.Trust.State != "unknown" {
				t.Errorf("%s trust = %+v", ap.Schedd, ap.Trust)
			}
		}
	}
}
