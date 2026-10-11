package httpserver

import (
	"context"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/sshgateway"
)

// The gateway in multi-AP mode reaches a job by its complete id, through
// that job's AP; a bare id is refused with candidates, and an
// interactive-session target is refused until submit is AP-aware.
func TestMultiAPSSHGatewayResolve(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), nil, "e30.e30.c2ln", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := htcondor.WithSecurityConfig(context.Background(), sec)
	parse := func(user string) sshgateway.Target {
		tg, err := sshgateway.ParseTargetWith(srv.gatewayJobIDCodec(), user)
		if err != nil {
			t.Fatal(err)
		}
		return tg
	}

	k2, err := srv.sshGatewayResolve(ctx, "alice", parse("1.0@"+ap2), nil)
	if err != nil || k2.Schedd != ap2 || k2.Cluster != 1 || k2.Proc != 0 {
		t.Fatalf("1.0@ap2 = %+v, %v", k2, err)
	}
	k1, err := srv.sshGatewayResolve(ctx, "alice", parse("1.0@"+ap1), nil)
	if err != nil || k1.Schedd != ap1 || k1 == k2 {
		t.Errorf("1.0@ap1 = %+v, %v; must differ from 1.0@ap2's key", k1, err)
	}
	if got := srv.scheddForTransport(k2); got == nil || got.Name() != ap2 {
		t.Errorf("ap2's transport dials %v", got)
	}

	_, err = srv.sshGatewayResolve(ctx, "alice", parse("1.0"), nil)
	if multiap.ReasonOf(err) != multiap.ReasonIncompleteID || len(multiap.CandidatesOf(err)) != 2 {
		t.Errorf("bare 1.0 = %v, want a refusal naming both of alice's", err)
	}
	if _, err := srv.sshGatewayResolve(ctx, "alice", parse("+work"), nil); err == nil ||
		!strings.Contains(err.Error(), "interactive sessions are not available") {
		t.Errorf("session target = %v", err)
	}
	if _, err := srv.sshGatewayResolve(ctx, "alice", parse("1.0@ap9.example.org"), nil); multiap.ReasonOf(err) != multiap.ReasonUnknownAP {
		t.Errorf("unknown AP = %v", err)
	}
}

// In multi-AP mode the gateway refuses a session target before any login,
// and no interactive-session manager is offered to the approval screen.
func TestMultiAPSSHGatewayRefusesSessionsUpFront(t *testing.T) {
	aps := newActionAPs(t, ap1)
	srv := newActionServer(t, aps, nil)
	parse := func(user string) sshgateway.Target {
		tg, _ := sshgateway.ParseTargetWith(srv.gatewayJobIDCodec(), user)
		return tg
	}
	for _, u := range []string{"+work", "bbockelm"} {
		if srv.sshGatewayRefuseTarget(parse(u)) == nil {
			t.Errorf("%q (a session) was not refused before login", u)
		}
	}
	if err := srv.sshGatewayRefuseTarget(parse("1.0@" + ap1)); err != nil {
		t.Errorf("a job target was refused: %v", err)
	}
	if srv.interactiveManagerOrNil() != nil {
		t.Error("the approval screen is offered an interactive-session manager in multi-AP mode")
	}
}
