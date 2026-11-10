package httpserver

import (
	"context"
	"errors"
	"reflect"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

type fixedOracle struct {
	d   ReauthDecision
	err error
}

func (fixedOracle) Name() string { return "fixed" }
func (o fixedOracle) Check(context.Context, string, []string) (ReauthDecision, error) {
	return o.d, o.err
}

func oracleOver(answers map[string]fixedOracle, extra ...apregistry.Member) *multiAPOracle {
	var members []apregistry.Member
	for name := range answers {
		members = append(members, apregistry.Member{Name: name, Present: true, Schedd: htcondor.NewSchedd(name, "<127.0.0.1:1>")})
	}
	members = append(members, extra...)
	return &multiAPOracle{name: "fixed",
		members:   func() []apregistry.Member { return members },
		perMember: func(m apregistry.Member) RevocationOracle { return answers[m.Name] }}
}

// One grant is good at every AP, so the merged verdict removes only what
// no AP would allow.
func TestMultiAPOracleMerge(t *testing.T) {
	revoked := fixedOracle{d: ReauthDecision{Status: UserStatusRevoked, Reason: "disabled"}}
	active := fixedOracle{d: ReauthDecision{Status: UserStatusActive}}
	noWrite := fixedOracle{d: ReauthDecision{Status: UserStatusActive, DeniedScopes: []string{"mcp:write", "condor:/WRITE"}}}
	unknown := fixedOracle{err: errors.New("unreachable")}

	for _, c := range []struct {
		name    string
		answers map[string]fixedOracle
		status  UserStatus
		denied  []string
	}{
		{"disabled on one AP only", map[string]fixedOracle{"ap1": revoked, "ap2": active}, UserStatusActive, nil},
		{"disabled everywhere that answered", map[string]fixedOracle{"ap1": revoked, "ap2": revoked, "ap3": unknown}, UserStatusRevoked, nil},
		{"write denied on one AP", map[string]fixedOracle{"ap1": noWrite, "ap2": active}, UserStatusActive, nil},
		{"write denied everywhere", map[string]fixedOracle{"ap1": noWrite, "ap2": noWrite, "ap3": revoked},
			UserStatusActive, []string{"condor:/WRITE", "mcp:write"}},
		{"nobody answered", map[string]fixedOracle{"ap1": unknown}, UserStatusUnknown, nil},
	} {
		d, err := oracleOver(c.answers).Check(context.Background(), "alice", nil)
		if err != nil || d.Status != c.status || !reflect.DeepEqual(d.DeniedScopes, c.denied) {
			t.Errorf("%s: %+v (%v), want %v denying %v", c.name, d, err, c.status, c.denied)
		}
	}

	// An untrusted or absent member is not asked.
	asked := 0
	o := oracleOver(map[string]fixedOracle{"ap1": active},
		apregistry.Member{Name: "bad", Present: true, Schedd: htcondor.NewSchedd("bad", "x"),
			Trust: apregistry.Trust{State: apregistry.TrustUntrusted}},
		apregistry.Member{Name: "gone", Schedd: htcondor.NewSchedd("gone", "x")})
	inner := o.perMember
	o.perMember = func(m apregistry.Member) RevocationOracle { asked++; return inner(m) }
	if _, err := o.Check(context.Background(), "alice", nil); err != nil || asked != 1 {
		t.Errorf("asked %d members (%v), want only the trusted present one", asked, err)
	}
}
