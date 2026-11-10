package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/dagman"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

func routedAs(t *testing.T, reg interface {
	Get(string) (apregistry.Member, bool)
}, ap, user string) context.Context {
	t.Helper()
	sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), nil, "e30.e30.c2ln", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := reg.Get(ap)
	return multiap.WithTarget(htcondor.WithAuthenticatedUser(htcondor.WithSecurityConfig(context.Background(), sec), user),
		multiap.Target{Member: m, ID: jobid.ID{Schedd: ap, Cluster: 1}})
}

// The DAG endpoint looks its cached structure up under the routed AP: a
// structure cached for 1.0@ap1 is served for 1.0@ap1 and never for
// 1.0@ap2.
func TestMultiAPDagStructureIsLookedUpPerAP(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	dagFile := "multiap-dag-test.dag"
	key := dagCacheKey(ap1, 1, 0, dagman.DotFileName(dagFile))
	dagStructures.put(dagCacheEntry{key: key, owner: "alice", value: &dagStructure{dagFile: dagFile, owner: "alice"}})
	ad := classad.New()
	_ = ad.Set("Owner", "alice")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)

	st, code, msg := srv.dagStructureFor(routedAs(t, aps.reg, ap1, "alice"), req, "true", 1, 0, dagFile, ad, false, &dagTimings{})
	if st == nil || st.dagFile != dagFile {
		t.Errorf("1.0@ap1 was not served its cached structure: %d %s", code, msg)
	}
	st, _, _ = srv.dagStructureFor(routedAs(t, aps.reg, ap2, "alice"), req, "true", 1, 0, dagFile, ad, false, &dagTimings{})
	if st != nil && st.dagFile == dagFile {
		t.Error("1.0@ap2 was served 1.0@ap1's cached structure")
	}
}

// The revocation oracles are wired per member: a user disabled on every
// member is revoked at refresh, and each member is asked through its own
// schedd.
func TestMultiAPOraclesAreWiredPerMember(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	var wrapped *multiAPOracle
	for _, o := range srv.revocationOracles {
		if mo, ok := o.(*multiAPOracle); ok && mo.name == OracleScheddUserRec {
			wrapped = mo
		}
	}
	if wrapped == nil || !wrapped.judgesUser {
		t.Fatalf("the user-record oracle is not wrapped per member: %#v", srv.revocationOracles)
	}
	for _, ap := range []string{ap1, ap2} {
		m, _ := aps.reg.Get(ap)
		one, ok := wrapped.perMember(m).(*UserRecordOracle)
		if !ok {
			t.Fatalf("per-member oracle for %s is %T", ap, wrapped.perMember(m))
		}
		if got := one.Lookup(); got != UserRecordLookup(m.Schedd) {
			t.Errorf("%s's oracle looks records up through %v, want its own schedd", ap, got)
		}
	}
	h := srv.Handler
	h.revocationOracles = h.multiAPOracles([]RevocationOracle{&ScheddACLOracle{UIDDomain: "d"}})
	acl, ok := h.revocationOracles[0].(*multiAPOracle)
	if !ok || acl.judgesUser {
		t.Fatalf("the ACL oracle is not wrapped, or judges users: %#v", h.revocationOracles[0])
	}
	for _, ap := range []string{ap1, ap2} {
		m, _ := aps.reg.Get(ap)
		if got := acl.perMember(m).(*ScheddACLOracle).Schedd(); got != m.Schedd {
			t.Errorf("%s's ACL oracle probes %v, want its own schedd", ap, got)
		}
	}
}

// apSuperusers reads each member's QUEUE_SUPER_USERS from that member.
func TestAPSuperusersArePerMember(t *testing.T) {
	src := map[string][]string{ap1: {"alice@d"}, ap2: {"bob@d"}}
	aps := newActionAPs(t, ap1, ap2)
	reg := aps.reg
	a := newAPSuperusers(reg, "d", newTestLogger(t))
	for ap, users := range src {
		p := a.policy(ap)
		p.source = fixedSuperUsers(users)
		if err := p.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		ap, actor string
		want      bool
	}{
		{ap1, "alice@d", true}, {ap1, "bob@d", false},
		{ap2, "bob@d", true}, {ap2, "alice@d", false},
		{"ap9.example.org", "alice@d", false},
	} {
		if got := a.isQueueSuperUser(c.ap, c.actor); got != c.want {
			t.Errorf("isQueueSuperUser(%s, %s) = %v, want %v", c.ap, c.actor, got, c.want)
		}
	}
	// The source asks the member it was made for, and no other.
	for _, c := range []struct{ ap, other string }{{ap2, ap1}, {ap1, ap2}} {
		before := aps.counts()
		ctx, cancel := context.WithTimeout(htcondor.WithDaemonCredential(context.Background(), "test"), 2*time.Second)
		_, _ = memberSuperUserSource{reg: reg, name: c.ap}.QueueSuperUsers(ctx)
		cancel()
		after := aps.counts()
		if after[c.ap] == before[c.ap] || after[c.other] != before[c.other] {
			t.Errorf("%s's QUEUE_SUPER_USERS source went %v -> %v", c.ap, before, after)
		}
	}
	// And a new member's policy is its own, polling its own AP.
	if a.policy(ap1) == a.policy(ap2) {
		t.Error("two members share one superuser policy")
	}
}

type fixedSuperUsers []string

func (f fixedSuperUsers) QueueSuperUsers(context.Context) ([]string, error) { return f, nil }

// A share URL minted in multi-AP mode carries the AP it was minted for,
// inside the signature.
func TestMultiAPShareMintCarriesTheAP(t *testing.T) {
	aps := newActionAPs(t, ap1, ap2)
	srv := newActionServer(t, aps, nil)
	var askedOf string
	srv.jobQueryOverride = func(ctx context.Context, _ string, _ *htcondor.QueryOptions) ([]*classad.ClassAd, error) {
		askedOf = routedSchedd(ctx)
		ad := classad.New()
		_ = ad.Set("ClusterId", 1)
		_ = ad.Set("ProcId", 0)
		_ = ad.Set("Owner", "alice")
		return []*classad.ClassAd{ad}, nil
	}
	rec := doAlice(t, srv, http.MethodPost, "/api/v1/jobs/1.0@"+ap2+"/output/share", "")
	var resp ShareOutputResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
		t.Fatalf("mint = %d %s", rec.Code, rec.Body.String())
	}
	if askedOf != ap2 {
		t.Errorf("the ownership check asked %q, want %s", askedOf, ap2)
	}
	_, tok, _ := strings.Cut(resp.URL, "?t=")
	if s := decodeShareSchedd(t, tok); s != ap2 {
		t.Errorf("minted for %q, want %s", s, ap2)
	}
}

func decodeShareSchedd(t *testing.T, tok string) string {
	t.Helper()
	enc, _, _ := strings.Cut(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		S string `json:"s"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p.S
}
