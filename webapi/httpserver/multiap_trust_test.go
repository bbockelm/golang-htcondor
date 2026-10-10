package httpserver

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	cedarserver "github.com/bbockelm/cedar/server"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

// fakeProbedSchedd authenticates pool tokens, answers DC_NOP_READ, and
// answers DC_CONFIG_VAL UID_DOMAIN with uidDomain. mapTo, when set,
// maps every authenticated identity to it, as a schedd whose mapfile
// rewrites tokens would.
func fakeProbedSchedd(t *testing.T, cfg *config.Config, uidDomain, mapTo string) string {
	t.Helper()
	srv := cedarserver.New(tokenDaemonSecurity(t, cfg, int(commands.DC_NOP_READ)))
	if mapTo != "" {
		srv.FQUMapper = func(string, string) string { return mapTo }
	}
	srv.Handle(int(commands.DC_NOP_READ), func(context.Context, *cedarserver.Conn) error { return nil }, "READ")
	srv.Handle(int(commands.DC_CONFIG_VAL), func(ctx context.Context, c *cedarserver.Conn) error {
		in := message.NewMessageFromStream(c.Stream)
		name, err := in.GetString(ctx)
		if err != nil {
			return err
		}
		val := "Not defined: " + name
		if name == "UID_DOMAIN" {
			val = uidDomain
		}
		out := message.NewMessageForStream(c.Stream)
		if err := out.PutString(ctx, val); err != nil {
			return err
		}
		return out.FinishMessage(ctx)
	}, "READ")
	return startTokenDaemon(t, srv)
}

// The trust probe passes a member that accepts this server's tokens and
// reports the probe identity, and marks untrusted one that refuses the
// token, maps it to someone else, or qualifies users with another
// UID_DOMAIN. An unreachable member is inconclusive, never untrusted.
func TestProbeMemberTrust(t *testing.T) {
	signingKey := writeSigningKey(t)
	cfg := tokenPoolConfig(filepath.Dir(signingKey))
	// A pool signed with a key this server does not hold.
	otherCfg := tokenPoolConfig(filepath.Dir(writeTestSigningKey(t)))

	h := &Handler{signingKeyPath: signingKey, trustDomain: mirrorAuthzTrustDomain, uidDomain: mirrorAuthzTrustDomain,
		clientConfig: cfg, logger: newTestLogger(t)}
	member := func(addr string) apregistry.Member {
		return apregistry.Member{Name: "ap", Address: addr, Schedd: htcondor.NewSchedd("ap", addr).WithConfig(cfg)}
	}
	probe := func(addr string) error { return h.probeMemberTrust(context.Background(), member(addr)) }

	if err := probe(fakeProbedSchedd(t, cfg, strings.ToUpper(mirrorAuthzTrustDomain), "")); err != nil {
		t.Errorf("a member that trusts the server: %v", err)
	}
	for _, c := range []struct {
		name, addr, want string
	}{
		{"maps the token to another identity", fakeProbedSchedd(t, cfg, mirrorAuthzTrustDomain, "nobody@elsewhere.org"), "nobody@elsewhere.org"},
		{"another UID_DOMAIN", fakeProbedSchedd(t, cfg, "other.example", ""), "other.example"},
		{"another signing key", fakeProbedSchedd(t, otherCfg, mirrorAuthzTrustDomain, ""), "refused a token"},
	} {
		err := probe(c.addr)
		if err == nil || errors.Is(err, apregistry.ErrInconclusive) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want untrusted mentioning %q", c.name, err, c.want)
		}
	}
	if err := probe("<127.0.0.1:1>"); !errors.Is(err, apregistry.ErrInconclusive) {
		t.Errorf("an unreachable member: %v, want inconclusive", err)
	}
	if err := (&Handler{logger: newTestLogger(t)}).probeMemberTrust(context.Background(), member("<127.0.0.1:1>")); !errors.Is(err, apregistry.ErrInconclusive) {
		t.Errorf("a server with no signing key: %v, want inconclusive", err)
	}
}

func TestSameIdentity(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"p@D.org", "p@d.org", true},
		{"P@d.org", "p@d.org", false},
		{"p@x@d.org", "p@x@D.ORG", true},
		{"p", "p@d.org", false},
		{"p@other.org", "p@d.org", false},
	} {
		if got := sameIdentity(c.a, c.b); got != c.want {
			t.Errorf("sameIdentity(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
