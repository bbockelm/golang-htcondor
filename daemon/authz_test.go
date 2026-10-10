package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// These tests serve a cedar command server the way a Go daemon does with the
// shared glue -- Daemon.NewAuthz as its Authorizer, RegisterDefaultCommands,
// Authz.Serve under Daemon.Serve -- and reach it as a chosen identity: a
// session pre-shared with the server and attributed to that identity there,
// as condor_master's family session or a claim session is.

const (
	authzReadCmd   = 81101 // registered at READ; replies 1
	authzDaemonCmd = 81102 // registered at DAEMON; replies 1
)

type authzServer struct {
	t         *testing.T
	addr      string
	cfgFile   string
	cache     *security.SessionCache
	srv       *cedarserver.Server
	az        *Authz
	reconfigs atomic.Int32
	records   chan slog.Record
}

// startAuthzServer serves the DC_* defaults and two test commands under the
// ALLOW_/DENY_ knobs, from a configuration file reloaded on reconfig.
func startAuthzServer(t *testing.T, knobs map[string]string, holes []authz.HoleSet) *authzServer {
	t.Helper()
	as := &authzServer{
		t:       t,
		cfgFile: filepath.Join(t.TempDir(), "condor_config"),
		cache:   security.NewSessionCache(),
		records: make(chan slog.Record, 64),
	}
	as.writeConfig(knobs)
	t.Setenv("CONDOR_CONFIG", as.cfgFile)
	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "TESTD"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Options{Subsys: "TESTD", Config: cfg, Logger: log, ShutdownGrace: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	as.srv = cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionCache:   as.cache,
	})
	as.az, err = d.NewAuthz(AuthzOptions{Holes: holes})
	if err != nil {
		t.Fatal(err)
	}
	as.srv.Authorizer = as.az.Authorize
	d.RegisterDefaultCommands(as.srv)
	reply := func(ctx context.Context, c *cedarserver.Conn) error {
		m := message.NewMessageForStream(c.Stream)
		if err := m.PutInt(ctx, 1); err != nil {
			return err
		}
		return m.FinishMessage(ctx)
	}
	as.srv.Handle(authzReadCmd, reply, "READ")
	as.srv.Handle(authzDaemonCmd, reply, "DAEMON")
	// Runs after the policy reload NewAuthz registered.
	d.OnReconfig(func(*config.Config) { as.reconfigs.Add(1) })

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	as.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = d.Serve(ctx, ln, as.az.Serve(as.srv, slog.New(&recordHandler{ch: as.records})))
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return as
}

func (as *authzServer) writeConfig(knobs map[string]string) {
	as.t.Helper()
	var b strings.Builder
	b.WriteString("LOCAL_CONFIG_FILE =\nLOCAL_CONFIG_DIR =\n")
	for k, v := range knobs {
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	if err := os.WriteFile(as.cfgFile, []byte(b.String()), 0o600); err != nil {
		as.t.Fatal(err)
	}
}

// as returns a client security config that resumes a session the server
// attributes to identity.
func (as *authzServer) as(identity string) *security.SecurityConfig {
	as.t.Helper()
	minted, err := security.MintClaimSession(as.cache, security.MintClaimOptions{
		Sinful:  "<127.0.0.1:1>",
		PeerFQU: identity,
	})
	if err != nil {
		as.t.Fatal(err)
	}
	cc := security.NewSessionCache()
	sid, err := security.ImportClaimSession(cc, minted.ClaimID(), security.ClaimSessionOptions{PeerFQU: "testd@pool"})
	if err != nil {
		as.t.Fatal(err)
	}
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionID:      sid,
		SessionCache:   cc,
	}
}

// run sends cmd as sec's identity and reports whether the server ran it: a
// test command replies 1, and a DC_* command, which has no reply, is judged
// by the reconfig count.
func (as *authzServer) run(sec *security.SecurityConfig, cmd int) bool {
	as.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs := *sec
	cs.Command = cmd
	cl, err := client.ConnectAndAuthenticate(ctx, as.addr, &cs)
	if err != nil {
		return false
	}
	defer func() { _ = cl.Close() }()
	if err := message.NewMessageForStream(cl.GetStream()).FinishMessage(ctx); err != nil {
		return false
	}
	v, err := message.NewMessageFromStream(cl.GetStream()).GetInt(ctx)
	return err == nil && v == 1
}

// reconfig sends DC_RECONFIG as sec's identity and reports whether the
// daemon reconfigured.
func (as *authzServer) reconfig(sec *security.SecurityConfig) bool {
	as.t.Helper()
	before := as.reconfigs.Load()
	as.run(sec, commands.DC_RECONFIG)
	return as.reconfigs.Load() > before
}

// expectDenial waits for the PERMISSION DENIED record of a refused command
// and checks the attributes that explain it.
func (as *authzServer) expectDenial(want map[string]string) {
	as.t.Helper()
	select {
	case r := <-as.records:
		got := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			got[a.Key] = a.Value.String()
			return true
		})
		if r.Message != "PERMISSION DENIED" {
			as.t.Fatalf("logged %q, want PERMISSION DENIED", r.Message)
		}
		for k, v := range want {
			if got[k] != v {
				as.t.Errorf("denial %s = %q, want %q (record %v)", k, got[k], v, got)
			}
		}
	case <-time.After(5 * time.Second):
		as.t.Fatal("no PERMISSION DENIED logged")
	}
}

// TestAuthzFamilyReconfigsUnderRestrictiveAdmin: condor_master's family
// session reconfigures the daemon although ALLOW_ADMINISTRATOR names only
// admin@pool and DENY_ADMINISTRATOR names every condor identity; another
// condor identity is refused, and the denial names the deciding knobs.
func TestAuthzFamilyReconfigsUnderRestrictiveAdmin(t *testing.T) {
	as := startAuthzServer(t, map[string]string{
		"ALLOW_ADMINISTRATOR": "admin@pool",
		"DENY_ADMINISTRATOR":  "condor@*",
	}, nil)

	if !as.reconfig(as.as(authz.FamilyFQU)) {
		t.Fatal("DC_RECONFIG as condor@family refused")
	}
	if !as.reconfig(as.as(authz.ParentFQU)) {
		t.Fatal("DC_RECONFIG as condor@parent refused")
	}
	if as.reconfig(as.as("condor@pool")) {
		t.Fatal("DC_RECONFIG as condor@pool ran, want refused")
	}
	as.expectDenial(map[string]string{
		"command":    "DC_RECONFIG",
		"level":      "ADMINISTRATOR",
		"user":       "condor@pool",
		"allow_knob": "ALLOW_ADMINISTRATOR",
		"deny_knob":  "DENY_ADMINISTRATOR",
	})
	// The family session's holes include DAEMON; the lists do not.
	if !as.run(as.as(authz.FamilyFQU), authzDaemonCmd) {
		t.Error("DAEMON command as condor@family refused")
	}
}

// TestAuthzReloadOnReconfig: DC_RECONFIG rebuilds the policy from the
// changed configuration file, so the next command is decided by it.
func TestAuthzReloadOnReconfig(t *testing.T) {
	knobs := map[string]string{"ALLOW_READ": "alice@pool"}
	as := startAuthzServer(t, knobs, nil)
	if as.run(as.as("bob@pool"), authzReadCmd) {
		t.Fatal("READ as bob@pool ran before reconfig, want refused")
	}
	as.expectDenial(map[string]string{"user": "bob@pool", "allow_knob": "ALLOW_READ"})
	if !as.run(as.as("alice@pool"), authzReadCmd) {
		t.Fatal("READ as alice@pool refused before reconfig")
	}

	as.writeConfig(map[string]string{"ALLOW_READ_TESTD": "bob@pool"})
	if !as.reconfig(as.as(authz.FamilyFQU)) {
		t.Fatal("DC_RECONFIG as condor@family refused")
	}
	if !as.run(as.as("bob@pool"), authzReadCmd) {
		t.Fatal("READ as bob@pool refused after reconfig added him")
	}
	if as.run(as.as("alice@pool"), authzReadCmd) {
		t.Fatal("READ as alice@pool ran after reconfig dropped her, want refused")
	}
	as.expectDenial(map[string]string{"user": "alice@pool", "allow_knob": "ALLOW_READ_TESTD"})
}

// TestAuthzMatchSessionHoleFollowsKnob: a startd's claim-session identity
// holds DAEMON while SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION is on, whatever
// ALLOW_DAEMON says, and a reconfig that turns the knob off or on closes or
// opens the hole.
func TestAuthzMatchSessionHoleFollowsKnob(t *testing.T) {
	knobs := map[string]string{
		"ALLOW_DAEMON": "schedd@pool",
		"SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION": "FALSE",
	}
	holes := append(authz.DaemonCoreHoles(), authz.StartdMatchSessionHoles())
	as := startAuthzServer(t, knobs, holes)
	claim := func() bool { return as.run(as.as(authz.SubmitSideMatchSessionFQU), authzDaemonCmd) }

	if claim() {
		t.Fatal("DAEMON as submit-side@matchsession ran with the knob off, want refused")
	}
	as.expectDenial(map[string]string{"user": authz.SubmitSideMatchSessionFQU, "allow_knob": "ALLOW_DAEMON"})

	delete(knobs, "SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION")
	as.writeConfig(knobs)
	if !as.reconfig(as.as(authz.FamilyFQU)) {
		t.Fatal("DC_RECONFIG as condor@family refused")
	}
	if !claim() {
		t.Fatal("DAEMON as submit-side@matchsession refused with the knob at its default (on)")
	}
	if as.run(as.as("alice@pool"), authzDaemonCmd) {
		t.Fatal("DAEMON as alice@pool ran; only the match-session identity has a hole")
	}

	knobs["SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION"] = "FALSE"
	as.writeConfig(knobs)
	if !as.reconfig(as.as(authz.FamilyFQU)) {
		t.Fatal("DC_RECONFIG as condor@family refused")
	}
	if claim() {
		t.Fatal("DAEMON as submit-side@matchsession ran after the knob was turned off, want refused")
	}
}

// TestAuthzLogDenial: both of cedar's authorization refusals are logged, and
// nothing else is.
func TestAuthzLogDenial(t *testing.T) {
	a, err := NewAuthz(config.NewEmpty(), AuthzOptions{CommandNames: map[int]string{81103: "TEST_CMD"}})
	if err != nil {
		t.Fatal(err)
	}
	records := make(chan slog.Record, 4)
	log := slog.New(&recordHandler{ch: records})

	if a.LogDenial(log, nil, "127.0.0.1:1", errors.New("cedar/server: command 60004 (DC_RECONFIG) refused: session (authenticated=false encrypted=false) does not meet the command's security level")) {
		t.Error("security-level refusal reported as an authorization denial")
	}
	if !a.LogDenial(log, nil, "127.0.0.1:1", fmt.Errorf("cedar/server: command 81103 () refused: identity %q is not authorized for this command under current policy", cedarserver.UnauthenticatedFQU)) {
		t.Fatal("policy refusal not logged")
	}
	if !a.LogDenial(log, nil, "127.0.0.1:1", errors.New("cedar/server: command 60004 (DC_RECONFIG) refused: authorization levels [ADMINISTRATOR] are outside the session's authorization limits [READ WRITE]")) {
		t.Fatal("authorization-limits refusal not logged")
	}
	if len(records) != 2 {
		t.Fatalf("logged %d records, want 2", len(records))
	}
	attrs := func(r slog.Record) map[string]string {
		m := map[string]string{}
		r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.String(); return true })
		return m
	}
	if got := attrs(<-records); got["command"] != "TEST_CMD" || got["user"] != cedarserver.UnauthenticatedFQU {
		t.Errorf("policy denial = %v", got)
	}
	if got := attrs(<-records); got["command"] != "DC_RECONFIG" || got["level"] != "ADMINISTRATOR" || got["authorization_limits"] != "READ,WRITE" {
		t.Errorf("limits denial = %v", got)
	}
}

// recordHandler is a slog.Handler that hands every record to a channel.
type recordHandler struct{ ch chan slog.Record }

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	select {
	case h.ch <- r.Clone():
	default:
	}
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }
