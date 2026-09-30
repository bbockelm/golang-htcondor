package htcondor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/config"
)

// daemonPoolConfig builds the configuration an access point actually has: a
// token directory holding the daemon's pool token, and an auth-method list
// that puts FS ahead of TOKEN. Both halves matter -- the token is what a
// credential-less connection would present to a remote schedd, and FS is what
// it would use on a same-host one.
func daemonPoolConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	tokDir := filepath.Join(dir, "tokens.d")
	if err := os.MkdirAll(tokDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokDir, "POOL"), []byte("eyJhbGciOiJIUzI1NiJ9.e30.sig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "condor_config")
	body := "SEC_TOKEN_DIRECTORY = " + tokDir + "\n" +
		"SEC_DEFAULT_AUTHENTICATION_METHODS = FS,TOKEN\n" +
		"SEC_CLIENT_AUTHENTICATION_METHODS = FS,TOKEN\n"
	if err := os.WriteFile(cfgFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONDOR_CONFIG", cfgFile)
	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	return cfg
}

// A context acting for somebody else, with no credential attached, must not
// be handed this daemon's configuration. That config carries the pool token
// and FS; on an access point it authenticates as a queue superuser.
func TestUserRequestCannotBecomeTheDaemon(t *testing.T) {
	cfg := daemonPoolConfig(t)

	ctx := WithUserRequest(context.Background(), "HTTP request GET /api/v1/jobs")
	got, err := GetSecurityConfigOrDefault(ctx, cfg, 1111, "CLIENT", "<127.0.0.1:9618>")
	if err == nil {
		t.Fatalf("a user-marked context with no caller credential was given a working security "+
			"config (methods %v, token %q) instead of being refused: that is the daemon identity",
			got.AuthMethods, got.Token)
	}
	if !IsDaemonFallbackRefused(err) {
		t.Fatalf("refused, but not as a daemon-fallback refusal, so no transport can map it to 401: %v", err)
	}
	// The refusal has to say which door the context came in through and how
	// to fix it, or it is just a 401 with no lead.
	for _, want := range []string{"HTTP request GET /api/v1/jobs", "WithSecurityConfig", "WithDaemonCredential"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal message does not mention %q: %v", want, err)
		}
	}
}

// The third branch of GetSecurityConfigOrDefault -- "sensible defaults" when
// no configuration is reachable at all -- is the same hazard in different
// clothes, and the gate has to sit in front of it too.
//
// The positive control below spells out what it hands back: FS in the method
// list and the privileged credential reader. On a same-host schedd FS wins
// the negotiation outright, so this branch authenticates as the daemon's OS
// user with no token involved anywhere -- which is why gating only the
// config-backed branch would have left the hole open.
func TestUserRequestCannotReachTheDefaultsBranch(t *testing.T) {
	withNoReachableConfig(t)

	ctx := WithUserRequest(context.Background(), "SSH gateway session channel for alice")
	got, err := GetSecurityConfigOrDefault(ctx, nil, 1111, "CLIENT", "<127.0.0.1:9618>")
	if err == nil {
		t.Fatalf("the defaults branch handed a user-marked request a config with methods %v "+
			"and credential reader %T", got.AuthMethods, got.Credentials)
	}
	if !IsDaemonFallbackRefused(err) {
		t.Fatalf("wrong error kind: %v", err)
	}
}

// Positive control, and the description of what the test above prevents:
// daemon-marked work still reaches the defaults branch and still gets the FS
// method and the privileged reader it needs.
func TestDefaultsBranchStillServesDaemonWork(t *testing.T) {
	withNoReachableConfig(t)

	got, err := GetSecurityConfigOrDefault(
		WithDaemonCredential(context.Background(), "collector advertise loop"),
		nil, 1111, "CLIENT", "<127.0.0.1:9618>")
	if err != nil {
		t.Fatalf("daemon-marked context refused: %v", err)
	}
	if !hasAuthMethod(got.AuthMethods, security.AuthFS) {
		t.Errorf("defaults branch no longer offers FS (%v); the refusal test above is no longer "+
			"proving anything about same-host authentication", got.AuthMethods)
	}
	if cache, ok := got.Credentials.(*CredentialCache); !ok || cache != daemonCredentialCache {
		t.Errorf("defaults branch no longer wires the privileged credential reader (%T)", got.Credentials)
	}
}

// Positive control for the ordinary daemon path: the configured branch.
func TestDaemonWorkStillGetsTheDaemonCredential(t *testing.T) {
	cfg := daemonPoolConfig(t)

	got, err := GetSecurityConfigOrDefault(
		WithDaemonCredential(context.Background(), "queue mirror"),
		cfg, 1111, "CLIENT", "<127.0.0.1:9618>")
	if err != nil {
		t.Fatalf("daemon-marked context refused: %v", err)
	}
	if got.TokenDir == "" {
		t.Error("daemon work did not get the configured token directory")
	}
}

// A caller credential still wins over the mark: marking a transport must not
// break the ordinary authenticated path, which never reaches the gate.
func TestCallerCredentialIsUnaffectedByTheMark(t *testing.T) {
	cfg := daemonPoolConfig(t)

	caller := &security.SecurityConfig{Token: "caller-token"}
	ctx := WithSecurityConfig(WithUserRequest(context.Background(), "HTTP request"), caller)
	got, err := GetSecurityConfigOrDefault(ctx, cfg, 1111, "CLIENT", "<127.0.0.1:9618>")
	if err != nil {
		t.Fatalf("an authenticated request was refused: %v", err)
	}
	if got.Token != "caller-token" {
		t.Fatalf("caller credential lost: token %q", got.Token)
	}
}

// WithDaemonCredential must detach a caller credential as well as classify,
// so daemon plumbing derived from a request context cannot offer the caller's
// token to a broker or relay that has no reason to accept it.
func TestWithDaemonCredentialDetachesCallerCredential(t *testing.T) {
	cfg := daemonPoolConfig(t)

	caller := &security.SecurityConfig{Token: "caller-token"}
	ctx := WithSecurityConfig(WithUserRequest(context.Background(), "HTTP request"), caller)
	if _, ok := GetSecurityConfigFromContext(ctx); !ok {
		t.Fatal("precondition: the caller credential is not on the context")
	}

	got, err := GetSecurityConfigOrDefault(
		WithDaemonCredential(ctx, "starter dial through a CCB broker"),
		cfg, 1111, "CLIENT", "<127.0.0.1:9618>")
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if got.Token == "caller-token" {
		t.Fatal("daemon plumbing was handed the caller's token")
	}
}

// WithoutSecurityConfig is the older spelling of the same act, and the one
// schedd_ssh.go uses to reach a starter through a CCB broker. It has to
// classify too: without that, an ssh-to-job request arriving over HTTP would
// carry the HTTP mark into the broker dial and be refused for having no
// credential -- the credential it deliberately dropped.
func TestWithoutSecurityConfigIsDaemonWork(t *testing.T) {
	ctx := WithUserRequest(context.Background(), "HTTP request GET /api/v1/jobs/1.0/ssh")
	origin, _ := CredentialOriginFromContext(WithoutSecurityConfig(ctx))
	if origin != OriginDaemon {
		t.Fatalf("WithoutSecurityConfig leaves the context %s, so the starter dial is refused", origin)
	}
}

// The staged-migration dial. Allow is the default and keeps today's
// behaviour; Warn reports without refusing; Deny fails closed.
func TestUnmarkedOriginPolicy(t *testing.T) {
	cfg := daemonPoolConfig(t)
	t.Cleanup(func() {
		SetUnmarkedOriginPolicy(UnmarkedAllow)
		SetUnmarkedOriginReporter(nil)
	})

	SetUnmarkedOriginPolicy(UnmarkedAllow)
	if _, err := GetSecurityConfigOrDefault(context.Background(), cfg, 1111, "CLIENT", "p"); err != nil {
		t.Fatalf("Allow must preserve today's behaviour for an unclassified context: %v", err)
	}

	reported := 0
	SetUnmarkedOriginReporter(func(command int, secContext, peerName string) {
		reported++
		if command != 1111 || secContext != "CLIENT" || peerName != "p" {
			t.Errorf("reporter got %d/%q/%q, which does not identify the call", command, secContext, peerName)
		}
	})
	SetUnmarkedOriginPolicy(UnmarkedWarn)
	if _, err := GetSecurityConfigOrDefault(context.Background(), cfg, 1111, "CLIENT", "p"); err != nil {
		t.Fatalf("Warn must not refuse: %v", err)
	}
	if reported != 1 {
		t.Errorf("Warn reported %d times, want 1; the migration cannot be staged from a silent mode", reported)
	}

	SetUnmarkedOriginPolicy(UnmarkedDeny)
	if _, err := GetSecurityConfigOrDefault(context.Background(), cfg, 1111, "CLIENT", "p"); !IsDaemonFallbackRefused(err) {
		t.Fatalf("Deny must refuse an unclassified context, got %v", err)
	}

	// Deny is about unclassified contexts only: daemon work stays allowed,
	// or turning the dial up would take the daemon's own RPCs with it.
	if _, err := GetSecurityConfigOrDefault(
		WithDaemonCredential(context.Background(), "queue mirror"), cfg, 1111, "CLIENT", "p"); err != nil {
		t.Fatalf("Deny refused daemon-marked work: %v", err)
	}
}

// The default has to be Allow: this change classifies three transports and
// leaves every other context in the process unclassified, so any other
// default would refuse the daemon's own background work on import.
func TestUnmarkedPolicyDefaultsToAllow(t *testing.T) {
	if got := UnmarkedOriginPolicy(unmarkedPolicy.Load()); got != UnmarkedAllow {
		t.Fatalf("unmarked policy defaults to %d, want UnmarkedAllow (%d)", got, UnmarkedAllow)
	}
}

// withNoReachableConfig points CONDOR_CONFIG at a file that does not exist
// and clears the cached global, so GetSecurityConfigOrDefault reaches its
// third branch.
func withNoReachableConfig(t *testing.T) {
	t.Helper()
	t.Setenv("CONDOR_CONFIG", filepath.Join(t.TempDir(), "does-not-exist"))
	globalDefaultConfig.Store(nil)
	t.Cleanup(func() { globalDefaultConfig.Store(nil) })
	if cfg := getDefaultConfig(); cfg != nil {
		t.Skip("this environment still resolves a configuration; the defaults branch is unreachable here")
	}
}
