package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

const (
	seclevelReadCmd   = 81201 // registered at READ, after InstallSecurityLevels
	seclevelWriteCmd  = 81202 // registered at WRITE, after InstallSecurityLevels
	seclevelNoPermCmd = 81203 // registered at no level

	// seclevelVersion is the base policy's RemoteVersion.
	seclevelVersion = "$CondorVersion: 25.14.0 2026-08-14 BuildID: seclevel-test $"
)

// startSeclevelServer serves the DC_* defaults and the seclevel test commands
// on a cedar server whose base policy is SEC_DEFAULT_*, with
// InstallSecurityLevels installed before any command is registered. knobs
// form the configuration file the daemon reloads on reconfig.
func startSeclevelServer(t *testing.T, knobs map[string]string) (addr string, d *Daemon, rewrite func(map[string]string)) {
	t.Helper()
	cfgFile := filepath.Join(t.TempDir(), "condor_config")
	rewrite = func(knobs map[string]string) {
		var b strings.Builder
		b.WriteString("LOCAL_CONFIG_FILE =\nLOCAL_CONFIG_DIR =\nSEC_DEFAULT_AUTHENTICATION_METHODS = FS\n")
		for k, v := range knobs {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
		if err := os.WriteFile(cfgFile, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rewrite(knobs)
	t.Setenv("CONDOR_CONFIG", cfgFile)
	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "TESTD"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatal(err)
	}
	d, err = New(Options{Subsys: "TESTD", Config: cfg, Logger: log, ShutdownGrace: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	base, err := d.ServerSecurityConfig(commands.DC_NOP, "DEFAULT")
	if err != nil {
		t.Fatal(err)
	}
	base.SessionCache = security.NewSessionCache()
	base.RemoteVersion = seclevelVersion
	srv := cedarserver.New(base)
	if err := d.InstallSecurityLevels(srv); err != nil {
		t.Fatal(err)
	}
	// Registered after the install, as a daemon registers a CCB server's or
	// an embedded negotiator's commands.
	d.RegisterDefaultCommands(srv)
	nop := func(context.Context, *cedarserver.Conn) error { return nil }
	srv.Handle(seclevelReadCmd, nop, "READ")
	srv.Handle(seclevelWriteCmd, nop, "WRITE")
	srv.Handle(seclevelNoPermCmd, nop)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = d.Serve(ctx, ln, srv.Serve)
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return ln.Addr().String(), d, rewrite
}

// negotiate runs a handshake for cmd as a peer that will not authenticate,
// and another as one that will not encrypt, and reports whether the server
// accepted each: the server's policy for cmd decides.
func negotiate(t *testing.T, addr string, cmd int) (unauthenticated, unencrypted bool) {
	t.Helper()
	try := func(auth, enc security.SecurityLevel) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cl, err := client.ConnectAndAuthenticate(ctx, addr, &security.SecurityConfig{
			Command:        cmd,
			AuthMethods:    []security.AuthMethod{security.AuthFS},
			Authentication: auth,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     enc,
			Integrity:      enc,
			SessionCache:   security.NewSessionCache(),
		})
		if err != nil {
			return false
		}
		_ = cl.Close()
		return true
	}
	return try(security.SecurityNever, security.SecurityOptional), try(security.SecurityOptional, security.SecurityNever)
}

// TestInstallSecurityLevelsNegotiatesAtCommandLevel: each command negotiates
// under the SEC_<level>_* policy of the level it is registered at, as
// DaemonCore negotiates it, whether it was registered before or after the
// install: an ADVERTISE_STARTD command under SEC_DAEMON_* while
// SEC_ADVERTISE_STARTD_* is unset and under SEC_ADVERTISE_STARTD_* once set,
// a READ command under SEC_READ_*, and a command at no level under the base
// policy. The policies follow a reconfig.
func TestInstallSecurityLevelsNegotiatesAtCommandLevel(t *testing.T) {
	knobs := map[string]string{
		"SEC_DEFAULT_AUTHENTICATION": "OPTIONAL",
		"SEC_DEFAULT_ENCRYPTION":     "OPTIONAL",
		"SEC_DEFAULT_INTEGRITY":      "OPTIONAL",
		"SEC_DAEMON_AUTHENTICATION":  "REQUIRED",
		"SEC_READ_ENCRYPTION":        "REQUIRED",
	}
	addr, d, rewrite := startSeclevelServer(t, knobs)

	expect := func(name string, cmd int, wantUnauthenticated, wantUnencrypted bool) {
		t.Helper()
		unauthenticated, unencrypted := negotiate(t, addr, cmd)
		if unauthenticated != wantUnauthenticated {
			t.Errorf("%s: unauthenticated handshake accepted = %v, want %v", name, unauthenticated, wantUnauthenticated)
		}
		if unencrypted != wantUnencrypted {
			t.Errorf("%s: unencrypted handshake accepted = %v, want %v", name, unencrypted, wantUnencrypted)
		}
	}

	// SEC_ADVERTISE_STARTD_AUTHENTICATION unset: SEC_DAEMON_AUTHENTICATION.
	expect("DC_NOP_ADVERTISE_STARTD", commands.DC_NOP_ADVERTISE_STARTD, false, true)
	expect("DC_NOP_DAEMON", commands.DC_NOP_DAEMON, false, true)
	// SEC_READ_* applies to READ commands only.
	expect("READ command", seclevelReadCmd, true, false)
	expect("DC_NOP_READ", commands.DC_NOP_READ, true, false)
	expect("WRITE command", seclevelWriteCmd, true, true)
	expect("DC_NOP (ALLOW)", commands.DC_NOP, true, true)
	expect("command at no level", seclevelNoPermCmd, true, true)

	// A session negotiated under a level's policy resumes.
	cache := security.NewSessionCache()
	for i, wantResumed := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cl, err := client.ConnectAndAuthenticate(ctx, addr, &security.SecurityConfig{
			Command:        commands.DC_NOP_DAEMON,
			AuthMethods:    []security.AuthMethod{security.AuthFS},
			Authentication: security.SecurityRequired,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityOptional,
			Integrity:      security.SecurityOptional,
			SessionCache:   cache,
		})
		cancel()
		if err != nil {
			t.Fatalf("authenticated DC_NOP_DAEMON %d: %v", i+1, err)
		}
		if got := cl.GetSecurityNegotiation().SessionResumed; got != wantResumed {
			t.Errorf("DC_NOP_DAEMON %d resumed its session = %v, want %v", i+1, got, wantResumed)
		}
		_ = cl.Close()
	}

	// SEC_ADVERTISE_STARTD_* set: its own, after a reconfig.
	knobs["SEC_ADVERTISE_STARTD_AUTHENTICATION"] = "OPTIONAL"
	knobs["SEC_ADVERTISE_STARTD_ENCRYPTION"] = "REQUIRED"
	rewrite(knobs)
	d.Reconfigure()
	expect("DC_NOP_ADVERTISE_STARTD", commands.DC_NOP_ADVERTISE_STARTD, true, false)
	// Not the other ADVERTISE_* levels, which still take DAEMON's.
	expect("DC_NOP_ADVERTISE_SCHEDD", commands.DC_NOP_ADVERTISE_SCHEDD, false, true)
	expect("READ command", seclevelReadCmd, true, false)
}

// TestInstallSecurityLevelsAdvertisesDaemonVersion: a command negotiated under
// a per-level policy advertises the base policy's RemoteVersion, as one
// negotiated under the base policy does, not cedar's built-in default. A C++
// peer gates wire features on the version.
func TestInstallSecurityLevelsAdvertisesDaemonVersion(t *testing.T) {
	addr, _, _ := startSeclevelServer(t, map[string]string{"SEC_DEFAULT_AUTHENTICATION": "OPTIONAL"})
	for name, cmd := range map[string]int{
		"DC_NOP_READ":         commands.DC_NOP_READ,
		"WRITE command":       seclevelWriteCmd,
		"command at no level": seclevelNoPermCmd,
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cl, err := client.ConnectAndAuthenticate(ctx, addr, &security.SecurityConfig{
			Command:        cmd,
			AuthMethods:    []security.AuthMethod{security.AuthFS},
			Authentication: security.SecurityOptional,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityOptional,
			Integrity:      security.SecurityOptional,
			SessionCache:   security.NewSessionCache(),
		})
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := cl.GetSecurityNegotiation().ServerConfig.RemoteVersion; got != seclevelVersion {
			t.Errorf("%s: server advertised version %q, want %q", name, got, seclevelVersion)
		}
		_ = cl.Close()
	}
}
