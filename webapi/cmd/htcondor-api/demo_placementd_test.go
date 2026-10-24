package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/idmap"
	"github.com/bbockelm/golang-htcondor/logging"
)

// fakeHTCondor puts an sbin directory holding the named executables, and
// nothing else, on PATH.
func fakeHTCondor(t *testing.T, names ...string) string {
	t.Helper()
	sbin := filepath.Join(t.TempDir(), "sbin")
	if err := os.MkdirAll(sbin, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		//nolint:gosec // a test executable
		if err := os.WriteFile(filepath.Join(sbin, n), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", sbin)
	return sbin
}

// demoLogger logs to a file the test can read back.
func demoLogger(t *testing.T) (*logging.Logger, func() string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	logger, err := logging.New(&logging.Config{OutputPath: path, DefaultLevel: logging.VerbosityDebug, SkipGlobalInstall: true})
	if err != nil {
		t.Fatal(err)
	}
	return logger, func() string {
		b, err := os.ReadFile(path) //nolint:gosec // the test's own file
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

// demoConfig writes the demo pool's configuration and parses it back.
func demoConfig(t *testing.T, placement *demoPlacement) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "condor_config")
	if err := writeMiniCondorConfig(path, dir, "/release", placement); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewFromReader(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("the demo config does not parse: %v", err)
	}
	return cfg, string(raw)
}

func demoKnob(t *testing.T, cfg *config.Config, knob string) string {
	t.Helper()
	v, ok := cfg.Get(knob)
	if !ok {
		t.Fatalf("%s is not set", knob)
	}
	return v
}

func TestDemoPlacementdAddedWhenPresent(t *testing.T) {
	sbin := fakeHTCondor(t, "condor_master", "condor_placementd")
	logger, logged := demoLogger(t)

	bin := lookForDemoPlacementd(logger)
	if want := filepath.Join(sbin, "condor_placementd"); bin != want {
		t.Fatalf("found %q, want %q", bin, want)
	}
	if strings.Contains(logged(), "no condor_placementd found") {
		t.Error("logged that there is no placementd when there is one")
	}

	localDir := t.TempDir()
	p, err := newDemoPlacement(localDir, bin)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := demoConfig(t, p)

	daemons := config.SplitConfigList(demoKnob(t, cfg, "DAEMON_LIST"))
	want := []string{"MASTER", "COLLECTOR", "NEGOTIATOR", "SCHEDD", "STARTD", "PLACEMENTD"}
	if strings.Join(daemons, " ") != strings.Join(want, " ") {
		t.Errorf("DAEMON_LIST = %v, want %v", daemons, want)
	}
	for knob, want := range map[string]string{
		"PLACEMENTD":                        bin,
		"PLACEMENTD_MAPFILE":                filepath.Join(localDir, "placementd_mapfile"),
		"PLACEMENTD_AUTHORIZATIONS_MAPFILE": filepath.Join(localDir, "placementd_authorizations"),
		"SEC_USE_TOKENS_DATABASE":           "True",
		"SEC_ACCEPT_CAPABILITY_TOKENS":      "True",
	} {
		if got := demoKnob(t, cfg, knob); got != want {
			t.Errorf("%s = %q, want %q", knob, got, want)
		}
	}

	files := map[string][]string{
		"placementd_mapfile": {
			"admin admin READ,WRITE 0 Demo",
			"user user READ,WRITE 0 Demo",
		},
		"placementd_authorizations": {
			"READ|Read|normal|View jobs",
			"WRITE|Write|warning|Submit and manage jobs",
		},
	}
	for name, wantLines := range files {
		raw, err := os.ReadFile(filepath.Join(localDir, name)) //nolint:gosec // the test's own file
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, line := range strings.Split(string(raw), "\n") {
			if line != "" && !strings.HasPrefix(line, "#") {
				got = append(got, line)
			}
		}
		if strings.Join(got, "\n") != strings.Join(wantLines, "\n") {
			t.Errorf("%s holds\n%s\nwant\n%s", name, strings.Join(got, "\n"), strings.Join(wantLines, "\n"))
		}
	}
}

func TestDemoPlacementdAbsentLeavesDemoUnchanged(t *testing.T) {
	fakeHTCondor(t, "condor_master")
	logger, logged := demoLogger(t)

	if bin := lookForDemoPlacementd(logger); bin != "" {
		t.Fatalf("found a placementd at %q where there is none", bin)
	}
	if !strings.Contains(logged(), "no condor_placementd found; placement features are off in demo mode") {
		t.Errorf("no log line saying placement is off; logged:\n%s", logged())
	}

	// What runDemoMode does with no placementd: a nil *demoPlacement.
	var p *demoPlacement
	cfg, raw := demoConfig(t, p)
	if got := demoKnob(t, cfg, "DAEMON_LIST"); got != "MASTER, COLLECTOR, NEGOTIATOR, SCHEDD, STARTD" {
		t.Errorf("DAEMON_LIST = %q", got)
	}
	for _, s := range []string{"PLACEMENTD", "TOKENS_DATABASE", "CAPABILITY"} {
		if strings.Contains(raw, s) {
			t.Errorf("the config mentions %s with no placementd", s)
		}
	}
	if strategies, passwd := p.identityMap(); strategies != nil || passwd != "" {
		t.Errorf("identity map %v %q with no placementd; demo mode has none", strategies, passwd)
	}
	var banner strings.Builder
	p.printBanner(&banner, "https://localhost:8080")
	if banner.Len() != 0 {
		t.Errorf("printed a placement banner with no placementd: %q", banner.String())
	}
}

// A placementd that is not executable is not one the master can run.
func TestDemoPlacementdNotExecutableIsAbsent(t *testing.T) {
	sbin := fakeHTCondor(t, "condor_master")
	//nolint:gosec // a test file
	if err := os.WriteFile(filepath.Join(sbin, "condor_placementd"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if bin := findDemoPlacementd(); bin != "" {
		t.Errorf("found %q, which is not executable", bin)
	}
}

// admin and user must sign in exactly as they do without a placementd: as
// themselves, by a local strategy that runs before the placementd is asked.
// Anyone else maps to no local account, so the placementd decides.
func TestDemoIdentityMapKeepsDemoAccountsLocal(t *testing.T) {
	p, err := newDemoPlacement(t.TempDir(), "/sbin/condor_placementd")
	if err != nil {
		t.Fatal(err)
	}
	strategies, passwd := p.identityMap()
	if len(strategies) < 2 || strategies[len(strategies)-1] != idmap.StrategyPlacementd {
		t.Fatalf("strategies %v: placementd must come last", strategies)
	}
	local := strategies[:len(strategies)-1]
	for _, s := range local {
		if s == idmap.StrategyPlacementd {
			t.Fatalf("strategies %v: placementd before a local strategy", strategies)
		}
	}

	r := idmap.New(&idmap.SystemAccounts{Path: passwd}, idmap.FileGecos{Path: passwd}, idmap.WithStrategies(local...))
	ctx := context.Background()
	for _, name := range []string{"admin", "user"} {
		got, err := r.Resolve(ctx, name)
		if err != nil || got != name {
			t.Errorf("%s maps to %q (%v), want itself", name, got, err)
		}
	}
	if got, err := r.Resolve(ctx, demoPlacementNewbie); !errors.Is(err, idmap.ErrNoMatch) {
		t.Errorf("%s maps to %q (%v); it must have no local account", demoPlacementNewbie, got, err)
	}

	raw, err := os.ReadFile(p.mapFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, demoPlacementNewbie+" ") {
			t.Errorf("the map file maps %s: %q", demoPlacementNewbie, line)
		}
	}
}
