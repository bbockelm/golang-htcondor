package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	return logger
}

// configWithLocalSchedd returns a config whose SPOOL holds a schedd
// address file, i.e. a host that runs its own schedd.
func configWithLocalSchedd(t *testing.T) *config.Config {
	t.Helper()
	spool := t.TempDir()
	if err := os.WriteFile(filepath.Join(spool, ".schedd_address"), []byte("<127.0.0.1:1234?sock=schedd>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewEmpty()
	cfg.Set("SPOOL", spool)
	return cfg
}

// TestScheddHostBeatsLocalAddressFile is the reported problem: on a host
// that runs its own schedd, a SCHEDD_HOST pointing at a central access
// point must win. With a port in the value no collector is needed, which
// is what makes this assertion possible without one.
func TestScheddHostBeatsLocalAddressFile(t *testing.T) {
	cfg := configWithLocalSchedd(t)

	addr, name := discoverSchedd(cfg, nil, testLogger(t), "", "central.example.edu:9618")
	if addr != "central.example.edu:9618" {
		t.Errorf("addr = %q, want the SCHEDD_HOST address rather than the local address file", addr)
	}
	if name != "" {
		t.Errorf("name = %q, want empty for a SCHEDD_HOST with no name part", name)
	}

	addr, name = discoverSchedd(cfg, nil, testLogger(t), "", "submit@central.example.edu:9618")
	if addr != "central.example.edu:9618" {
		t.Errorf("addr = %q, want the host part of name@host:port", addr)
	}
	if name != "submit" {
		t.Errorf("name = %q, want submit", name)
	}
}

// TestExplicitScheddNameBeatsScheddHost keeps the documented precedence:
// an operator who names a schedd (-schedd or SCHEDD_NAME) means that
// one, so SCHEDD_HOST must not redirect it. With no collector to resolve
// the name, discovery falls back to the local address file.
func TestExplicitScheddNameBeatsScheddHost(t *testing.T) {
	cfg := configWithLocalSchedd(t)

	addr, _ := discoverSchedd(cfg, nil, testLogger(t), "named-schedd", "central.example.edu:9618")
	if addr == "central.example.edu:9618" {
		t.Error("SCHEDD_HOST must not override an explicitly requested schedd name")
	}
	if addr != "<127.0.0.1:1234?sock=schedd>" {
		t.Errorf("addr = %q, want the local address file", addr)
	}
}

// TestNoScheddHostUsesLocalAddressFile is the unchanged default: no
// SCHEDD_HOST, so the local schedd is used.
func TestNoScheddHostUsesLocalAddressFile(t *testing.T) {
	cfg := configWithLocalSchedd(t)

	addr, _ := discoverSchedd(cfg, nil, testLogger(t), "", "")
	if addr != "<127.0.0.1:1234?sock=schedd>" {
		t.Errorf("addr = %q, want the local address file", addr)
	}
}

// TestScheddHostWithoutPortFallsBackWithoutCollector documents the one
// case SCHEDD_HOST cannot serve on its own: a bare hostname needs the
// collector to become an address, so with no collector configured
// discovery falls back to the local knobs rather than failing.
func TestScheddHostWithoutPortFallsBackWithoutCollector(t *testing.T) {
	cfg := configWithLocalSchedd(t)

	addr, _ := discoverSchedd(cfg, nil, testLogger(t), "", "central.example.edu")
	if addr != "<127.0.0.1:1234?sock=schedd>" {
		t.Errorf("addr = %q, want the local address file as the fallback", addr)
	}
}

// TestGetScheddConfigReadsScheddHost checks the knob is actually read.
func TestGetScheddConfigReadsScheddHost(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("SCHEDD_NAME", "from-name")
	cfg.Set("SCHEDD_HOST", "submit@central.example.edu")

	name, addr, host := getScheddConfig(cfg)
	if name != "from-name" {
		t.Errorf("name = %q, want from-name", name)
	}
	if addr != "" {
		t.Errorf("addr = %q, want empty", addr)
	}
	if host != "submit@central.example.edu" {
		t.Errorf("host = %q, want the SCHEDD_HOST value", host)
	}
}

// TestLocalScheddAddressFileTakesFirstLineOnly is the reported failure: a
// real HTCondor schedd address file carries the sinful string on line 1
// and then metadata lines ($CondorVersion, CredDIpAddr, Machine, Name,
// SubmitAlwaysCheckCreds). Slurping the whole file left those lines inside
// the address, so the shared-port sock id parsed as
// "schedd_6739_f8d1> $CondorVersion..." and the connection failed with
// "invalid shared port ID". discoverSchedd must return only the sinful.
func TestLocalScheddAddressFileTakesFirstLineOnly(t *testing.T) {
	const sinful = "<128.105.68.12:9618?addrs=128.105.68.12-9618+[2607-f388-2200-100-216-3eff-fe63-f8d6]-9618&alias=ap1.facility.path-cc.io&noUDP&sock=schedd_6739_f8d1>"
	content := sinful + "\n" +
		"$CondorVersion: 25.14.0 2026-09-03 BuildID: 949436 PackageID: 25.14.0-0.949436 RC $\n" +
		"$CondorPlatform: x86_64_AlmaLinux9 $\n" +
		`CredDIpAddr = "<128.105.68.12:9618?sock=credd_6739_f8d1>"` + "\n" +
		`Machine = "ap1.facility.path-cc.io"` + "\n" +
		`Name = "ap1.facility.path-cc.io"` + "\n" +
		"SubmitAlwaysCheckCreds = true\n"

	spool := t.TempDir()
	if err := os.WriteFile(filepath.Join(spool, ".schedd_address"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewEmpty()
	cfg.Set("SPOOL", spool)

	addr, _ := discoverSchedd(cfg, nil, testLogger(t), "", "")
	if addr != sinful {
		t.Errorf("addr = %q,\nwant only the first-line sinful %q", addr, sinful)
	}
	if strings.Contains(addr, "\n") || strings.Contains(addr, "CondorVersion") {
		t.Errorf("addr carried trailing address-file metadata: %q", addr)
	}
}
