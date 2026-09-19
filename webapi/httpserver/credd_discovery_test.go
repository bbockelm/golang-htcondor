package httpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

func discoveryLogger(t *testing.T) *logging.Logger {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return lg
}

// writeAddressFile writes an HTCondor address file: the sinful on the first
// line, metadata after it.
func writeAddressFile(t *testing.T, dir, name, sinful string, metadata ...string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	body := sinful + "\n$CondorVersion: 25.8.0\n" + strings.Join(metadata, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestConfiguredCreddWins: an operator who names the credd means it, whatever
// discovery would otherwise find.
func TestConfiguredCreddWins(t *testing.T) {
	addr, err := discoverCredd(context.Background(), creddLookup{
		configured: "<10.0.0.5:9618?sock=credd>",
		scheddName: "ap.example.org",
	}, discoveryLogger(t))
	if err != nil {
		t.Fatalf("discoverCredd: %v", err)
	}
	if addr != "<10.0.0.5:9618?sock=credd>" {
		t.Errorf("addr = %q, want the configured one", addr)
	}
}

// TestCreddFromLocalScheddAddressFile: a schedd on this host publishes its
// credd in its own address file, so a single-host deployment needs no
// collector at all.
func TestCreddFromLocalScheddAddressFile(t *testing.T) {
	dir := t.TempDir()
	const scheddAddr = "<192.168.1.10:9618?sock=schedd>"
	const creddAddr = "<192.168.1.10:9618?sock=credd_6739_f8d1>" //nolint:gosec // G101: a daemon address, not a credential.
	file := writeAddressFile(t, dir, ".schedd_address", scheddAddr,
		`CredDIpAddr = "`+creddAddr+`"`, `Machine = "ap.example.org"`)

	got, err := discoverCredd(context.Background(), creddLookup{
		scheddAddr:        scheddAddr,
		scheddIsLocal:     true,
		scheddAddressFile: file,
	}, discoveryLogger(t))
	if err != nil {
		t.Fatalf("discoverCredd: %v", err)
	}
	if got != creddAddr {
		t.Errorf("addr = %q, want %q", got, creddAddr)
	}
}

// TestRemoteScheddWithoutCredDIpAddrIsRefused is the failure this design
// exists to produce. A remote schedd that does not say which credd it uses
// must yield an error, NOT this host's credd: credentials written to the wrong
// credd are accepted, reported as stored, and leave the job held anyway.
func TestRemoteScheddWithoutCredDIpAddrIsRefused(t *testing.T) {
	_, err := discoverCredd(context.Background(), creddLookup{
		scheddName:    "remote-ap.example.org",
		scheddAddr:    "<10.9.9.9:9618?sock=schedd>",
		scheddIsLocal: false,
		// No collector, no configured address: nothing can identify its credd.
	}, discoveryLogger(t))
	if err == nil {
		t.Fatal("a remote schedd with no advertised credd was given one anyway")
	}
	if !strings.Contains(err.Error(), "HTTP_API_CREDD_ADDRESS") {
		t.Errorf("the error does not say how to fix it: %v", err)
	}
}

// TestLocalAddressFileOnlyForALocalSchedd: the local credd file is a fallback
// for a schedd on this host and must never answer for a remote one.
//
// The local credd is injected rather than left to the host, so this fails when
// the rule is broken instead of passing on any machine that has no credd.
func TestLocalAddressFileOnlyForALocalSchedd(t *testing.T) {
	const localCredd = "<127.0.0.1:9618?sock=credd>" //nolint:gosec // G101: a daemon address, not a credential.
	present := func(*logging.Logger) string { return localCredd }

	if _, err := discoverCredd(context.Background(), creddLookup{
		scheddName:    "remote-ap.example.org",
		scheddAddr:    "<10.9.9.9:9618?sock=schedd>",
		scheddIsLocal: false,
		localCredd:    present,
	}, discoveryLogger(t)); err == nil {
		t.Error("a remote schedd was given this host's credd")
	}

	// The same lookup is used for a local schedd, so the fallback is real
	// and the test above is about the rule rather than about absence.
	got, err := discoverCredd(context.Background(), creddLookup{
		scheddName:    "ap.example.org",
		scheddAddr:    "<127.0.0.1:9618?sock=schedd>",
		scheddIsLocal: true,
		localCredd:    present,
	}, discoveryLogger(t))
	if err != nil {
		t.Fatalf("a local schedd did not fall back to the local credd: %v", err)
	}
	if got != localCredd {
		t.Errorf("addr = %q, want %q", got, localCredd)
	}
}

// TestScheddIsOnThisHost: locality is decided by whether this host's schedd
// address file names the schedd we are talking to, not by whether the address
// looks like loopback -- a schedd reached by its real hostname is still local,
// and loopback inside a container need not be.
func TestScheddIsOnThisHost(t *testing.T) {
	dir := t.TempDir()
	const ours = "<192.168.1.10:9618?sock=schedd>"
	file := writeAddressFile(t, dir, ".schedd_address", ours)

	if !scheddIsOnThisHost(file, ours) {
		t.Error("the host's own schedd was not recognised as local")
	}
	if scheddIsOnThisHost(file, "<10.9.9.9:9618?sock=schedd>") {
		t.Error("a different schedd was treated as local")
	}
	if scheddIsOnThisHost(filepath.Join(dir, "absent"), ours) {
		t.Error("a missing address file made a schedd look local")
	}
	if scheddIsOnThisHost(file, "") {
		t.Error("an empty schedd address was treated as local")
	}
}

// TestCreddFromAddressFileMetadata covers the parse: an address file is a
// sinful followed by metadata, and only the CredDIpAddr line is wanted.
func TestCreddFromAddressFileMetadata(t *testing.T) {
	dir := t.TempDir()
	const creddAddr = "<128.105.68.12:9618?sock=credd_6739_f8d1>" //nolint:gosec // G101: a daemon address, not a credential.
	file := writeAddressFile(t, dir, ".schedd_address", "<128.105.68.12:9618?sock=schedd>",
		`Machine = "ap.example.org"`, `CredDIpAddr = "`+creddAddr+`"`, `Name = "ap.example.org"`)

	got, err := creddFromAddressFileMetadata(file)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != creddAddr {
		t.Errorf("got %q, want %q", got, creddAddr)
	}

	none := writeAddressFile(t, dir, "no_credd", "<1.2.3.4:9618?sock=schedd>", `Machine = "x"`)
	if _, err := creddFromAddressFileMetadata(none); err == nil {
		t.Error("an address file without CredDIpAddr parsed anyway")
	}
}

// TestClassadStringQuoting guards the constraint built from a schedd name.
func TestClassadStringQuoting(t *testing.T) {
	if got := classadString(`ap.example.org`); got != `"ap.example.org"` {
		t.Errorf("got %s", got)
	}
	if got := classadString(`we"ird`); got != `"we\"ird"` {
		t.Errorf("got %s", got)
	}
}
