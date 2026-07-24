package daemon

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// TestReadyNameFallsBackToSubsystem verifies that when running under
// condor_master without _CONDOR_DAEMON_NAME (HTCondor does not export it), the
// daemon reports its subsystem as the DC_SET_READY DaemonName, so the master
// does not log an empty "Setting ready state 'Ready' for ".
func TestReadyNameFallsBackToSubsystem(t *testing.T) {
	t.Setenv("CONDOR_CONFIG", "/dev/null")
	// Under condor_master: CONDOR_INHERIT = "<parentPID> <master-sinful>".
	t.Setenv("CONDOR_INHERIT", "1234 <127.0.0.1:9618>")
	t.Setenv("_CONDOR_DAEMON_NAME", "") // explicitly unset, as in a real master

	d, err := New(Options{Subsys: "HTCONDORDB", Config: config.NewEmpty()})
	if err != nil {
		t.Fatal(err)
	}
	m := d.Master()
	if m == nil {
		t.Fatal("expected a master (running under condor_master), got nil")
	}
	if got := m.DaemonName(); got != "HTCONDORDB" {
		t.Errorf("ready DaemonName = %q, want %q (subsystem fallback)", got, "HTCONDORDB")
	}
}

// TestReadyNamePrefersEnv verifies an explicit _CONDOR_DAEMON_NAME (if a future
// master ever exports it) is not overwritten by the subsystem fallback.
func TestReadyNamePrefersEnv(t *testing.T) {
	t.Setenv("CONDOR_CONFIG", "/dev/null")
	t.Setenv("CONDOR_INHERIT", "1234 <127.0.0.1:9618>")
	t.Setenv("_CONDOR_DAEMON_NAME", "HTCONDORDB_VIEW")

	d, err := New(Options{Subsys: "HTCONDORDB", Config: config.NewEmpty()})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Master().DaemonName(); got != "HTCONDORDB_VIEW" {
		t.Errorf("ready DaemonName = %q, want %q (env should win)", got, "HTCONDORDB_VIEW")
	}
}
