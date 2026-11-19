package daemon

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// TestSessionDBFileName pins the naming convention: the shared "sessions_"
// prefix lets administrators exclude every daemon's session database from
// spool cleanup with one glob (VALID_SPOOL_FILES = sessions_*), while the
// subsystem + local-name keep instances sharing a SPOOL from opening each
// other's databases.
func TestSessionDBFileName(t *testing.T) {
	cases := []struct{ subsys, local, want string }{
		{"COLLECTOR", "", "sessions_collector.db"},
		{"COLLECTOR", "ViewServer", "sessions_collector_viewserver.db"},
		{"HTCONDORDB", "JobsDB", "sessions_htcondordb_jobsdb.db"},
	}
	for _, tc := range cases {
		if got := SessionDBFileName(tc.subsys, tc.local); got != tc.want {
			t.Errorf("SessionDBFileName(%q,%q) = %q, want %q", tc.subsys, tc.local, got, tc.want)
		}
	}
}

func autoTestDaemon(t *testing.T, confText string) *Daemon {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(confText))
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Options{Subsys: "TESTDAEMON", LocalName: "auto", Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestSessionPersistenceFromConfig covers the single-knob policy matrix:
// SEC_PERSIST_SESSIONS defaults OFF; when set, missing prerequisites are fatal.
