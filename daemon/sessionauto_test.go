package daemon

import (
	"os"
	"path/filepath"
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

// TestAutoSessionPersistence covers the default-on policy matrix.
func TestAutoSessionPersistence(t *testing.T) {
	// Explicitly off: nothing happens.
	d := autoTestDaemon(t, "TESTDAEMON_PERSIST_SESSIONS = false\n")
	if closer, err := d.autoSessionPersistence(); err != nil || closer != nil {
		t.Fatalf("explicit false: got closer=%v err=%v, want nil/nil", closer != nil, err)
	}

	// AUTO with no SPOOL and no keys: skips quietly.
	d = autoTestDaemon(t, "")
	if closer, err := d.autoSessionPersistence(); err != nil || closer != nil {
		t.Fatalf("auto without prerequisites: got closer=%v err=%v, want nil/nil (skip)", closer != nil, err)
	}

	// Explicitly required without signing keys: fatal, never plaintext.
	spool := t.TempDir()
	d = autoTestDaemon(t, "TESTDAEMON_PERSIST_SESSIONS = true\nSPOOL = "+spool+"\n")
	if _, err := d.autoSessionPersistence(); err == nil {
		t.Fatal("required without signing keys succeeded; must be a fatal misconfiguration")
	}

	// AUTO with SPOOL + a signing key: enabled, database created under the
	// prefix-named default, closer returned.
	keydir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keydir, "POOL"), []byte("test-signing-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	d = autoTestDaemon(t, "SPOOL = "+spool+"\nSEC_PASSWORD_DIRECTORY = "+keydir+"\n")
	closer, err := d.autoSessionPersistence()
	if err != nil {
		t.Fatalf("auto with prerequisites: %v", err)
	}
	if closer == nil {
		t.Fatal("auto with prerequisites returned no closer (not enabled?)")
	}
	defer closer()
	want := filepath.Join(spool, "sessions_testdaemon_auto.db")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("session database not created at %s: %v", want, err)
	}
}
