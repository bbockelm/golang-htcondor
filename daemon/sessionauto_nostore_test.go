//go:build condor_nosqlite

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A build with no session store must REFUSE SEC_PERSIST_SESSIONS, not skip it.
//
// This is the whole safety argument for the build tag. An administrator who
// turns persistence on and gets a daemon that runs without it has lost
// session resumption across restarts with nothing to tell them: the sessions
// simply are not there afterwards. Failing at startup is recoverable in a way
// that silence is not, and the error has to name the tag, because the cause
// is a build-time choice invisible from the configuration.
func TestSessionPersistenceRefusedWithNoStoreLinked(t *testing.T) {
	spool := t.TempDir()
	keydir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keydir, "POOL"), []byte("test-signing-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := autoTestDaemon(t, "SEC_PERSIST_SESSIONS = true\nSPOOL = "+spool+"\nSEC_PASSWORD_DIRECTORY = "+keydir+"\n")

	closer, err := d.sessionPersistenceFromConfig()
	if err == nil {
		if closer != nil {
			closer()
		}
		t.Fatal("SEC_PERSIST_SESSIONS was accepted in a build with no session store linked; " +
			"it must fail rather than run without the persistence that was asked for")
	}
	if closer != nil {
		t.Error("a failed open returned a closer")
	}
	// The message must name the tag: the configuration looks correct, so
	// nothing else points at the build.
	if !strings.Contains(err.Error(), "condor_nosqlite") {
		t.Errorf("the error does not name the build tag that caused it: %v", err)
	}
	if !strings.Contains(err.Error(), "SEC_PERSIST_SESSIONS") {
		t.Errorf("the error does not name the knob that was set: %v", err)
	}
}
