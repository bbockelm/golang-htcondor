//go:build !condor_nosqlite

package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// This exercises the path that actually opens a store, so it needs one
// linked. A condor_nosqlite build has none by design; the counterpart in
// sessionauto_nostore_test.go asserts what happens then.
func TestSessionPersistenceFromConfig(t *testing.T) {
	// Knob unset: default off, nothing happens even with prerequisites present.
	spool := t.TempDir()
	keydir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keydir, "POOL"), []byte("test-signing-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := autoTestDaemon(t, "SPOOL = "+spool+"\nSEC_PASSWORD_DIRECTORY = "+keydir+"\n")
	if closer, err := d.sessionPersistenceFromConfig(); err != nil || closer != nil {
		t.Fatalf("knob unset: got closer=%v err=%v, want nil/nil (default off)", closer != nil, err)
	}

	// Explicitly off: same.
	d = autoTestDaemon(t, "SEC_PERSIST_SESSIONS = false\nSPOOL = "+spool+"\n")
	if closer, err := d.sessionPersistenceFromConfig(); err != nil || closer != nil {
		t.Fatalf("explicit false: got closer=%v err=%v, want nil/nil", closer != nil, err)
	}

	// Enabled without SPOOL: fatal misconfiguration, not a quiet skip.
	d = autoTestDaemon(t, "SEC_PERSIST_SESSIONS = true\n")
	if _, err := d.sessionPersistenceFromConfig(); err == nil {
		t.Fatal("enabled without SPOOL succeeded; must be fatal")
	}

	// Enabled without signing keys: fatal, never plaintext.
	d = autoTestDaemon(t, "SEC_PERSIST_SESSIONS = true\nSPOOL = "+spool+"\n")
	if _, err := d.sessionPersistenceFromConfig(); err == nil {
		t.Fatal("enabled without signing keys succeeded; must be fatal")
	}

	// Enabled with SPOOL + a signing key: database created under the
	// prefix-named default, closer returned.
	d = autoTestDaemon(t, "SEC_PERSIST_SESSIONS = true\nSPOOL = "+spool+"\nSEC_PASSWORD_DIRECTORY = "+keydir+"\n")
	closer, err := d.sessionPersistenceFromConfig()
	if err != nil {
		t.Fatalf("enabled with prerequisites: %v", err)
	}
	if closer == nil {
		t.Fatal("enabled with prerequisites returned no closer (not enabled?)")
	}
	closer()
	want := filepath.Join(spool, "sessions_testdaemon_auto.db")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("session database not created at %s: %v", want, err)
	}

	// SEC_SESSION_CACHE_FILE overrides the SPOOL-derived path entirely.
	override := filepath.Join(t.TempDir(), "my_sessions.db")
	d = autoTestDaemon(t, "SEC_PERSIST_SESSIONS = true\nSEC_SESSION_CACHE_FILE = "+override+"\nSEC_PASSWORD_DIRECTORY = "+keydir+"\n")
	closer, err = d.sessionPersistenceFromConfig()
	if err != nil {
		t.Fatalf("override path: %v", err)
	}
	if closer == nil {
		t.Fatal("override path returned no closer")
	}
	closer()
	if _, err := os.Stat(override); err != nil {
		t.Fatalf("session database not created at override path %s: %v", override, err)
	}
}
