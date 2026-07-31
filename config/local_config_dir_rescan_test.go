package config

import (
	"os"
	"path/filepath"
	"testing"
)

// mkdirs is a small helper that creates each directory (and parents).
func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
}

// writeFile is a small helper that writes a config file.
func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestLocalConfigDirSelfAppendScanned is the regression guard for issue #169: a
// config file that appends a directory to LOCAL_CONFIG_DIR
// (LOCAL_CONFIG_DIR = $(LOCAL_CONFIG_DIR),/extra) must cause that directory to be
// scanned. Previously LOCAL_CONFIG_DIR was read once and the appended directory
// was silently ignored, unlike condor_config_val.
func TestLocalConfigDirSelfAppendScanned(t *testing.T) {
	tmp := t.TempDir()
	dirA := filepath.Join(tmp, "a.d")
	dirB := filepath.Join(tmp, "b.d")
	mkdirs(t, dirA, dirB)

	root := filepath.Join(tmp, "condor_config")
	writeFile(t, root, "LOCAL_CONFIG_DIR = "+dirA+"\n")
	// A file in the initially-scanned dir appends a second directory.
	writeFile(t, filepath.Join(dirA, "20-append.conf"),
		"FROM_DIR_A = yes\nLOCAL_CONFIG_DIR = $(LOCAL_CONFIG_DIR),"+dirB+"\n")
	// The appended directory carries the value the daemon must pick up.
	writeFile(t, filepath.Join(dirB, "50-port.conf"),
		"FROM_APPENDED_DIR = yes\nSHARED_PORT_PORT = 9620\n")

	t.Setenv("CONDOR_CONFIG", root)
	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for key, want := range map[string]string{
		"FROM_DIR_A":        "yes",  // the initial dir was scanned
		"FROM_APPENDED_DIR": "yes",  // the appended dir was scanned (the bug)
		"SHARED_PORT_PORT":  "9620", // ...and its values took effect
	} {
		if got, _ := cfg.Get(key); got != want {
			t.Errorf("Get(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestLocalConfigDirAppendChainMultiLevel covers an append chain deeper than one
// level (a -> b -> c): each newly scanned directory appends the next. This needs
// more than a single re-scan, so it exercises the loop-until-converged behavior
// (stricter than condor_config's single re-check).
func TestLocalConfigDirAppendChainMultiLevel(t *testing.T) {
	tmp := t.TempDir()
	dirA := filepath.Join(tmp, "a.d")
	dirB := filepath.Join(tmp, "b.d")
	dirC := filepath.Join(tmp, "c.d")
	mkdirs(t, dirA, dirB, dirC)

	root := filepath.Join(tmp, "condor_config")
	writeFile(t, root, "LOCAL_CONFIG_DIR = "+dirA+"\n")
	writeFile(t, filepath.Join(dirA, "20.conf"), "LOCAL_CONFIG_DIR = $(LOCAL_CONFIG_DIR),"+dirB+"\n")
	writeFile(t, filepath.Join(dirB, "20.conf"), "LOCAL_CONFIG_DIR = $(LOCAL_CONFIG_DIR),"+dirC+"\n")
	writeFile(t, filepath.Join(dirC, "50.conf"), "FROM_DIR_C = yes\n")

	t.Setenv("CONDOR_CONFIG", root)
	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("FROM_DIR_C"); got != "yes" {
		t.Errorf("Get(FROM_DIR_C) = %q, want yes: a multi-level append chain was not fully followed", got)
	}
}

// TestLocalConfigDirRescanPicksUpFileAddedLater mirrors the issue's exact flow:
// a daemon starts, then a file is dropped into the appended directory, then the
// config is reloaded. A fresh load (as a reconfig performs) must see the new
// file. The first load sees the appended directory empty; the second sees the
// added file.
func TestLocalConfigDirRescanPicksUpFileAddedLater(t *testing.T) {
	tmp := t.TempDir()
	dirA := filepath.Join(tmp, "a.d")
	dirB := filepath.Join(tmp, "b.d") // the daemon-owned drop directory
	mkdirs(t, dirA, dirB)

	root := filepath.Join(tmp, "condor_config")
	writeFile(t, root, "LOCAL_CONFIG_DIR = "+dirA+"\n")
	writeFile(t, filepath.Join(dirA, "20-append.conf"),
		"LOCAL_CONFIG_DIR = $(LOCAL_CONFIG_DIR),"+dirB+"\n")

	t.Setenv("CONDOR_CONFIG", root)

	// First load: the appended directory exists but is empty.
	cfg1, err := New()
	if err != nil {
		t.Fatalf("New (initial): %v", err)
	}
	if _, ok := cfg1.Get("DROPPED_LATER"); ok {
		t.Fatal("DROPPED_LATER unexpectedly set before the file existed")
	}

	// Drop a config file into the appended directory (as the daemon would).
	writeFile(t, filepath.Join(dirB, "50-dropped.conf"), "DROPPED_LATER = yes\n")

	// Reload: a fresh load must now pick up the dropped file.
	cfg2, err := New()
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	if got, _ := cfg2.Get("DROPPED_LATER"); got != "yes" {
		t.Errorf("Get(DROPPED_LATER) = %q, want yes: reload did not scan the appended directory", got)
	}
}

// TestLocalConfigDirSelfAppendTerminates guards termination: a file that appends
// its OWN directory must not cause the scan to loop forever. The directory is
// scanned once (already-scanned directories are skipped) and loading completes.
func TestLocalConfigDirSelfAppendTerminates(t *testing.T) {
	tmp := t.TempDir()
	dirA := filepath.Join(tmp, "a.d")
	mkdirs(t, dirA)

	root := filepath.Join(tmp, "condor_config")
	writeFile(t, root, "LOCAL_CONFIG_DIR = "+dirA+"\n")
	writeFile(t, filepath.Join(dirA, "20.conf"),
		"MARKER = yes\nLOCAL_CONFIG_DIR = $(LOCAL_CONFIG_DIR),"+dirA+"\n")

	t.Setenv("CONDOR_CONFIG", root)
	cfg, err := New() // must return, not hang
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("MARKER"); got != "yes" {
		t.Errorf("Get(MARKER) = %q, want yes", got)
	}
}
