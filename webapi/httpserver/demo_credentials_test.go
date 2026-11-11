package httpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

func demoCredsHandler(t *testing.T, path string) *Handler {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return &Handler{logger: lg, demoCredentialsFile: path}
}

func readDemoCreds(t *testing.T, path string) demoCredentialsDoc {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc demoCredentialsDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, body)
	}
	return doc
}

// The file is the published contract for -demo, so assert on the shape a
// consumer actually reads: a version it can gate on, and a password
// reachable by username without knowing the order they were seeded in.
func TestWriteDemoCredentialsShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	h := demoCredsHandler(t, path)

	creds := []demoCredential{
		{Username: "admin", Password: "pw-admin", State: "admin"},
		{Username: "user", Password: "pw-user", State: "active", Note: "ordinary user"},
		{Username: "newbie", Password: "pw-newbie", State: "active", Note: "no access"},
	}
	if err := h.writeDemoCredentials(creds); err != nil {
		t.Fatalf("writeDemoCredentials: %v", err)
	}

	doc := readDemoCreds(t, path)
	if doc.Version != demoCredentialsVersion {
		t.Errorf("version = %d, want %d", doc.Version, demoCredentialsVersion)
	}
	if doc.GeneratedAt.IsZero() {
		t.Error("generated_at is zero")
	}

	byName := map[string]demoCredential{}
	for _, c := range doc.Users {
		byName[c.Username] = c
	}
	if got := byName["admin"]; got.Password != "pw-admin" || got.State != "admin" {
		t.Errorf("admin = %+v, want password pw-admin state admin", got)
	}
	// The non-admin account's state is what tells a harness which
	// identity to use for an authorization boundary; a file that got it
	// backwards would make those tests pass against the wrong user.
	if got := byName["user"]; got.Password != "pw-user" || got.State != "active" {
		t.Errorf("user = %+v, want password pw-user state active", got)
	}

	// "user" and "newbie" are BOTH state "active" and are told apart
	// only by the note. A harness that picked by state alone would get
	// whichever came first, so the note has to survive the round trip.
	if got := byName["newbie"]; got.Password != "pw-newbie" || got.Note == "" {
		t.Errorf("newbie = %+v, want password pw-newbie and a non-empty note", got)
	}
	if byName["user"].Note == byName["newbie"].Note {
		t.Error("user and newbie carry the same note; nothing distinguishes them")
	}
}

// 0600 is the only thing standing between the default /tmp path and any
// other account on the host.
func TestWriteDemoCredentialsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	h := demoCredsHandler(t, path)

	if err := h.writeDemoCredentials([]demoCredential{{Username: "admin", Password: "p", State: "admin"}}); err != nil {
		t.Fatalf("writeDemoCredentials: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
}

// A second demo run on the same host must replace the file rather than
// fail the open, or the server dies at startup on every run but the
// first.
func TestWriteDemoCredentialsReplacesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"users":[{"username":"stale","password":"old"}]}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := demoCredsHandler(t, path)

	if err := h.writeDemoCredentials([]demoCredential{{Username: "admin", Password: "fresh", State: "admin"}}); err != nil {
		t.Fatalf("writeDemoCredentials: %v", err)
	}
	doc := readDemoCreds(t, path)
	if len(doc.Users) != 1 || doc.Users[0].Username != "admin" || doc.Users[0].Password != "fresh" {
		t.Fatalf("stale content survived: %+v", doc.Users)
	}
}

// The default path is in a world-writable directory, so a pre-planted
// symlink is the attack this guards against: the password must land in
// a new regular file at the path, and NOT be written through the link.
func TestWriteDemoCredentialsDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	target := filepath.Join(dir, "victim")

	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	h := demoCredsHandler(t, path)
	if err := h.writeDemoCredentials([]demoCredential{{Username: "admin", Password: "secret", State: "admin"}}); err != nil {
		t.Fatalf("writeDemoCredentials: %v", err)
	}

	victim, err := os.ReadFile(target) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(victim) != "untouched" {
		t.Fatalf("symlink was followed: target now holds %q", victim)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("path is still a symlink; nothing was written")
	}
	if doc := readDemoCreds(t, path); len(doc.Users) != 1 || doc.Users[0].Password != "secret" {
		t.Fatalf("credentials not written to the path: %+v", doc.Users)
	}
}

// Empty path is how a non-demo deployment opts out; it must not create
// a file and must not error.
func TestWriteDemoCredentialsDisabled(t *testing.T) {
	dir := t.TempDir()
	h := demoCredsHandler(t, "")
	if err := h.writeDemoCredentials([]demoCredential{{Username: "admin", Password: "p", State: "admin"}}); err != nil {
		t.Fatalf("writeDemoCredentials: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("wrote something with an empty path: %v", entries)
	}
}
