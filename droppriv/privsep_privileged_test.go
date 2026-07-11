//go:build linux

package droppriv

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestPoolPrivilegedSwitchesCredentials proves the pool backend really runs
// operations as a target user: helpers switch credentials permanently, so files
// they create are owned by that uid and launched commands run as it. Requires
// root; skipped otherwise.
func TestPoolPrivilegedSwitchesCredentials(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}

	target, err := lookupUser("nobody")
	if err != nil {
		t.Skipf("cannot resolve nobody: %v", err)
	}

	mgr, err := NewManager(Config{CondorUser: "condor"})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	ps, err := NewPrivsep(PrivsepConfig{Mode: ModePool, Manager: mgr})
	if err != nil {
		t.Fatalf("NewPrivsep: %v", err)
	}
	defer func() { _ = ps.Close() }()
	ctx := context.Background()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the target user must traverse into the temp dir
		t.Fatal(err)
	}

	// MkdirAll as nobody: the created directory must be owned by nobody.
	sub := filepath.Join(dir, "made-by-nobody")
	if err := ps.MkdirAll(ctx, "nobody", sub, 0o755); err != nil {
		t.Fatalf("MkdirAll as nobody: %v", err)
	}
	assertOwner(t, sub, target.UID)

	// OpenFile as nobody: the created file must be owned by nobody.
	file := filepath.Join(sub, "f.txt")
	f, err := ps.OpenFile(ctx, "nobody", file, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("OpenFile as nobody: %v", err)
	}
	if _, err := f.WriteString("owned by nobody\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	assertOwner(t, file, target.UID)

	// Command as nobody: `id -u` must print nobody's uid.
	pr, pw, _ := os.Pipe()
	proc, err := ps.Command(ctx, "nobody", CommandSpec{Path: "/bin/sh", Args: []string{"-c", "id -u"}, Stdout: pw})
	if err != nil {
		t.Fatalf("Command as nobody: %v", err)
	}
	_ = pw.Close()
	out, _ := io.ReadAll(pr)
	_ = pr.Close()
	if err := proc.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != itoa(int(target.UID)) {
		t.Fatalf("command ran as uid %q, want %d", got, target.UID)
	}
}

func assertOwner(t *testing.T, path string, uid uint32) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no syscall.Stat_t for %s", path)
	}
	if st.Uid != uid {
		t.Fatalf("%s owned by uid %d, want %d", path, st.Uid, uid)
	}
}
