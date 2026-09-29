package vscode

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// shortScratch makes a scratch directory with a short path.
//
// t.TempDir() will not do: on macOS it is under /var/folders/... and
// includes the test's own name, which put these paths at 112 and 121
// bytes and tripped the launcher's own sun_path check. That is the
// check doing its job -- an EXECUTE directory really can be that deep
// -- but it makes t.TempDir() unusable for the tests that need the
// launcher to get as far as starting something.
func shortScratch(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "vsc")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// runScript writes the launcher into scratch and runs it with
// _CONDOR_SCRATCH_DIR set, with fakeBin first on PATH. The script is
// what actually runs in a sandbox, so the tests run it rather than
// matching strings against it: a golden file would pass just as
// happily for a script that never executes.
func runScript(t *testing.T, a ScriptArgs, scratch, fakeBin string) (string, error) {
	t.Helper()
	return runScriptEnv(t, a, scratch, fakeBin)
}

// runScriptEnv is runScript with extra environment, for the cases that
// turn on what $HOME is.
func runScriptEnv(t *testing.T, a ScriptArgs, scratch, fakeBin string, env ...string) (string, error) {
	t.Helper()
	path := filepath.Join(scratch, ExecutableName)
	//nolint:gosec // G306: the launcher is the job's executable; running it is the test
	if err := os.WriteFile(path, []byte(LaunchScript(a)), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	// A context bounds the run: a launcher bug that blocks instead of
	// exiting would otherwise hang the suite until the test timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	//nolint:gosec // G204: running the generated script is the whole point
	cmd := exec.CommandContext(ctx, "/bin/sh", path)
	cmd.Dir = scratch
	cmd.Env = append(os.Environ(),
		"_CONDOR_SCRATCH_DIR="+scratch,
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// fakeServer puts a program named `name` on a fresh PATH directory. It
// records its own argv and the mode of the socket path it was handed,
// then exits, standing in for a server that would otherwise block.
func fakeServer(t *testing.T, argvFile string) string {
	t.Helper()
	const name = DefaultServerCommand
	dir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$@" > %q
# Create the socket the way the real server would, so the test can see
# what umask the launcher left in place.
for a in "$@"; do
	case "$prev" in --socket) : > "$a" ;; esac
	prev="$a"
done
exit 0
`, argvFile)
	path := filepath.Join(dir, name)
	//nolint:gosec // G306: a stand-in for the server binary, so executable
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake server: %v", err)
	}
	return dir
}

func TestLaunchScriptExecsTheServerOnAScratchSocket(t *testing.T) {
	scratch := shortScratch(t)
	argvFile := filepath.Join(t.TempDir(), "argv")
	bin := fakeServer(t, argvFile)

	out, err := runScript(t, ScriptArgs{}, scratch, bin)
	if err != nil {
		t.Fatalf("launcher failed: %v\n%s", err, out)
	}

	//nolint:gosec // G304: a path this test just created in its own temp dir
	argv, rerr := os.ReadFile(argvFile)
	if rerr != nil {
		t.Fatalf("the launcher never reached the server: %v\n%s", rerr, out)
	}
	args := strings.Split(strings.TrimSpace(string(argv)), "\n")

	// Bound by bare name, against the working directory the launcher
	// cd'd into. An absolute address would carry the whole scratch path
	// into sun_path, which is capped at ~100 bytes and which a glidein's
	// sandbox exceeds on its own.
	if !containsPair(args, "--socket", SocketName) {
		t.Errorf("args %q do not bind --socket by bare name (%q)", args, SocketName)
	}
	wantSock := filepath.Join(scratch, SocketName)
	// Authentication off is only correct because the socket's
	// permissions are the authorization; if one goes the other must.
	if !contains(args, "--auth") || !contains(args, "none") {
		t.Errorf("args %q do not disable the server's own auth", args)
	}

	// umask 077 must be in force when the socket is created, or any
	// local user on the execute node can open it -- which is the whole
	// reason this is a socket and not a port.
	info, serr := os.Stat(wantSock)
	if serr != nil {
		t.Fatalf("socket was not created: %v", serr)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("socket mode is %04o; group and other must have no access", perm)
	}
}

func TestLaunchScriptWorksInADeepSandbox(t *testing.T) {
	// The glidein case, and the one the previous version of this
	// launcher refused outright. sun_path is capped at ~100 bytes for
	// bind() as much as for connect(), and an EP running inside a SLURM
	// job nests its execute/dir_N under the host batch system's -- so
	// the scratch path can exceed the limit before anything of ours is
	// added. Refusing there would refuse on exactly the pools this is
	// for. The launcher binds by bare name and publishes an address
	// short enough to reach the socket by.
	base := shortScratch(t)
	deep := filepath.Join(base, strings.Repeat("glide_dir/", 12), "execute", "dir_9")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Skipf("cannot create a deep path here: %v", err)
	}
	if len(filepath.Join(deep, SocketName)) <= MaxSocketPath {
		t.Fatalf("the test's own scratch path is only %d bytes; it is not exercising the limit",
			len(filepath.Join(deep, SocketName)))
	}

	argvFile := filepath.Join(t.TempDir(), "argv")
	bin := fakeServer(t, argvFile)

	out, err := runScript(t, ScriptArgs{}, deep, bin)
	if err != nil {
		t.Fatalf("the launcher refused a deep sandbox, which is the normal glidein shape: %v\n%s", err, out)
	}

	published, rerr := os.ReadFile(filepath.Join(deep, SocketName+".path")) //nolint:gosec // G304: a path this test just created
	if rerr != nil {
		t.Fatalf("the launcher published no address for its socket: %v\n%s", rerr, out)
	}
	addr := strings.TrimSpace(string(published))
	if !strings.HasPrefix(addr, "/") {
		t.Errorf("published address %q is relative; sshd resolves it against its own cwd", addr)
	}
	if len(addr) > MaxSocketPath {
		t.Errorf("published address is %d bytes (%q), over the ~%d a Unix socket allows",
			len(addr), addr, MaxSocketPath)
	}

	// The socket itself is bound in the sandbox, and its mode is what
	// makes running the server with authentication disabled safe.
	//nolint:gosec // G703: a path this test built from its own temp dir
	st, serr := os.Stat(filepath.Join(deep, SocketName))
	if serr != nil {
		t.Fatalf("no socket was bound in the sandbox: %v", serr)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("socket mode is %04o; group and other must have no access", perm)
	}

	// Whether the published address resolves is deliberately NOT
	// asserted here, and the first version of this test got that wrong.
	// On Linux the address is /proc/<pid>/cwd/..., which is valid only
	// while that process lives -- and the stand-in server has exited by
	// now, so it resolves on macOS (a symlink) and not on Linux. What
	// can be checked without a live process is the shape, and that the
	// mechanism is the one meant for this platform. Reachability is the
	// integration test's job, where the server is still running.
	if strings.HasPrefix(addr, "/proc/") {
		if !procAddrRE.MatchString(addr) {
			t.Errorf("published address %q is not /proc/<pid>/cwd/%s", addr, SocketName)
		}
	} else {
		//nolint:gosec // G703: the address the launcher just published for this test
		if _, lerr := os.Stat(addr); lerr != nil {
			t.Errorf("published address %q does not resolve: %v", addr, lerr)
		}
	}
}

// procAddrRE matches the address the launcher publishes on Linux, where
// a kernel symlink keeps it short however deep the sandbox is.
var procAddrRE = regexp.MustCompile(`^/proc/[0-9]+/cwd/` + regexp.QuoteMeta(SocketName) + `$`)

func TestLaunchScriptRefusesAMissingServer(t *testing.T) {
	scratch := shortScratch(t)
	empty := t.TempDir() // nothing named code-server on PATH

	out, err := runScript(t, ScriptArgs{ServerCommand: "definitely-not-installed"}, scratch, empty)
	if err == nil {
		t.Fatalf("launcher started without the server present:\n%s", out)
	}
	if !strings.Contains(out, "is not installed") {
		t.Errorf("output does not say the server is missing:\n%s", out)
	}
}

// TestLaunchScriptQuotesTheWorkdir: the workdir reaches the script
// from a caller, and the script is the job's own executable, so an
// unquoted one is command injection into the job.
//
// The payload is a command substitution, deliberately. Two more
// obvious ones do not work and would make this test pass whatever the
// code did: a payload carrying its own quotes (\'; touch x; echo \')
// is turned into a literal by the surrounding quotes it is trying to
// escape, and a trailing \'; touch x\' never runs because exec has
// already replaced the shell. $(...) is expanded before exec, so it
// fires if and only if the word is unquoted.
func TestLaunchScriptQuotesTheWorkdir(t *testing.T) {
	scratch := shortScratch(t)
	argvFile := filepath.Join(t.TempDir(), "argv")
	bin := fakeServer(t, argvFile)
	canary := filepath.Join(shortScratch(t), "pwned")

	out, err := runScript(t, ScriptArgs{
		Workdir: "/work$(touch " + canary + ")",
	}, scratch, bin)
	if err != nil {
		t.Fatalf("launcher failed: %v\n%s", err, out)
	}
	if _, serr := os.Stat(canary); serr == nil {
		t.Fatal("a workdir containing a command substitution ran it")
	}
}

func TestBatchNameRoundTrip(t *testing.T) {
	id := "abc123"
	got, ok := SessionIDFromBatchName(BatchName(id))
	if !ok || got != id {
		t.Errorf("round trip gave (%q, %v), want (%q, true)", got, ok, id)
	}
	for _, bad := range []string{"", "other-job", BatchPrefix} {
		if _, ok := SessionIDFromBatchName(bad); ok {
			t.Errorf("SessionIDFromBatchName(%q) claimed a session", bad)
		}
	}
}

func TestPeriodicRemoveExpr(t *testing.T) {
	if got := PeriodicRemoveExpr(0); got != "" {
		t.Errorf("zero lifetime gave %q, want no expression", got)
	}
	got := PeriodicRemoveExpr(2 * time.Hour)
	if !strings.Contains(got, "7200") || !strings.HasPrefix(got, "periodic_remove") {
		t.Errorf("PeriodicRemoveExpr(2h) = %q", got)
	}
}

func TestContainerImageRef(t *testing.T) {
	for in, want := range map[string]string{
		"codercom/code-server:latest": "docker://codercom/code-server:latest",
		"docker://already":            "docker://already",
		"/images/thing.sif":           "/images/thing.sif",
		"thing.sif":                   "thing.sif",
		"":                            "",
	} {
		if got := containerImageRef(in); got != want {
			t.Errorf("containerImageRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildSubmitFile(t *testing.T) {
	out, err := BuildSubmitFile(SubmitArgs{
		SessionID:         "s1",
		Universe:          "container",
		Image:             "codercom/code-server:latest",
		Cpus:              2,
		MemoryMB:          4096,
		MaxLifetime:       time.Hour,
		CallerSubmitLines: "+WantGPU = true",
		ExtraSubmitLines:  "accounting_group = interactive",
	})
	if err != nil {
		t.Fatalf("BuildSubmitFile: %v", err)
	}
	for _, want := range []string{
		"universe = container",
		"container_image = docker://codercom/code-server:latest",
		"executable = " + ExecutableName,
		"request_cpus = 2",
		"request_memory = 4096",
		"batch_name = " + BatchName("s1"),
		"periodic_remove",
		"queue",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("submit file is missing %q:\n%s", want, out)
		}
	}
	// Operator policy last, so it overrides the caller's.
	if strings.Index(out, "accounting_group") < strings.Index(out, "+WantGPU") {
		t.Error("operator submit lines must come after the caller's so they win")
	}
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func containsPair(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

// TestBuildSubmitFileDefaultsToContainer: the server is a ~220 MB
// download that has to be on the execute node, so it comes from an
// image the node can cache. Vanilla is the exception, not the default.
func TestBuildSubmitFileDefaultsToContainer(t *testing.T) {
	out, err := BuildSubmitFile(SubmitArgs{SessionID: "s1", Image: "example/code-server:1"})
	if err != nil {
		t.Fatalf("BuildSubmitFile: %v", err)
	}
	if !strings.Contains(out, "universe = container") {
		t.Errorf("an unspecified universe did not default to container:\n%s", out)
	}
}

// TestBuildSubmitFileRefusesContainerWithNoImage: caught here rather
// than at the schedd, which answers a missing container_image with
// something far less specific.
func TestBuildSubmitFileRefusesContainerWithNoImage(t *testing.T) {
	if _, err := BuildSubmitFile(SubmitArgs{SessionID: "s1"}); !errors.Is(err, ErrNoImage) {
		t.Errorf("err = %v, want ErrNoImage", err)
	}
	// Vanilla needs no image: the launcher's command -v check reports
	// a server that is not installed.
	if _, err := BuildSubmitFile(SubmitArgs{SessionID: "s1", Universe: "vanilla"}); err != nil {
		t.Errorf("vanilla universe rejected without an image: %v", err)
	}
}

// TestLaunchScriptKeepsStateOutOfAnUnusableHome: left to itself the
// server writes under $HOME, which in a container is often unwritable
// -- and when it is writable it may be a real shared home, where one
// session's extensions outlive it and reach the next.
func TestLaunchScriptKeepsStateOutOfAnUnusableHome(t *testing.T) {
	scratch := shortScratch(t)
	argvFile := filepath.Join(t.TempDir(), "argv")
	bin := fakeServer(t, argvFile)

	// HOME pointing at something that does not exist, as a container
	// without a mounted home gives.
	out, err := runScriptEnv(t, ScriptArgs{}, scratch, bin, "HOME=/nonexistent-home")
	if err != nil {
		t.Fatalf("launcher failed: %v\n%s", err, out)
	}
	argv, rerr := os.ReadFile(argvFile) //nolint:gosec // G304: a path this test just created
	if rerr != nil {
		t.Fatalf("the launcher never reached the server: %v\n%s", rerr, out)
	}
	args := strings.Split(strings.TrimSpace(string(argv)), "\n")

	for _, flag := range []string{"--user-data-dir", "--extensions-dir", "--config"} {
		v, ok := valueFor(args, flag)
		if !ok {
			t.Errorf("args %q do not set %s", args, flag)
			continue
		}
		if !strings.HasPrefix(v, scratch) {
			t.Errorf("%s = %q, want it under the scratch directory %q", flag, v, scratch)
		}
	}
}

// TestLaunchScriptUsesAUsableHome is the other half: a session with a
// home directory mounted is exactly where a user wants their
// extensions to persist.
func TestLaunchScriptUsesAUsableHome(t *testing.T) {
	scratch := shortScratch(t)
	home := shortScratch(t)
	argvFile := filepath.Join(t.TempDir(), "argv")
	bin := fakeServer(t, argvFile)

	out, err := runScriptEnv(t, ScriptArgs{}, scratch, bin, "HOME="+home)
	if err != nil {
		t.Fatalf("launcher failed: %v\n%s", err, out)
	}
	argv, rerr := os.ReadFile(argvFile) //nolint:gosec // G304: a path this test just created
	if rerr != nil {
		t.Fatalf("the launcher never reached the server: %v\n%s", rerr, out)
	}
	args := strings.Split(strings.TrimSpace(string(argv)), "\n")

	v, ok := valueFor(args, "--user-data-dir")
	if !ok {
		t.Fatalf("args %q do not set --user-data-dir", args)
	}
	if !strings.HasPrefix(v, home) {
		t.Errorf("--user-data-dir = %q, want it under the usable home %q", v, home)
	}
}

func valueFor(args []string, flag string) (string, bool) {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1], true
		}
	}
	return "", false
}

// TestRecommendedImageIsPinned: `latest` makes a session whose editor
// can change under it between one day and the next, which is a support
// problem nobody can reproduce.
func TestRecommendedImageIsPinned(t *testing.T) {
	if strings.HasSuffix(RecommendedImage, ":latest") || !strings.Contains(RecommendedImage, ":") {
		t.Errorf("RecommendedImage = %q; it must name a version, not a moving tag", RecommendedImage)
	}
	// It goes into container_image unchanged, so it must already carry
	// a scheme -- containerImageRef only rescues a bare repo:tag.
	if got := containerImageRef(RecommendedImage); got != RecommendedImage {
		t.Errorf("containerImageRef rewrote RecommendedImage to %q", got)
	}
}
