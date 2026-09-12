//go:build integration

package htcondor

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// An operator serving the web UI on 443 needs the daemon to bind a
// privileged port after condor_master has dropped it to the condor account.
// Ports below 1024 need root, and the drop happens long before the daemon
// knows which port it was configured with.
//
// This runs the real binary under a real condor_master, as root, so the
// drop actually happens. Running it unprivileged would prove nothing: the
// bind would be attempted by whoever ran the test, and the privilege
// question would never arise.
func TestHTCondorAPIBindsPrivilegedPortUnderMaster(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping condor_master integration test in -short mode")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root: without it condor_master cannot drop the daemon, which is the case under test")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH")
	}

	// Docker sets net.ipv4.ip_unprivileged_port_start=0, which lets any
	// user bind any port. Under that setting the daemon binds 443 without
	// needing privilege at all, and this test would pass with the
	// elevation removed -- proving only that the port is reachable, not
	// that a dropped daemon can take it. Put the threshold back.
	restorePortFloor := requirePrivilegedPorts(t)
	defer restorePortFloor()

	workDir, err := os.MkdirTemp("/tmp", "htcapp") //nolint:usetesting // shared-port UDS paths must stay short
	if err != nil {
		t.Fatalf("mkdir workDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workDir) })

	bin := filepath.Join(workDir, "htcondor-api")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "./cmd/htcondor-api")
	// The daemon lives in the webapi module, not this one.
	build.Dir = "webapi"
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build htcondor-api: %v", err)
	}

	certPath, keyPath, caPool := writeSelfSignedCert(t, workDir)
	dbPath := filepath.Join(workDir, "htcondor-api.db")
	daemonLog := filepath.Join(workDir, "HTTPApiLog")

	// 443 is the case operators actually ask about. No shared-port
	// forwarding id and no -sock: the daemon must bind the port itself,
	// which is the path that needs the privilege.
	const privilegedPort = 443
	// The master keeps its own socket for CEDAR, and the daemon binds 443
	// itself for browsers. The master cannot be told to hand down 443, so
	// the daemon has to bind it after being dropped to the condor
	// account -- which is the privileged step under test.
	sockDir := filepath.Join(workDir, "sock")
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		t.Fatalf("mkdir sockDir: %v", err)
	}
	const endpoint = "http_api"
	extraConfig := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, SHARED_PORT, SCHEDD, HTTP_API
DC_DAEMON_LIST = +HTTP_API
DAEMON_SOCKET_DIR = %[7]s
SHARED_PORT_HTTP_FORWARDING_ID = %[8]s
SHARED_PORT_PORT = 0
SHARED_PORT_LOG = $(LOG)/SharedPortLog
SHARED_PORT_DEBUG = D_FULLDEBUG D_COMMAND
HTTP_API = %[1]s
HTTP_API_ARGS = -sock %[8]s
HTTP_API_LOG = %[2]s
HTTP_API_DEBUG = D_FULLDEBUG D_COMMAND
HTTP_API_LISTEN_ADDR = 127.0.0.1:%[6]d
HTTP_API_TLS_CERT = %[3]s
HTTP_API_TLS_KEY = %[4]s
HTTP_API_DB_PATH = %[5]s
MASTER_DEBUG = D_FULLDEBUG D_COMMAND
`, bin, daemonLog, certPath, keyPath, dbPath, privilegedPort, sockDir, endpoint)

	// The daemon drops to the condor account and then has to write its log
	// and open its database, both of which live in this root-owned temp
	// dir. The harness does the same for its own tree; this one is ours.
	chownTreeToCondor(t, workDir)

	h := SetupCondorHarnessWithConfig(t, extraConfig)
	defer h.Shutdown()

	// The daemon says it bound the port, and says which euid it was as.
	if !waitForLog(t, daemonLog, "Also listening on", 60*time.Second) {
		dumpDaemonLog(t, daemonLog)
		if b, err := os.ReadFile(filepath.Join(h.GetLogDir(), "MasterLog")); err == nil {
			t.Logf("MasterLog:\n%s", string(b))
		}
		t.Fatal("the daemon never bound the configured port alongside the master socket")
	}

	// The bind must have happened while dropped. If the daemon were simply
	// running as root the bind would succeed too, and the test would pass
	// without exercising anything -- so read the euid it logged.
	euid := daemonEUID(t)
	if euid == 0 {
		dumpDaemonLog(t, daemonLog)
		t.Fatalf("the daemon bound %d while still root (euid=0); the privilege drop did not happen, "+
			"so this says nothing about binding after dropping", privilegedPort)
	}
	t.Logf("bound %d while running as euid=%d", privilegedPort, euid)

	// And it actually serves there.
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}},
	}
	url := fmt.Sprintf("https://127.0.0.1:%d/healthz", privilegedPort)
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	dumpDaemonLog(t, daemonLog)
	t.Fatalf("the daemon bound %d but does not serve there: %v", privilegedPort, lastErr)
}

// daemonEUID returns the effective uid the htcondor-api process is running
// as, so the test can tell "served on 443 because the daemon is root" from
// "served on 443 while dropped", which is the only interesting case.
func daemonEUID(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("ps", "-eo", "euid,comm").Output()
	if err != nil {
		t.Fatalf("ps: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.Contains(f[1], "htcondor-api") {
			var euid int
			if _, err := fmt.Sscanf(f[0], "%d", &euid); err == nil {
				return euid
			}
		}
	}
	t.Fatal("the htcondor-api process is not running")
	return -1
}

// chownTreeToCondor hands a directory to the condor account so a dropped
// daemon can use it. A no-op when not root or when there is no condor user,
// which is also when no drop happens.
func chownTreeToCondor(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() != 0 {
		return
	}
	u, err := user.Lookup("condor")
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	}); err != nil {
		t.Logf("chowning %s to condor failed (continuing): %v", dir, err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Logf("chmod %s: %v", dir, err)
	}
}

// requirePrivilegedPorts makes ports below 1024 actually privileged for the
// duration of the test, and returns a function restoring the previous value.
//
// It skips the test when the setting cannot be changed: without it the bind
// under test is not privileged, so a pass would mean nothing.
func requirePrivilegedPorts(t *testing.T) func() {
	t.Helper()
	const knob = "/proc/sys/net/ipv4/ip_unprivileged_port_start"
	prev, err := os.ReadFile(knob)
	if err != nil {
		t.Skipf("cannot read %s, so ports below 1024 cannot be made privileged: %v", knob, err)
	}
	if err := os.WriteFile(knob, []byte("1024"), 0o644); err != nil {
		t.Skipf("cannot set %s=1024, so the bind under test would not be privileged: %v", knob, err)
	}
	return func() {
		if err := os.WriteFile(knob, prev, 0o644); err != nil {
			t.Logf("restoring %s to %q failed: %v", knob, strings.TrimSpace(string(prev)), err)
		}
	}
}
