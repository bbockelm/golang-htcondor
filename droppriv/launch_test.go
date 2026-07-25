package droppriv

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

// runIDU starts `id -u` as userName via StartAsUser and returns the child's printed uid.
func runIDU(t *testing.T, userName string) (string, error) {
	t.Helper()
	cmd := exec.Command("id", "-u")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := StartAsUser(userName, cmd); err != nil {
		return "", err
	}
	if err := cmd.Wait(); err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(out.Bytes())), nil
}

func TestStartAsUserEmptyRunsAsSelf(t *testing.T) {
	uid, err := runIDU(t, "")
	if err != nil {
		t.Fatalf("StartAsUser(\"\"): %v", err)
	}
	if uid != strconv.Itoa(os.Getuid()) {
		t.Errorf("child uid = %s, want self %d", uid, os.Getuid())
	}
}

func TestStartAsUserRejectsPrivilegedNames(t *testing.T) {
	if err := StartAsUser("root", exec.Command("true")); err == nil {
		t.Error("StartAsUser(\"root\") should be rejected")
	}
	if err := StartAsUser("condor", exec.Command("true")); err == nil {
		t.Error("StartAsUser(\"condor\") should be rejected")
	}
}

// TestStartAsUserUnprivilegedFallsBackToSelf: when the process can't regain root, a drop request
// is honored best-effort by running the child as the current user (Start still succeeds).
func TestStartAsUserUnprivilegedFallsBackToSelf(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("covered by the privileged test when running as root")
	}
	uid, err := runIDU(t, "nobody")
	if err != nil {
		t.Skipf("could not run child as nobody (user may be absent): %v", err)
	}
	if uid != strconv.Itoa(os.Getuid()) {
		t.Errorf("unprivileged fallback ran child as uid %s, want self %d", uid, os.Getuid())
	}
}
