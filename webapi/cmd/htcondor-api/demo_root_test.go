package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// lookupOf resolves the named accounts and fails every other name, so a
// test can say which accounts a machine has without having any.
func lookupOf(accounts map[string]user.User) accountLookup {
	return func(name string) (*user.User, error) {
		if u, ok := accounts[name]; ok {
			return &u, nil
		}
		return nil, user.UnknownUserError(name)
	}
}

func bothDemoAccounts() map[string]user.User {
	return map[string]user.User{
		demoCondorAccount: {Uid: "64", Gid: "64", Username: demoCondorAccount},
		demoGenericOSUser: {Uid: "99", Gid: "99", Username: demoGenericOSUser},
	}
}

// Each account demo mode needs as root is named when it is missing, and the
// message says to run as an ordinary user -- the remedy, since the whole
// problem is only there for root.
func TestCheckDemoRootAccountsNamesTheMissingOne(t *testing.T) {
	for _, missing := range []string{demoCondorAccount, demoGenericOSUser} {
		accounts := bothDemoAccounts()
		delete(accounts, missing)
		err := checkDemoRootAccounts(lookupOf(accounts))
		if err == nil {
			t.Fatalf("no error with %q missing", missing)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("the error for a missing %q does not name it: %v", missing, err)
		}
		if !strings.Contains(err.Error(), "ordinary user") {
			t.Errorf("the error for a missing %q does not say what to do instead: %v", missing, err)
		}
	}
	if err := checkDemoRootAccounts(lookupOf(bothDemoAccounts())); err != nil {
		t.Errorf("both accounts present: %v", err)
	}
}

// Off root the tree is left exactly as it was: same owner, same modes, and
// no account lookup at all. This is the path every ordinary demo takes.
func TestPrepareDemoTreeForRootLeavesNonRootAlone(t *testing.T) {
	tempDir := t.TempDir()
	logDir, spoolDir, executeDir := demoTreeDirs(tempDir)
	for _, d := range []string{logDir, spoolDir, executeDir} {
		if err := os.MkdirAll(d, 0750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(tempDir, 0700); err != nil { //nolint:gosec // the test's own directory
		t.Fatal(err)
	}

	lookup := func(string) (*user.User, error) {
		t.Error("an account was looked up off root")
		return nil, fmt.Errorf("should not be called")
	}
	if err := prepareDemoTreeForRoot(1000, tempDir, logDir, spoolDir, executeDir, lookup, nil); err != nil {
		t.Fatalf("non-root: %v", err)
	}

	info, err := os.Stat(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Errorf("the temp directory is now %o; a non-root demo should keep 0700", got)
	}
}

// As root a missing account stops the demo before condor_master starts --
// the point of the check, since HTCondor's own failure names a log file and
// not the account that could not open it.
func TestPrepareDemoTreeForRootRefusesWithoutTheAccounts(t *testing.T) {
	tempDir := t.TempDir()
	logDir, spoolDir, executeDir := demoTreeDirs(tempDir)
	for _, d := range []string{logDir, spoolDir, executeDir} {
		if err := os.MkdirAll(d, 0750); err != nil {
			t.Fatal(err)
		}
	}
	err := prepareDemoTreeForRoot(0, tempDir, logDir, spoolDir, executeDir, lookupOf(map[string]user.User{}), nil)
	if err == nil {
		t.Fatal("root with no condor account was allowed to continue")
	}
	if !strings.Contains(err.Error(), demoCondorAccount) {
		t.Errorf("error does not name the condor account: %v", err)
	}
}

// The generic job account is checked too, not just condor. With condor
// present and nobody missing, the lookup for the chown succeeds, so
// nothing downstream would object: only the up-front check catches it, and
// only the account's name in the message proves the check ran.
func TestPrepareDemoTreeForRootChecksTheJobAccountToo(t *testing.T) {
	tempDir := t.TempDir()
	logDir, spoolDir, executeDir := demoTreeDirs(tempDir)
	for _, d := range []string{logDir, spoolDir, executeDir} {
		if err := os.MkdirAll(d, 0750); err != nil {
			t.Fatal(err)
		}
	}
	accounts := bothDemoAccounts()
	delete(accounts, demoGenericOSUser)

	err := prepareDemoTreeForRoot(0, tempDir, logDir, spoolDir, executeDir, lookupOf(accounts), nil)
	if err == nil {
		t.Fatal("root with no job account was allowed to continue")
	}
	if !strings.Contains(err.Error(), demoGenericOSUser) {
		t.Errorf("the failure does not name the missing job account, so the check did not run: %v", err)
	}
}

// A non-numeric uid is reported rather than silently chowning to 0, which
// is what strconv.Atoi's zero value would otherwise mean: giving the tree
// to root is exactly the state that does not work.
func TestCondorAccountIDsRejectsANonNumericUID(t *testing.T) {
	accounts := bothDemoAccounts()
	accounts[demoCondorAccount] = user.User{Uid: "not-a-number", Gid: "64"}
	if _, _, err := condorAccountIDs(lookupOf(accounts)); err == nil {
		t.Fatal("a non-numeric uid was accepted")
	}
}

// The generic-account setting is in the config only when running as root,
// and names the account jobs actually run as.
func TestDemoGenericOSUsersConfig(t *testing.T) {
	if got := demoGenericOSUsersConfig(1000); got != "" {
		t.Errorf("a non-root demo config carries %q", got)
	}
	got := demoGenericOSUsersConfig(0)
	if !strings.Contains(got, "AP_GENERIC_OS_USERS = "+demoGenericOSUser) {
		t.Errorf("the root demo config does not set the generic account: %q", got)
	}
}

// The mini config a root demo writes carries the setting, and the one an
// ordinary demo writes does not. Guards the wiring, not just the helper:
// the helper returning the right string is no use if nothing uses it.
func TestWriteMiniCondorConfigCarriesTheGenericAccountOnlyAsRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "condor_config")
	if err := writeMiniCondorConfig(path, t.TempDir(), "/usr", nil); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	// The test process is not root, so this is the ordinary demo's config.
	if os.Geteuid() != 0 && strings.Contains(string(body), "AP_GENERIC_OS_USERS") {
		t.Error("a non-root demo config sets AP_GENERIC_OS_USERS")
	}
	if os.Geteuid() == 0 && !strings.Contains(string(body), "AP_GENERIC_OS_USERS") {
		t.Error("a root demo config does not set AP_GENERIC_OS_USERS")
	}
}
