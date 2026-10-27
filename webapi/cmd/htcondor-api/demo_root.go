package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Demo mode under root.
//
// A demo pool started by an ordinary user needs none of this: HTCondor
// cannot change uid unless it is root, so every daemon stays the invoking
// user, who owns the temp tree, and the schedd takes the submitter's word
// for who they are.
//
// Root changes all three of those, and each one breaks the demo somewhere
// different:
//
//   - The daemons open their logs as the condor account (dprintf.cpp sets
//     PRIV_CONDOR before the open), which cannot enter a 0700 root-owned
//     temp directory. condor_master dies with "Cannot open log file" before
//     it writes a line, which reads like a bad path and is not.
//   - The schedd resolves every submitter to a real OS account before it
//     will create a cluster, and the demo's identities -- admin, user,
//     newbie -- are IdP accounts that exist nowhere in /etc/passwd.
//   - The starter builds each job's scratch directory under EXECUTE as the
//     job's own user, so that path has to be traversable by someone other
//     than condor.
//
// So demo mode hands the tree to condor, runs jobs as one generic account,
// and makes the two directories a job walks through traversable. All of it
// is gated on being root: an ordinary user's demo is untouched.

const (
	// demoCondorAccount is the account HTCondor's daemons drop to when the
	// master is started by root. It comes from the condor packages.
	demoCondorAccount = "condor"

	// demoGenericOSUser is the OS account a root schedd runs the demo's
	// jobs as, via AP_GENERIC_OS_USERS. One account for every demo
	// identity: the demo is a single-user sandbox, and the alternative is
	// creating system accounts for admin and user, which is not something
	// a demo should do to the machine it runs on.
	demoGenericOSUser = "nobody"

	// demoTraversableMode is the mode of the directories a job's own user
	// has to walk through: the temp directory and EXECUTE under it.
	// Traverse but not list, so the demo tree stays closed to a passer-by
	// on a shared login node -- which is where this runs most often.
	demoTraversableMode os.FileMode = 0711
)

// accountLookup resolves an account by name. user.Lookup in the demo,
// something that returns what the test wants in a test.
type accountLookup func(string) (*user.User, error)

// demoRootAccount is an account demo mode needs when it runs as root, and
// why it needs it -- the "why" is what a person reads when it is missing.
type demoRootAccount struct {
	name string
	need string
}

var demoRootAccounts = []demoRootAccount{
	{demoCondorAccount, "HTCondor's daemons run as it and cannot write their logs without it"},
	{demoGenericOSUser, "a schedd started by root runs the demo's jobs as it"},
}

// checkDemoRootAccounts reports the first account demo mode needs and this
// machine does not have. Checked up front, before condor_master starts,
// because every one of these failures otherwise surfaces much later as an
// HTCondor error that names the symptom and not the cause.
func checkDemoRootAccounts(lookup accountLookup) error {
	for _, acct := range demoRootAccounts {
		if _, err := lookup(acct.name); err != nil {
			return fmt.Errorf("demo mode as root needs a %q account (%s), and this machine has none: "+
				"run htcondor-api -demo as an ordinary user instead, which needs no system accounts",
				acct.name, acct.need)
		}
	}
	return nil
}

// condorAccountIDs returns the condor account's uid and gid.
func condorAccountIDs(lookup accountLookup) (int, int, error) {
	u, err := lookup(demoCondorAccount)
	if err != nil {
		return 0, 0, fmt.Errorf("could not look up the %q account: %w", demoCondorAccount, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("the %q account has a non-numeric uid %q", demoCondorAccount, u.Uid)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("the %q account has a non-numeric gid %q", demoCondorAccount, u.Gid)
	}
	return uid, gid, nil
}

// prepareDemoTreeForRoot gives the demo tree to the condor account and
// opens the path a job walks. It does nothing unless euid is 0, so the
// ordinary non-root demo keeps the tree it always had.
//
// tempDir is the demo's directory; logDir, spoolDir and executeDir are the
// three under it HTCondor writes to.
func prepareDemoTreeForRoot(euid int, tempDir, logDir, spoolDir, executeDir string, lookup accountLookup, logger *logging.Logger) error {
	if euid != 0 {
		return nil
	}
	if err := checkDemoRootAccounts(lookup); err != nil {
		return err
	}
	uid, gid, err := condorAccountIDs(lookup)
	if err != nil {
		return err
	}
	for _, dir := range []string{tempDir, logDir, spoolDir, executeDir} {
		if err := os.Chown(dir, uid, gid); err != nil {
			return fmt.Errorf("failed to give %s to the %q account: %w", dir, demoCondorAccount, err)
		}
	}
	// Only the two a job's user has to walk through. The log and spool
	// directories stay closed: nothing but a daemon reads them.
	for _, dir := range []string{tempDir, executeDir} {
		if err := os.Chmod(dir, demoTraversableMode); err != nil {
			return fmt.Errorf("failed to make %s traversable: %w", dir, err)
		}
	}
	if logger != nil {
		logger.Info(logging.DestinationGeneral,
			"Running as root: the demo tree belongs to the condor account and every demo identity's jobs run as one generic account",
			"condor_account", demoCondorAccount, "job_account", demoGenericOSUser)
	}
	return nil
}

// demoGenericOSUsersConfig is the AP_GENERIC_OS_USERS setting for the mini
// pool, or "" when this demo is not running as root.
//
// Empty off root on purpose. A schedd that cannot change uid never checks a
// submitter against /etc/passwd, so the setting would buy nothing, and
// leaving it out keeps a non-root demo's config exactly what it has always
// been.
func demoGenericOSUsersConfig(euid int) string {
	if euid != 0 {
		return ""
	}
	return fmt.Sprintf(`
# Started by root, so the schedd insists every submitter resolve to a real
# OS account. The demo's identities (admin, user, newbie) are IdP accounts
# and exist in no passwd file, so every one of them runs its jobs as this
# single generic account instead. Demo jobs are therefore not isolated from
# one another; a demo pool in a temp directory is not where that matters.
AP_GENERIC_OS_USERS = %s
`, demoGenericOSUser)
}

// createDemoTree makes the three directories HTCondor writes to under the
// demo's temp directory and, when this process is root, hands them to the
// accounts that will actually use them (prepareDemoTreeForRoot).
func createDemoTree(tempDir string, logger *logging.Logger) error {
	logDir, spoolDir, executeDir := demoTreeDirs(tempDir)
	for name, dir := range map[string]string{"log": logDir, "spool": spoolDir, "execute": executeDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create %s directory: %w", name, err)
		}
	}
	return prepareDemoTreeForRoot(os.Geteuid(), tempDir, logDir, spoolDir, executeDir, user.Lookup, logger)
}

// demoTreeDirs names the three directories under the demo's temp directory
// that HTCondor writes to.
func demoTreeDirs(tempDir string) (logDir, spoolDir, executeDir string) {
	return filepath.Join(tempDir, "log"),
		filepath.Join(tempDir, "spool"),
		filepath.Join(tempDir, "execute")
}
