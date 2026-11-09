//go:build integration

package reservation_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver"
	"github.com/bbockelm/golang-htcondor/webapi/reservation"
)

// Stamping edits other people's jobs. It does that as the owner of each
// job rather than with superuser rights over the whole queue, which
// rests on two claims this file tests against a real schedd: a token
// naming the owner is accepted for that owner's jobs, and a token
// naming somebody else is not.
//
// The second claim is what makes the first mean anything. These tests
// run as the user who owns the jobs, so a connection that quietly
// authenticated by some other means -- FS, as the local account --
// would pass the first test while proving nothing at all.

// ownerStampConfig keeps the queue's superusers away from the account
// the test runs as, so nothing here can succeed by being privileged.
//
// QUEUE_ALL_USERS_TRUSTED is the one that matters, and the harness
// turns it on. With it on, the schedd lets any authenticated client act
// as any owner: both tests below pass, the second one vacuously, and
// the design claim goes untested. Turning it off is what makes the
// schedd check ownership at all.
const ownerStampConfig = "NUM_CPUS = 2\nMEMORY = 1024\n" +
	"QUEUE_ALL_USERS_TRUSTED = False\n" +
	"QUEUE_SUPER_USERS = nobody\nQUEUE_SUPER_USER_MAY_IMPERSONATE = nobody\n" +
	"SCHEDD_INTERVAL = 3\n"

// jobUser is the identity the schedd records for a job, which is the
// name a token has to carry to be allowed to edit it.
//
// Read off the ad rather than built from the local account and the
// trust domain, because those give the wrong answer: User is qualified
// with UID_DOMAIN, the token's issuer is TRUST_DOMAIN, and a pool where
// the two differ -- the harness is one -- refuses the write. Reading it
// is what the stamping writer does for the same reason.
func jobUser(t *testing.T, h *htcondor.CondorTestHarness, cluster int) string {
	t.Helper()
	//nolint:gosec,noctx // G204: fixed command in a test
	cmd := exec.Command("condor_q", strconv.Itoa(cluster), "-af", "User")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("condor_q -af User: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if v := strings.TrimSpace(line); v != "" && v != "undefined" {
			return v
		}
	}
	t.Fatalf("cluster %d has no User attribute", cluster)
	return ""
}

// stampAs opens a queue connection authenticated as subject and sets
// the bucket on one cluster ad.
func stampAs(t *testing.T, h *htcondor.CondorTestHarness, subject string, cluster int, bucket int64) error {
	t.Helper()
	now := time.Now()
	token, err := security.GenerateJWT(
		filepath.Dir(h.GetSigningKeyPath()), filepath.Base(h.GetSigningKeyPath()),
		subject, h.GetTrustDomain(), now.Unix(), now.Add(5*time.Minute).Unix(), nil)
	if err != nil {
		t.Fatalf("minting a token for %s: %v", subject, err)
	}
	// The same builder the stamping writer uses, which strips FS so
	// the schedd cannot authenticate us as the local account instead
	// of the token's subject.
	secConfig, err := httpserver.ConfigureSecurityForToken(token)
	if err != nil {
		t.Fatalf("configuring security: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx = htcondor.WithSecurityConfig(ctx, secConfig)

	conn, err := htcondor.NewQmgmtConnection(ctx, scheddAddress(t, h))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetEffectiveOwner(ctx, subject); err != nil {
		return err
	}
	if err := conn.SetAttribute(ctx, cluster, -1, reservation.AttrBucket,
		strconv.FormatInt(bucket, 10), 0); err != nil {
		_ = conn.AbortTransaction(ctx)
		return err
	}
	return conn.CommitTransaction(ctx)
}

func readBucket(t *testing.T, h *htcondor.CondorTestHarness, cluster int) string {
	t.Helper()
	//nolint:gosec,noctx // G204: fixed command in a test
	cmd := exec.Command("condor_q", strconv.Itoa(cluster), "-af", reservation.AttrBucket)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("condor_q: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			return v
		}
	}
	return ""
}

// TestAJobsOwnerMayStampItWithNoSuperuserRights is the claim the design
// rests on: editing a job as the person who submitted it asks the
// schedd for no privilege over anyone else's queue.
func TestAJobsOwnerMayStampItWithNoSuperuserRights(t *testing.T) {
	h, _ := harness(t, ownerStampConfig)
	cluster := submitCluster(t, h, 2)
	owner := jobUser(t, h, cluster)

	if err := stampAs(t, h, owner, cluster, 1800); err != nil {
		t.Fatalf("stamping cluster %d as its owner %s: %v", cluster, owner, err)
	}
	if got := readBucket(t, h, cluster); got != "1800" {
		t.Fatalf("%s on cluster %d reads %q, want 1800", reservation.AttrBucket, cluster, got)
	}
}

// TestAStrangerMayNotStampSomebodyElsesJob is the half that makes the
// test above mean something. If the connection were authenticating as
// the local account by some other means, this would succeed too.
func TestAStrangerMayNotStampSomebodyElsesJob(t *testing.T) {
	h, _ := harness(t, ownerStampConfig)
	cluster := submitCluster(t, h, 1)

	// Same domain as the real owner, so the only thing that differs is
	// who the token says we are.
	owner := jobUser(t, h, cluster)
	stranger := "not-the-owner@" + owner[strings.IndexByte(owner, '@')+1:]
	err := stampAs(t, h, stranger, cluster, 3600)
	if err == nil {
		t.Fatalf("the schedd let %s stamp a job it does not own", stranger)
	}
	t.Logf("refused, as it should be: %v", err)
	if got := readBucket(t, h, cluster); got == "3600" {
		t.Fatalf("%s was written anyway", reservation.AttrBucket)
	}
}
