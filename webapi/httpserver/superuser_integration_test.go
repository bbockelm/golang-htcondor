//go:build integration

//nolint:errcheck,noctx,gosec,errorlint,govet // Integration test file with acceptable test patterns
package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSuperuserModeEndToEnd exercises superuser mode against a real schedd.
//
// Everything else about this feature is reasoned from the HTCondor source and
// unit-tested against fakes. The claims that only a live daemon can settle are:
//
//   - a minted token asserting a QUEUE_SUPER_USERS identity actually passes
//     UserCheck2 for somebody else's job;
//   - the schedd really does append "(by user <identity>)" to the reason we
//     send, so the job ad ends up naming both parties;
//   - the fallback identity (condor@UID_DOMAIN) is accepted as a superuser
//     just as the actor's own identity is;
//   - and, the negative that gives the rest meaning, that without the mode
//     armed the same request is refused.
//
// The pool is configured with QUEUE_SUPER_USERS = root, condor, superadmin, so
// one web admin (superadmin) is a queue superuser and another (plainadmin) is
// not. That is what lets a single pool cover both identity branches.
func TestSuperuserModeEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	const (
		trustDomain = "test.htcondor.org"
		jobOwner    = "jobowner"
		superAdmin  = "superadmin" // in QUEUE_SUPER_USERS
		plainAdmin  = "plainadmin" // NOT in QUEUE_SUPER_USERS
		suGroup     = "condor-webadmins"
	)

	// The user this pool runs as. PERSONAL_CONDOR_IS_SUPER_USER (default
	// true) already makes them a queue superuser, and submitting below
	// gives them a UserRec, so they are a usable fallback identity.
	me, err := user.Current()
	if err != nil {
		t.Fatalf("could not determine the current user: %v", err)
	}
	poolUser := me.Username

	tempDir, err := os.MkdirTemp("", "htcondor-superuser-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	// KEEP_TEST_DIR=1 preserves the pool's LOG directory. The interesting
	// evidence when this test fails is in SchedLog, and printHTCondorLogs
	// only tails it.
	defer func() {
		if os.Getenv("KEEP_TEST_DIR") != "" {
			t.Logf("KEEP_TEST_DIR set; leaving %s in place", tempDir)
			return
		}
		os.RemoveAll(tempDir)
	}()

	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	defer os.RemoveAll(socketDir)

	defer func() {
		if t.Failed() {
			printHTCondorLogs(tempDir, t)
		}
	}()

	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	// Append the two knobs this test turns on. UID_DOMAIN has to match the
	// domain the server qualifies identities with, or "superadmin@domain"
	// never matches the "superadmin" in QUEUE_SUPER_USERS.
	extra := fmt.Sprintf(`
# --- superuser-mode test additions ---
UID_DOMAIN = %s
QUEUE_SUPER_USERS = root, condor, %s
`, trustDomain, superAdmin)
	f, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Failed to open config for append: %v", err)
	}
	if _, err := f.WriteString(extra); err != nil {
		t.Fatalf("Failed to append config: %v", err)
	}
	f.Close()

	os.Setenv("CONDOR_CONFIG", configFile)
	defer os.Unsetenv("CONDOR_CONFIG")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Starting condor_master...")
	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	defer stopCondorMaster(condorMaster, t)

	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}
	scheddAddr, err := getScheddAddress(tempDir, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to get schedd address: %v", err)
	}
	t.Logf("Schedd at %s", scheddAddr)

	server, err := NewServer(Config{
		ListenAddr:     "127.0.0.1:0",
		ScheddName:     "local",
		ScheddAddr:     scheddAddr,
		SigningKeyPath: signingKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      trustDomain,
		// The admins are Web UI admins too, which is the realistic
		// deployment AND what makes the negative case below meaningful:
		// a non-admin session has its constraint owner-scoped to itself,
		// so it would fail to touch another user's job for a reason that
		// has nothing to do with superuser mode. With scoping out of the
		// way the only thing left standing between them and the job is
		// the schedd's own authorization, which is what we want to test.
		WebUIAdminGroup: suGroup,
		SuperuserGroup:  suGroup,
		// The pool here is a personal condor running as the test user, so
		// "condor@UID_DOMAIN" is not recognised as the condor identity --
		// real_owner_is_condor only matches the daemon's own OS user when
		// personal_condor is false. Point the fallback at the user the
		// pool actually runs as, which PERSONAL_CONDOR_IS_SUPER_USER has
		// already made a queue superuser. Without this the fallback path
		// could only be tested as root, i.e. nowhere: CI's integration
		// container runs as "vscode".
		SuperuserFallbackIdentity: poolUser,
		OAuth2DBPath:              filepath.Join(tempDir, "sessions.db"),
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	go func() { _ = server.Start() }()
	time.Sleep(500 * time.Millisecond)
	baseURL := "http://" + server.GetAddr()
	if err := waitForServer(baseURL, 10*time.Second); err != nil {
		t.Fatalf("Server failed to start: %v", err)
	}
	defer func() {
		sc, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		_ = server.Shutdown(sc)
	}()

	if !server.superuserModeAvailable() {
		t.Fatalf("superuser mode did not enable; the rest of this test would prove nothing")
	}
	// The policy polls at startup; give it a moment and confirm it actually
	// read the pool's set. Without this the identity choice below would be
	// the fallback for the boring reason that we asked too early.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if n, _, _ := server.superuserPolicy.Status(); n > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	count, fetchedAt, lastErr := server.superuserPolicy.Status()
	if count == 0 {
		t.Fatalf("never read QUEUE_SUPER_USERS from the schedd (err=%v)", lastErr)
	}
	t.Logf("queue superusers known: %d (as of %s)", count, fetchedAt.Format(time.RFC3339))

	// Sanity: the identity choice must differ for the two admins, or the
	// two halves of this test are the same test.
	if id, isSuper := server.superuserPolicy.ImpersonationIdentity(superAdmin); !isSuper {
		t.Fatalf("%s should be a queue superuser, got identity %q", superAdmin, id)
	}
	if id, isSuper := server.superuserPolicy.ImpersonationIdentity(plainAdmin); isSuper {
		t.Fatalf("%s should NOT be a queue superuser, got identity %q", plainAdmin, id)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	// A job that will sit idle: we want something stable to act on, not a
	// race against the starter.
	submitFile := `executable = /bin/sleep
arguments = 3600
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
requirements = (SuperuserTestNeverMatches =?= True)
queue`

	// Precondition. Everything below assumes the job really belongs to
	// jobOwner; if the server authenticated as somebody else the whole test
	// would pass or fail for reasons unrelated to superuser mode.
	//
	// This is not hypothetical: an earlier version of this test set
	// UserHeader, which makes allowFSFallback true for every request, and
	// the server then authenticated to the schedd over FS as the OS process
	// user. Jobs came out owned by whoever ran the test. Driving everything
	// through sessions keeps authentication TOKEN-only and the identities
	// honest.
	// Give the acting admin a UserRec by having them submit once.
	//
	// Not incidental setup: the schedd's UserCheck2 rejects a caller it
	// cannot map to a UserRec with "anonymous user not permitted", and it
	// does so BEFORE it ever consults superuser status. An admin who is in
	// QUEUE_SUPER_USERS but has never submitted therefore cannot act at all.
	// `condor_qusers -add` is the operator-facing way to create one; this
	// test uses a submission because it needs no extra privilege.
	superSID0 := newAdminSession(t, server, superAdmin, suGroup)
	_ = submitIdleJob(t, client, baseURL, superSID0, submitFile)
	t.Logf("gave %s a schedd UserRec by submitting once", superAdmin)

	ownerSID := newAdminSession(t, server, jobOwner, "no-groups")
	probeJob := submitIdleJob(t, client, baseURL, ownerSID, submitFile)
	if owner := jobOwnerOf(t, client, baseURL, ownerSID, probeJob); owner != jobOwner {
		t.Fatalf("submitted job %s is owned by %q, want %q -- the test's identity "+
			"plumbing is wrong and nothing below would mean anything", probeJob, owner, jobOwner)
	}
	t.Logf("precondition ok: %s is owned by %s", probeJob, jobOwner)

	// NOTE on what these subtests can and cannot show.
	//
	// superadmin is in QUEUE_SUPER_USERS, so their own minted token already
	// carries the power to touch anybody's job -- superuser mode adds the
	// audit trail and the reason strings for them, not the authorization.
	// plainadmin is not, so for them the mode is what grants the power at
	// all. The negative cases therefore have to use plainadmin, or they
	// would pass whether or not the feature works.
	//
	// Assertions are on the JOB's state rather than the HTTP status. The
	// schedd in use publishes an uninitialised result_total_6
	// (HTCONDOR-2926 added the counter without initialising it;
	// HTCONDOR-3665 fixed that in 2026-04), which makes the client compute a
	// negative total and report a successful action as a failure. Checking
	// whether the job is actually held is both immune to that and a stronger
	// claim than "the endpoint said OK".
	t.Run("without the mode armed a non-superuser admin cannot act", func(t *testing.T) {
		jobID := submitIdleJob(t, client, baseURL, ownerSID, submitFile)
		sid := newAdminSession(t, server, plainAdmin, suGroup)

		status, body := holdAsSession(t, client, baseURL, sid, jobID, "poking someone else's job")
		t.Logf("hold returned %d: %s", status, truncate(body, 200))
		if st := waitJobStatus(t, client, baseURL, ownerSID, jobID, 5, 3*time.Second); st == 5 {
			t.Errorf("job %s was held without superuser mode armed", jobID)
		}
	})

	t.Run("armed, a queue-superuser admin acts as themselves", func(t *testing.T) {
		jobID := submitIdleJob(t, client, baseURL, ownerSID, submitFile)
		sid := newAdminSession(t, server, superAdmin, suGroup)
		armSuperuser(t, client, baseURL, sid, true)

		status, body := holdAsSession(t, client, baseURL, sid, jobID, "ignored")
		t.Logf("hold returned %d: %s", status, truncate(body, 160))
		if st := waitJobStatus(t, client, baseURL, ownerSID, jobID, 5, 15*time.Second); st != 5 {
			t.Fatalf("job %s not held (JobStatus=%d)", jobID, st)
		}

		reason := holdReasonOf(t, client, baseURL, ownerSID, jobID)
		t.Logf("HoldReason: %s", reason)
		for _, want := range []string{superAdmin, jobOwner, "superuser"} {
			if !strings.Contains(reason, want) {
				t.Errorf("HoldReason does not mention %q: %s", want, reason)
			}
		}
		// Appended by the schedd itself. When the actor is a queue
		// superuser it names them, which makes the daemon an independent
		// witness to who acted.
		if !strings.Contains(reason, "by user "+superAdmin) {
			t.Errorf("schedd did not attribute the action to %s: %s", superAdmin, reason)
		}
	})

	t.Run("armed, a non-queue-superuser admin acts via condor", func(t *testing.T) {
		jobID := submitIdleJob(t, client, baseURL, ownerSID, submitFile)
		sid := newAdminSession(t, server, plainAdmin, suGroup)
		armSuperuser(t, client, baseURL, sid, true)

		status, body := holdAsSession(t, client, baseURL, sid, jobID, "ignored")
		t.Logf("hold returned %d: %s", status, truncate(body, 160))
		if st := waitJobStatus(t, client, baseURL, ownerSID, jobID, 5, 15*time.Second); st != 5 {
			t.Fatalf("job %s not held (JobStatus=%d) -- superuser mode did not grant the action", jobID, st)
		}

		reason := holdReasonOf(t, client, baseURL, ownerSID, jobID)
		t.Logf("HoldReason: %s", reason)
		// The human is in the text we sent, because the schedd can only
		// append the shared identity here. This is exactly the case where
		// the reason string is the only record in the job ad of who acted.
		if !strings.Contains(reason, plainAdmin) {
			t.Errorf("HoldReason does not name the acting admin: %s", reason)
		}
		// The schedd attributes the action to the fallback identity, not
		// to the human -- which is exactly why the human's name has to be
		// in the reason text we send.
		if !strings.Contains(reason, "by user "+poolUser) {
			t.Errorf("expected the schedd to attribute this to the fallback identity %q: %s",
				poolUser, reason)
		}
	})

	t.Run("armed, remove works too", func(t *testing.T) {
		jobID := submitIdleJob(t, client, baseURL, ownerSID, submitFile)
		sid := newAdminSession(t, server, plainAdmin, suGroup)
		armSuperuser(t, client, baseURL, sid, true)

		req, _ := http.NewRequest("DELETE", baseURL+"/api/v1/jobs/"+jobID, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("delete failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("delete returned %d: %s", resp.StatusCode, truncate(string(body), 160))

		// Removed jobs leave the queue, so "gone or status 3" is the
		// success condition.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			st := jobStatusOf(t, client, baseURL, ownerSID, jobID)
			if st == -1 || st == 3 {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Errorf("job %s still in the queue after a superuser remove (status=%d)",
			jobID, jobStatusOf(t, client, baseURL, ownerSID, jobID))
	})

	t.Run("disarming stops it again", func(t *testing.T) {
		jobID := submitIdleJob(t, client, baseURL, ownerSID, submitFile)
		sid := newAdminSession(t, server, plainAdmin, suGroup)
		armSuperuser(t, client, baseURL, sid, true)
		armSuperuser(t, client, baseURL, sid, false)

		status, body := holdAsSession(t, client, baseURL, sid, jobID, "should not work")
		t.Logf("hold returned %d: %s", status, truncate(body, 160))
		if st := waitJobStatus(t, client, baseURL, ownerSID, jobID, 5, 3*time.Second); st == 5 {
			t.Errorf("job %s was held after the mode was disarmed", jobID)
		}
	})
}

// newAdminSession creates a browser session for an admin in the given group.
func newAdminSession(t *testing.T, server *Server, user, group string) string {
	t.Helper()
	sid, _, err := server.sessionStore.Create(user, []string{group})
	if err != nil {
		t.Fatalf("failed to create session for %s: %v", user, err)
	}
	return sid
}

// armSuperuser toggles superuser mode for a session.
func armSuperuser(t *testing.T, client *http.Client, baseURL, sid string, on bool) {
	t.Helper()
	body, _ := json.Marshal(map[string]bool{"enabled": on})
	req, _ := http.NewRequest("POST", baseURL+"/api/v1/admin/superuser", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("arm(%v) failed: %v", on, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("arm(%v) returned %d: %s", on, resp.StatusCode, respBody)
	}
	t.Logf("superuser arm(%v): %s", on, strings.TrimSpace(string(respBody)))
}

// holdAsSession holds a job using a browser session (no X-Test-User header, so
// the session drives the identity).
func holdAsSession(t *testing.T, client *http.Client, baseURL, sid, jobID, reason string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"reason": reason})
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/jobs/%s/hold", baseURL, jobID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("hold request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody)
}

// holdReasonOf reads a job's HoldReason back out of the queue.
func holdReasonOf(t *testing.T, client *http.Client, baseURL, sid, jobID string) string {
	t.Helper()
	parts := strings.SplitN(jobID, ".", 2)
	constraint := fmt.Sprintf("ClusterId == %s && ProcId == %s", parts[0], parts[1])

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", fmt.Sprintf(
			"%s/api/v1/jobs?constraint=%s&projection=ClusterId,ProcId,JobStatus,HoldReason",
			baseURL, urlQueryEscape(constraint)), nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var parsed struct {
			Jobs []map[string]any `json:"jobs"`
		}
		if err := json.Unmarshal(body, &parsed); err == nil && len(parsed.Jobs) > 0 {
			if hr, ok := parsed.Jobs[0]["HoldReason"].(string); ok && hr != "" {
				return hr
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("HoldReason never appeared for %s", jobID)
	return ""
}

func urlQueryEscape(s string) string {
	return strings.NewReplacer(" ", "%20", "\"", "%22", "=", "%3D", "&", "%26").Replace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// jobStatusOf reads a job's JobStatus, or -1 if it cannot be found. Used to
// assert that a refused action genuinely left the job alone rather than
// trusting the HTTP status.
func jobStatusOf(t *testing.T, client *http.Client, baseURL, sid, jobID string) int {
	t.Helper()
	parts := strings.SplitN(jobID, ".", 2)
	constraint := fmt.Sprintf("ClusterId == %s && ProcId == %s", parts[0], parts[1])
	req, _ := http.NewRequest("GET", fmt.Sprintf(
		"%s/api/v1/jobs?constraint=%s&projection=ClusterId,ProcId,JobStatus",
		baseURL, urlQueryEscape(constraint)), nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("status query failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Jobs []map[string]any `json:"jobs"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Jobs) == 0 {
		return -1
	}
	if v, ok := parsed.Jobs[0]["JobStatus"].(float64); ok {
		return int(v)
	}
	return -1
}

// submitAsSession submits a job as the session's user. Sessions rather than
// the X-Test-User header on purpose: setting UserHeader turns on FS fallback
// for every request, and the server then authenticates to the schedd as the OS
// process user, so the job would not belong to whoever the test meant.
func submitAsSession(t *testing.T, client *http.Client, baseURL, sid, submitFile string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"submit_file": submitFile})
	req, _ := http.NewRequest("POST", baseURL+"/api/v1/jobs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("submit returned %d: %s", resp.StatusCode, respBody)
	}
	var parsed JobSubmitResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		t.Fatalf("could not parse submit response %s: %v", respBody, err)
	}
	if len(parsed.JobIDs) == 0 {
		t.Fatalf("submit returned no job ids: %s", respBody)
	}
	return parsed.JobIDs[0]
}

// jobOwnerOf reads a job's Owner attribute back out of the queue.
func jobOwnerOf(t *testing.T, client *http.Client, baseURL, sid, jobID string) string {
	t.Helper()
	parts := strings.SplitN(jobID, ".", 2)
	constraint := fmt.Sprintf("ClusterId == %s && ProcId == %s", parts[0], parts[1])
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", fmt.Sprintf(
			"%s/api/v1/jobs?constraint=%s&projection=ClusterId,ProcId,Owner,User",
			baseURL, urlQueryEscape(constraint)), nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("owner query failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var parsed struct {
			Jobs []map[string]any `json:"jobs"`
		}
		if err := json.Unmarshal(body, &parsed); err == nil && len(parsed.Jobs) > 0 {
			if o, ok := parsed.Jobs[0]["Owner"].(string); ok && o != "" {
				return o
			}
			if u, ok := parsed.Jobs[0]["User"].(string); ok && u != "" {
				return ownerFromActor(u)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("job %s never became visible", jobID)
	return ""
}

// waitJobStatus polls until a job reaches want, or the timeout expires, and
// returns the last status seen. Used in both directions: to confirm an action
// took effect, and to give a refused action a fair chance to (incorrectly)
// take effect before concluding it did not.
func waitJobStatus(t *testing.T, client *http.Client, baseURL, sid, jobID string, want int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := -1
	for time.Now().Before(deadline) {
		last = jobStatusOf(t, client, baseURL, sid, jobID)
		if last == want {
			return last
		}
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

// submitIdleJob submits a job and drives it to a stable idle state.
//
// The API's submit spools, which parks the job in HELD with
// "Spooling input data files" until the input upload completes. Acting on a
// job in that state tells you nothing about superuser mode -- an earlier
// version of this test read the spool hold and concluded the admin had held
// the job. Finish the spool, then wait for idle, so the only thing that can
// change the job's status afterwards is the thing under test.
//
// The job's requirements never match, so idle is where it stays.
func submitIdleJob(t *testing.T, client *http.Client, baseURL, sid, submitFile string) string {
	t.Helper()
	jobID := submitAsSession(t, client, baseURL, sid, submitFile)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("placeholder\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "placeholder.txt", Mode: 0644, Size: int64(len(content)),
	}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}

	req, _ := http.NewRequest("PUT", baseURL+"/api/v1/jobs/"+jobID+"/input", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", "application/x-tar")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("input upload failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("input upload returned %d: %s", resp.StatusCode, body)
	}

	if st := waitJobStatus(t, client, baseURL, sid, jobID, 1, 30*time.Second); st != 1 {
		reason := ""
		if st == 5 {
			reason = " HoldReason=" + holdReasonOf(t, client, baseURL, sid, jobID)
		}
		t.Fatalf("job %s never reached idle (status=%d)%s", jobID, st, reason)
	}
	return jobID
}
