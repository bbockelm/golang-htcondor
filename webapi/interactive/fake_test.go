package interactive

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// fakeSchedd is a queue that remembers what was submitted and answers
// queries the way a schedd would: only the caller's own jobs, unless a
// test deliberately makes it misbehave.
type fakeSchedd struct {
	mu sync.Mutex

	nextCluster int
	jobs        []*fakeJob

	submitted   []string // submit files, in order
	spooled     [][]string
	constraints []string // constraints the manager queried with
	removed     []string

	// onQuery runs before each query answer, so a test can make the
	// queue change underneath a polling loop.
	onQuery func()

	submitErr error
	spoolErr  error
	queryErr  error

	// leakOtherOwners makes the fake answer with a job the caller does
	// not own, standing in for a schedd whose authenticated-query
	// filter did not apply. The manager is expected to drop it.
	leakOtherOwners bool
}

type fakeJob struct {
	cluster, proc int
	owner         string
	session       string
	batchName     string
	status        int
	holdReason    string
	holdCode      int
}

func newFakeSchedd() *fakeSchedd { return &fakeSchedd{nextCluster: 100} }

func (f *fakeSchedd) SubmitRemote(_ context.Context, submitFile string) (int, []*classad.ClassAd, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.submitErr != nil {
		return 0, nil, f.submitErr
	}
	f.submitted = append(f.submitted, submitFile)
	cluster := f.nextCluster
	f.nextCluster++

	job := &fakeJob{cluster: cluster, proc: 0, status: jobStatusIdle}
	for _, line := range strings.Split(submitFile, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "batch_name = ") {
			job.batchName = strings.TrimPrefix(line, "batch_name = ")
		}
	}
	if name, ok := SessionNameFromBatchName(job.batchName); ok {
		job.session = name
	}
	f.jobs = append(f.jobs, job)

	ad := classad.New()
	ad.InsertAttr("ClusterId", int64(cluster))
	ad.InsertAttr("ProcId", int64(0))
	return cluster, []*classad.ClassAd{ad}, nil
}

func (f *fakeSchedd) SpoolJobFilesFromFS(_ context.Context, _ []*classad.ClassAd, fsys fs.FS) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.spoolErr != nil {
		return f.spoolErr
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	f.spooled = append(f.spooled, names)
	return nil
}

func (f *fakeSchedd) QueryWithOptions(_ context.Context, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.queryErr != nil {
		return nil, nil, f.queryErr
	}
	if f.onQuery != nil {
		f.onQuery()
	}
	f.constraints = append(f.constraints, constraint)

	var ads []*classad.ClassAd
	for _, job := range f.jobs {
		if job.session == "" {
			continue
		}
		switch job.status {
		case jobStatusIdle, jobStatusRunning, jobStatusHeld:
		default:
			continue
		}
		if !f.leakOtherOwners && opts != nil && opts.Owner != "" && job.owner != opts.Owner {
			continue
		}
		ad := classad.New()
		ad.InsertAttr("ClusterId", int64(job.cluster))
		ad.InsertAttr("ProcId", int64(job.proc))
		ad.InsertAttr("JobStatus", int64(job.status))
		ad.InsertAttrString("JobBatchName", job.batchName)
		ad.InsertAttrString("Owner", job.owner)
		ad.InsertAttr("QDate", time.Now().Unix())
		if job.holdReason != "" {
			ad.InsertAttrString("HoldReason", job.holdReason)
		}
		if job.holdCode != 0 {
			ad.InsertAttr("HoldReasonCode", int64(job.holdCode))
		}
		ads = append(ads, ad)
	}
	return ads, nil, nil
}

func (f *fakeSchedd) RemoveJobs(_ context.Context, constraint string, _ string) (*htcondor.JobActionResults, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, constraint)
	return &htcondor.JobActionResults{}, nil
}

// setOwner assigns the owner of the most recently submitted job and
// returns it. Submission does not carry an owner in the submit file --
// the schedd stamps it from the authenticated identity -- so the fake
// does the same thing at the same moment.
func (f *fakeSchedd) setOwner(owner string) *fakeJob {
	f.mu.Lock()
	defer f.mu.Unlock()
	job := f.jobs[len(f.jobs)-1]
	job.owner = owner
	return job
}

func (f *fakeSchedd) setStatus(job *fakeJob, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job.status = status
}

func (f *fakeSchedd) removedJobs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.removed...)
}

// fakeShell records every command run through it and answers with a
// scripted result.
type fakeShell struct {
	mu       sync.Mutex
	commands []string
	closed   bool

	stdout   string
	stderr   string
	exitCode int
	runErr   error
	// notDispatched marks runErr as a failure that happened before the
	// command started, which is the only kind the manager retries.
	notDispatched bool

	// block, when non-nil, is waited on before a non-heartbeat command
	// returns -- for exercising timeouts.
	block chan struct{}
}

func (s *fakeShell) Run(ctx context.Context, cmd string, stdout, stderr io.Writer) (int, error) {
	s.mu.Lock()
	s.commands = append(s.commands, cmd)
	block := s.block
	runErr := s.runErr
	out, errOut, code := s.stdout, s.stderr, s.exitCode
	notDispatched := s.notDispatched
	s.mu.Unlock()

	if cmd == HeartbeatCmd || cmd == ShutdownCmd {
		// Sentinels are not the thing under test in a command test;
		// they always succeed unless the whole shell is failing.
		if runErr != nil {
			return -1, runErr
		}
		return 0, nil
	}
	if runErr != nil && notDispatched {
		return -1, fmt.Errorf("%w: %w", errNotDispatched, runErr)
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return -1, ctx.Err()
		}
	}
	if runErr != nil {
		return -1, runErr
	}
	_, _ = io.WriteString(stdout, out)
	_, _ = io.WriteString(stderr, errOut)
	return code, nil
}

func (s *fakeShell) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *fakeShell) ran() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func (s *fakeShell) countOf(cmd string) int {
	n := 0
	for _, c := range s.ran() {
		if c == cmd {
			n++
		}
	}
	return n
}

// testManager builds a Manager over a fake queue and a fake shell.
func testManager(t *testing.T, schedd *fakeSchedd, opts Options) (*Manager, *fakeShell) {
	t.Helper()
	shell := &fakeShell{}
	dialCount := 0
	if opts.Schedd == nil {
		opts.Schedd = func() ScheddClient { return schedd }
	}
	if opts.Dial == nil {
		opts.Dial = func(context.Context, int, int) (Shell, error) {
			dialCount++
			return shell, nil
		}
	}
	if opts.Logger == nil {
		logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
		if err != nil {
			t.Fatalf("logger: %v", err)
		}
		opts.Logger = logger
	}
	mgr, err := NewManager(opts)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(mgr.Close)
	return mgr, shell
}

// waitFor polls cond until it holds or the deadline passes. Tests wait
// on the condition rather than on a fixed sleep: a fixed sleep costs
// its full duration every run and still fails on a loaded machine.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

func mustCreate(t *testing.T, mgr *Manager, schedd *fakeSchedd, caller Caller, name string) *fakeJob {
	t.Helper()
	if _, err := mgr.Create(context.Background(), caller, CreateSpec{Name: name}); err != nil {
		t.Fatalf("Create(%q): %v", name, err)
	}
	return schedd.setOwner(caller.Owner)
}
