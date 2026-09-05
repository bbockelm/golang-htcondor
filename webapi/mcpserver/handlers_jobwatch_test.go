package mcpserver

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// stubSource lets the tool tests drive the evaluator without a schedd.
type stubSource struct {
	queue   []*classad.ClassAd
	history []*classad.ClassAd
}

func (s *stubSource) Queue(context.Context, string, []string, int) (jobwatch.QueueResult, error) {
	return jobwatch.QueueResult{Ads: s.queue}, nil
}
func (s *stubSource) History(context.Context, string, []string, time.Time, int) ([]*classad.ClassAd, error) {
	return s.history, nil
}

func watchServer(t *testing.T, src jobwatch.Source) *Server {
	t.Helper()
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := jobwatch.NewStore(db)
	return &Server{jobWatch: store, jobWatchEval: jobwatch.NewEvaluator(store, src, nil)}
}

func aliceCtx() context.Context {
	return htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
}

func histAd(cluster, proc, status, exitCode int64) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttr("ClusterId", cluster)
	ad.InsertAttr("ProcId", proc)
	ad.InsertAttr("JobStatus", status)
	ad.InsertAttr("ExitCode", exitCode)
	ad.InsertAttrBool("ExitBySignal", false)
	return ad
}

func text(t *testing.T, res interface{}) string {
	t.Helper()
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not a map: %T", res)
	}
	content, ok := m["content"].([]map[string]interface{})
	if !ok || len(content) == 0 {
		t.Fatalf("no content: %+v", m)
	}
	s, _ := content[0]["text"].(string)
	return s
}

// TestWatchJobsAnswersImmediatelyWhenAlreadyDone is the one-shot case,
// and the reason registration evaluates before returning. An agent
// submits, does other work, and only then thinks to wait -- by which
// time the jobs have finished. A watch that only fired on a FUTURE
// change would wait forever for something that already happened.
func TestWatchJobsAnswersImmediatelyWhenAlreadyDone(t *testing.T) {
	s := watchServer(t, &stubSource{history: []*classad.ClassAd{
		histAd(42, 0, 4, 0), histAd(42, 1, 4, 0),
	}})

	res, err := s.toolWatchJobs(aliceCtx(), map[string]interface{}{"constraint": "ClusterId == 42"})
	if err != nil {
		t.Fatalf("watch_jobs: %v", err)
	}
	got := text(t, res)
	if !strings.Contains(got, "FIRED") {
		t.Errorf("a condition that is already true must be answered in the registration call:\n%s", got)
	}
	if !strings.Contains(got, "2 jobs finished") {
		t.Errorf("the answer should say what happened:\n%s", got)
	}
}

// TestWatchJobsReturnsWithoutBlocking: the default is register and
// return. Blocking by default would tie the answer to a connection
// staying open, which is exactly what an agent cannot rely on.
func TestWatchJobsReturnsWithoutBlocking(t *testing.T) {
	s := watchServer(t, &stubSource{queue: []*classad.ClassAd{histAd(42, 0, 2, 0)}})

	start := time.Now()
	res, err := s.toolWatchJobs(aliceCtx(), map[string]interface{}{"constraint": "ClusterId == 42"})
	if err != nil {
		t.Fatalf("watch_jobs: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("registration blocked for %v with no wait_seconds", elapsed)
	}
	got := text(t, res)
	if !strings.Contains(got, "WAITING") {
		t.Errorf("a running job should leave the watch waiting:\n%s", got)
	}
	if !strings.Contains(got, "Do not poll") {
		t.Errorf("the response should tell the agent not to poll, since that is the habit being replaced:\n%s", got)
	}
}

// TestDefaultModeFollowsTheEvent. "Tell me when my jobs are done" means
// all of them; "tell me if anything fails" means any. Defaulting
// everything to "any" would make the commonest call fire on the first
// job of a thousand -- a wrong answer that looks right.
func TestDefaultModeFollowsTheEvent(t *testing.T) {
	// One finished, one still running: "done" must NOT fire.
	s := watchServer(t, &stubSource{
		queue:   []*classad.ClassAd{histAd(42, 1, 2, 0)},
		history: []*classad.ClassAd{histAd(42, 0, 4, 0)},
	})
	res, err := s.toolWatchJobs(aliceCtx(), map[string]interface{}{"constraint": "ClusterId == 42"})
	if err != nil {
		t.Fatal(err)
	}
	if got := text(t, res); strings.Contains(got, "FIRED") {
		t.Errorf("default \"done\" fired with a job still running; it should mean ALL:\n%s", got)
	}

	// Whereas "failed" means any.
	s2 := watchServer(t, &stubSource{history: []*classad.ClassAd{
		histAd(7, 0, 4, 0), histAd(7, 1, 4, 3),
	}})
	res, err = s2.toolWatchJobs(aliceCtx(), map[string]interface{}{"constraint": "ClusterId == 7", "event": "failed"})
	if err != nil {
		t.Fatal(err)
	}
	if got := text(t, res); !strings.Contains(got, "FIRED") || !strings.Contains(got, "FAILED") {
		t.Errorf("\"failed\" should fire on any failure:\n%s", got)
	}
}

// TestCheckWatchesReportsThenStopsRepeating: "what happened while I was
// gone" must be cheap to call every turn, which means it cannot keep
// re-reporting the same answer.
func TestCheckWatchesReportsThenStopsRepeating(t *testing.T) {
	s := watchServer(t, &stubSource{history: []*classad.ClassAd{histAd(42, 0, 4, 0)}})
	ctx := aliceCtx()
	if _, err := s.toolWatchJobs(ctx, map[string]interface{}{"constraint": "ClusterId == 42"}); err != nil {
		t.Fatal(err)
	}

	first, err := s.toolCheckWatches(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text(t, first), "1 watch fired") {
		t.Errorf("the first check should report the answer:\n%s", text(t, first))
	}

	second, err := s.toolCheckWatches(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text(t, second), "1 watch fired") {
		t.Errorf("the same answer was reported twice; an agent calling this every turn would "+
			"re-act on old news:\n%s", text(t, second))
	}

	// But it is not consumed -- asking again explicitly still finds it.
	again, err := s.toolCheckWatches(ctx, map[string]interface{}{"include_delivered": true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text(t, again), "finished") {
		t.Errorf("a delivered answer must still be retrievable:\n%s", text(t, again))
	}
}

// TestWatchToolsRefuseAnUnidentifiedCaller. A watch is stored against an
// identity and every readback filters on it; defaulting an unknown
// caller to anything would put one user's answers in another's hands.
func TestWatchToolsRefuseAnUnidentifiedCaller(t *testing.T) {
	s := watchServer(t, &stubSource{})
	ctx := context.Background()

	if _, err := s.toolWatchJobs(ctx, map[string]interface{}{"constraint": "true"}); err == nil {
		t.Error("watch_jobs must refuse a caller it cannot identify")
	}
	if _, err := s.toolCheckWatches(ctx, map[string]interface{}{}); err == nil {
		t.Error("check_watches must refuse a caller it cannot identify")
	}
	if _, err := s.toolCancelWatch(ctx, map[string]interface{}{"watch_id": "w-1"}); err == nil {
		t.Error("cancel_watch must refuse a caller it cannot identify")
	}
}

// TestCancelIsScopedToTheCaller: guessing an id must not reach someone
// else's watch.
func TestCancelIsScopedToTheCaller(t *testing.T) {
	s := watchServer(t, &stubSource{queue: []*classad.ClassAd{histAd(42, 0, 2, 0)}})
	res, err := s.toolWatchJobs(aliceCtx(), map[string]interface{}{"constraint": "ClusterId == 42"})
	if err != nil {
		t.Fatal(err)
	}
	id := watchIDFrom(t, text(t, res))

	bob := htcondor.WithAuthenticatedUser(context.Background(), "bob@uid.domain")
	if _, err := s.toolCancelWatch(bob, map[string]interface{}{"watch_id": id}); err == nil {
		t.Error("bob cancelled alice's watch")
	}
	if _, err := s.toolCancelWatch(aliceCtx(), map[string]interface{}{"watch_id": id}); err != nil {
		t.Errorf("alice could not cancel her own watch: %v", err)
	}
}

// TestToolDescriptionSteersAwayFromTheTrap. The tool description is the
// only instruction the model gets, and "JobStatus == 4" is exactly what
// it writes when asked to wait for completion -- a condition the schedd
// never leaves observable. The description has to say so.
func TestToolDescriptionSteersAwayFromTheTrap(t *testing.T) {
	var watchTool *Tool
	for i, tool := range jobWatchTools() {
		if tool.Name == "watch_jobs" {
			watchTool = &jobWatchTools()[i]
		}
	}
	if watchTool == nil {
		t.Fatal("watch_jobs is not defined")
	}
	for _, want := range []string{"JobStatus == 4", "removed from the queue", "event=\"done\""} {
		if !strings.Contains(watchTool.Description, want) {
			t.Errorf("the description should warn about %q:\n%s", want, watchTool.Description)
		}
	}
	// And every event in the vocabulary must be offered, or the
	// description promises something the schema will not accept.
	props := watchTool.InputSchema["properties"].(map[string]interface{})
	enum := props["event"].(map[string]interface{})["enum"].([]interface{})
	if len(enum) != len(jobwatch.Events) {
		t.Errorf("the event enum has %d values but the vocabulary has %d", len(enum), len(jobwatch.Events))
	}
}

func watchIDFrom(t *testing.T, s string) string {
	t.Helper()
	i := strings.Index(s, "w-")
	if i < 0 {
		t.Fatalf("no watch id in:\n%s", s)
	}
	end := i
	for end < len(s) && s[end] != ' ' && s[end] != '\n' {
		end++
	}
	return s[i:end]
}
