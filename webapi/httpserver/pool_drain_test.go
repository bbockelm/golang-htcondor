package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/drainest"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// fakeDrainSlots is the collector: a fixed set of slot ads, an optional
// error, and a count of reads.
type fakeDrainSlots struct {
	mu      sync.Mutex
	ads     []string
	err     error
	calls   atomic.Int64
	origins []htcondor.CredentialOrigin
	// gate, when set, holds every read until it is closed.
	gate chan struct{}
}

func (f *fakeDrainSlots) Slots(ctx context.Context, yield func(*classad.ClassAd)) error {
	f.calls.Add(1)
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	origin, _ := htcondor.CredentialOriginFromContext(ctx)
	f.origins = append(f.origins, origin)
	if f.err != nil {
		return f.err
	}
	for _, text := range f.ads {
		ad, err := classad.ParseOld(text)
		if err != nil {
			return err
		}
		yield(ad)
	}
	return nil
}

func (f *fakeDrainSlots) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// fakeDrainJobs is the schedd's running jobs.
type fakeDrainJobs struct {
	ads     []*classad.ClassAd
	err     error
	origins []htcondor.CredentialOrigin
	attrs   []string
}

func (f *fakeDrainJobs) RunningJobs(ctx context.Context, attrs []string, limit int, yield func(*classad.ClassAd)) (bool, error) {
	origin, _ := htcondor.CredentialOriginFromContext(ctx)
	f.origins = append(f.origins, origin)
	f.attrs = attrs
	if f.err != nil {
		return false, f.err
	}
	for i, ad := range f.ads {
		if i >= limit {
			return true, nil
		}
		yield(ad)
	}
	return false, nil
}

var drainNow = time.Unix(1_800_000_000, 0)

func slotAdText(machine, slot, gid string, cpus int, jobStart, retirementLeft int64) string {
	return fmt.Sprintf(`Name = "%s@%s"
Machine = %q
SlotType = "Dynamic"
State = "Claimed"
Activity = "Busy"
Cpus = %d
GlobalJobId = %q
RemoteOwner = "someone@chtc.wisc.edu"
JobStart = %d
MyCurrentTime = %d
RetirementTimeRemaining = %d
MaxJobRetirementTime = JobRuntimeGuarantee`, slot, machine, machine, cpus, gid, jobStart, drainNow.Unix(), retirementLeft)
}

// drainEstimator has read five 3600-second runs of alice's program.
func drainEstimator(t *testing.T) *runtimeest.Estimator {
	t.Helper()
	est := runtimeest.New(runtimeest.Config{})
	b := runtimeest.NewBatch()
	for i := range 5 {
		b.AddAd(historyRecord(t, "alice", 100+i, 3600, 1_000_000+int64(i)))
	}
	est.Ingest(b)
	return est
}

// runningJob is alice's job 7.0 on this access point, 600 seconds in.
func runningJob(t *testing.T) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(fmt.Sprintf(`Owner = "alice"
ClusterId = 7
ProcId = 0
Cmd = "/home/alice/sim"
JobStatus = 2
JobCurrentStartDate = %d
GlobalJobId = "ap2001.chtc.wisc.edu#7.0#1"`, drainNow.Unix()-600))
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

func testPoolDrain(t *testing.T, slots *fakeDrainSlots, jobs *fakeDrainJobs, est *runtimeest.Estimator, ap string) (*poolDrain, func(time.Duration)) {
	t.Helper()
	var dj drainJobSource
	if jobs != nil {
		dj = jobs
	}
	p := newPoolDrain(slots, dj, est, ap, testLogger(t))
	clock := drainNow
	var mu sync.Mutex
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}
	p.now = now
	p.cache.now = now
	return p, func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(d)
	}
}

func mixedSlots() *fakeDrainSlots {
	return &fakeDrainSlots{ads: []string{
		slotAdText("e1.chtc.wisc.edu", "slot1_1", "ap2001.chtc.wisc.edu#7.0#1", 4, drainNow.Unix()-600, 259200-600),
		slotAdText("e1.chtc.wisc.edu", "slot1_2", "ap2002.chtc.wisc.edu#9.0#1", 1, drainNow.Unix()-600, 172800),
		slotAdText("e2.chtc.wisc.edu", "slot1_1", "grid.icecube.wisc.edu#3.4#1", 1, drainNow.Unix()-60, 30),
	}}
}

func TestPoolDrainComputesAsTheDaemon(t *testing.T) {
	slots := mixedSlots()
	jobs := &fakeDrainJobs{ads: []*classad.ClassAd{runningJob(t)}}
	p, _ := testPoolDrain(t, slots, jobs, drainEstimator(t), "")

	resp, err := p.get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(slots.origins) != 1 || slots.origins[0] != htcondor.OriginDaemon ||
		len(jobs.origins) != 1 || jobs.origins[0] != htcondor.OriginDaemon {
		t.Errorf("reads ran as %v / %v, want the daemon", slots.origins, jobs.origins)
	}
	// The access point was learned from its own jobs' ids.
	if resp.AccessPoint != "ap2001.chtc.wisc.edu" || !resp.EstimatesAvailable {
		t.Errorf("%+v", resp)
	}
	if len(resp.Machines) != 2 {
		t.Fatalf("machines %+v", resp.Machines)
	}
	e1, e2 := resp.Machines[0], resp.Machines[1]
	if e1.JobsEstimated != 1 || e1.JobsUnknownEnd != 1 || e1.AtLeastSeconds == nil || *e1.AtLeastSeconds != 3000 {
		t.Errorf("e1: %+v", e1)
	}
	if e1.UnknownUpToSeconds == nil || *e1.UnknownUpToSeconds != 172800 {
		t.Errorf("e1 unknown up to: %v", e1.UnknownUpToSeconds)
	}
	if e2.EvictedOnDrain != 1 || e2.LikelyEmptySeconds == nil || *e2.LikelyEmptySeconds != 30 {
		t.Errorf("e2: %+v", e2)
	}
	if resp.Summary.CoresFreeingNextHour != 4 || resp.Summary.JobsEstimated != 1 || resp.Summary.JobsRunning != 3 {
		t.Errorf("summary %+v", resp.Summary)
	}
	found := false
	for _, a := range jobs.attrs {
		if a == "GlobalJobId" {
			found = true
		}
	}
	if !found {
		t.Errorf("the job read does not project GlobalJobId: %v", jobs.attrs)
	}
}

// One read serves every caller within the TTL, and concurrent callers
// share one read.
func TestPoolDrainSingleFlightAndCache(t *testing.T) {
	slots := mixedSlots()
	slots.gate = make(chan struct{})
	p, advance := testPoolDrain(t, slots, nil, nil, "ap2001.chtc.wisc.edu")

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.get(context.Background()); err != nil {
				errs <- err
			}
		}()
	}
	// Let them all queue behind the first read, then release it.
	deadline := time.Now().Add(5 * time.Second)
	for slots.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(slots.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := slots.calls.Load(); n != 1 {
		t.Errorf("%d reads for concurrent callers, want 1", n)
	}

	if _, err := p.get(context.Background()); err != nil || slots.calls.Load() != 1 {
		t.Errorf("within the TTL: err %v, reads %d", err, slots.calls.Load())
	}
	advance(poolDrainTTL + time.Second)
	if _, err := p.get(context.Background()); err != nil || slots.calls.Load() != 2 {
		t.Errorf("past the TTL: err %v, reads %d", err, slots.calls.Load())
	}
}

// A failed refresh serves the last good answer, marked stale.
func TestPoolDrainLastGoodOnError(t *testing.T) {
	slots := mixedSlots()
	p, advance := testPoolDrain(t, slots, nil, nil, "ap2001.chtc.wisc.edu")
	first, err := p.get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if at, lastErr := p.lastFailure(); lastErr != nil || !at.IsZero() {
		t.Errorf("no failure yet: %v %v", at, lastErr)
	}

	advance(poolDrainTTL + time.Second)
	slots.setErr(errors.New("collector unreachable"))
	again, err := p.get(context.Background())
	if err != nil || again != first {
		t.Fatalf("after a failure: %v, same answer %v", err, again == first)
	}
	at, lastErr := p.lastFailure()
	if lastErr == nil || !at.After(first.GeneratedAt) {
		t.Errorf("failure not recorded: %v at %v", lastErr, at)
	}

	// With nothing to fall back on, the error.
	fresh, _ := testPoolDrain(t, &fakeDrainSlots{err: errors.New("down")}, nil, nil, "")
	if _, err := fresh.get(context.Background()); err == nil {
		t.Error("no answer and no error")
	}
}

// Running jobs that cannot be read leave the retirement bounds.
func TestPoolDrainJobReadFails(t *testing.T) {
	jobs := &fakeDrainJobs{err: errors.New("schedd down")}
	p, _ := testPoolDrain(t, mixedSlots(), jobs, drainEstimator(t), "ap2001.chtc.wisc.edu")
	resp, err := p.get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.EstimatesAvailable || resp.Error == "" || resp.Summary.JobsEstimated != 0 || resp.Summary.JobsRunning != 3 {
		t.Errorf("%+v", resp)
	}
	if resp.Machines[0].JobsFromThisAP != 1 {
		t.Errorf("the configured access point still identifies its jobs: %+v", resp.Machines[0])
	}
}

// No estimator: no job read at all, and the structure is unchanged.
func TestPoolDrainWithoutEstimator(t *testing.T) {
	jobs := &fakeDrainJobs{}
	p, _ := testPoolDrain(t, mixedSlots(), jobs, nil, "ap2001.chtc.wisc.edu")
	resp, err := p.get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs.origins) != 0 {
		t.Error("read the queue with no estimator to use it")
	}
	if resp.EstimatesAvailable || resp.Summary.JobsEstimated != 0 || len(resp.Machines) != 2 ||
		resp.Machines[1].EvictedOnDrain != 1 {
		t.Errorf("%+v", resp)
	}
}

type drainBody struct {
	drainest.Response
}

func (f *twoOwnerFixture) drain(t *testing.T, query string, auth func(*http.Request)) (int, drainBody) {
	t.Helper()
	w := f.do(t, http.MethodGet, "/api/v1/pool/drain-estimates"+query, "", auth)
	var body drainBody
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding %s: %v", w.Body.String(), err)
		}
	}
	return w.Code, body
}

func TestPoolDrainEndpoint(t *testing.T) {
	f := twoOwnerScheddServer(t)
	slots := mixedSlots()
	jobs := &fakeDrainJobs{ads: []*classad.ClassAd{runningJob(t)}}
	p, advance := testPoolDrain(t, slots, jobs, drainEstimator(t), "ap2001.chtc.wisc.edu")
	f.s.poolDrainVal = p

	if code, _ := f.drain(t, "", func(*http.Request) {}); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: %d", code)
	}
	if slots.calls.Load() != 0 {
		t.Error("an unauthenticated request started a computation")
	}

	// Any signed-in user sees every user's jobs: bob sees alice's.
	code, body := f.drain(t, "", f.bearer(t, "bob"))
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if len(body.Machines) != 2 || body.Machines[0].Slots != nil || body.Machines[0].JobsEstimated != 1 {
		t.Errorf("pool-wide: %+v", body.Machines)
	}
	if body.Stale || body.Error != "" || !body.EstimatesAvailable {
		t.Errorf("envelope: %+v", body.Response)
	}

	code, body = f.drain(t, "?machine=E1.chtc.wisc.edu", f.bearer(t, "bob"))
	if code != http.StatusOK || len(body.Machines) != 1 || len(body.Machines[0].Slots) != 2 {
		t.Fatalf("one machine: %d %+v", code, body.Machines)
	}
	s := body.Machines[0].Slots[0]
	if !s.FromThisAP || s.ExpectedEnd == nil || !s.ExpectedEnd.Equal(drainNow.Add(3000*time.Second)) {
		t.Errorf("alice's slot: %+v", s)
	}
	other := body.Machines[0].Slots[1]
	if other.FromThisAP || other.SubmittedFrom != "ap2002.chtc.wisc.edu" || other.ExpectedEnd != nil || other.RetirementDeadline == nil {
		t.Errorf("other AP's slot: %+v", other)
	}
	if slots.calls.Load() != 1 {
		t.Errorf("%d computations for two requests within the TTL", slots.calls.Load())
	}

	// A failed refresh: the last answer, its age, and why.
	advance(poolDrainTTL + 5*time.Second)
	slots.setErr(errors.New("collector unreachable"))
	code, body = f.drain(t, "", f.bearer(t, "alice"))
	if code != http.StatusOK || !body.Stale || body.Error == "" || body.AgeSeconds != (poolDrainTTL+5*time.Second).Seconds() {
		t.Errorf("stale: %d %+v", code, body.Response)
	}

	if w := f.do(t, http.MethodPost, "/api/v1/pool/drain-estimates", "", f.bearer(t, "bob")); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}

// No collector: nothing to describe.
func TestPoolDrainEndpointNoCollector(t *testing.T) {
	f := twoOwnerScheddServer(t)
	if f.s.collector != nil {
		t.Skip("the fixture has a collector")
	}
	if code, _ := f.drain(t, "", f.bearer(t, "bob")); code != http.StatusNotImplemented {
		t.Errorf("status %d, want 501", code)
	}
}

func TestPoolDrainRouteIsClassified(t *testing.T) {
	if got := classifyRoute("/api/v1/pool/drain-estimates"); got != "/api/v1/pool/drain-estimates" {
		t.Errorf("classifyRoute = %q", got)
	}
}

func TestPoolDrainIsDocumented(t *testing.T) {
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("openapi does not parse: %v", err)
	}
	if _, ok := doc.Paths["/pool/drain-estimates"]; !ok {
		t.Error("/pool/drain-estimates missing from the OpenAPI paths")
	}
}
