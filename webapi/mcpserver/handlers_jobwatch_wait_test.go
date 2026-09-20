package mcpserver

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Waiting in check_watches. The tool an agent is told to call repeatedly
// has to be the tool that can wait: watch_jobs is "call this once per
// question", so steering waits there left "is it done yet" with no
// correct move but a polling loop.

// shortPoll shrinks the re-evaluation interval for a test, so a test of the
// blocking path costs a few poll cycles rather than a few seconds. It is the
// interval that is shortened, never the deadline under test.
func shortPoll(t *testing.T, d time.Duration) {
	t.Helper()
	prev := watchPollInterval
	watchPollInterval = d
	t.Cleanup(func() { watchPollInterval = prev })
}

func blockedSeconds(t *testing.T, res interface{}) int {
	t.Helper()
	sc := structuredOf(t, res)
	v, ok := sc["blocked_seconds"].(int)
	if !ok {
		t.Fatalf("no blocked_seconds in the result: %+v", sc)
	}
	return v
}

// flipSource is a queue that finishes a job partway through a wait. The
// change is tied to the evaluation pass, not to the clock: pass finishAt
// and everything after it reads the job from history as done, so the
// answer provably arrives while the call is blocked rather than before it
// started.
type flipSource struct {
	mu       sync.Mutex
	passes   int
	finishAt int
	running  *classad.ClassAd
	finished *classad.ClassAd
}

func (f *flipSource) Queue(_ context.Context, _ string, _ []string, _ int, yield func(*classad.ClassAd)) (bool, error) {
	f.mu.Lock()
	f.passes++
	pass := f.passes
	f.mu.Unlock()
	if pass < f.finishAt {
		yield(f.running)
	}
	return false, nil
}

// History answers for the same pass the queue read belongs to, so one
// evaluation never sees the job both running and finished.
func (f *flipSource) History(_ context.Context, _ string, _ []string, _ time.Time, _ int, yield func(*classad.ClassAd)) error {
	if f.passCount() >= f.finishAt {
		yield(f.finished)
	}
	return nil
}

func (f *flipSource) passCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.passes
}

// TestCheckWatchesReturnsAnAnswerItAlreadyHas: an answer that already
// exists must come back on the first pass. A wait that slept first would
// hold a caller for 30 seconds on a question that was settled before it
// asked -- the same "fires straight away if already satisfied" property
// registration has.
func TestCheckWatchesReturnsAnAnswerItAlreadyHas(t *testing.T) {
	s := watchServer(t, &stubSource{history: []*classad.ClassAd{histAd(42, 0, 4, 0)}})
	shortPoll(t, time.Second)
	mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 42"})

	started := time.Now()
	res := mustCheck(t, s, map[string]interface{}{"wait_seconds": 30})
	elapsed := time.Since(started)

	if elapsed > 500*time.Millisecond {
		t.Errorf("check_watches blocked for %s on an answer it already had", elapsed)
	}
	if got := text(t, res); !strings.Contains(got, "1 watch fired") {
		t.Errorf("the answer was not reported:\n%s", got)
	}
	if got := blockedSeconds(t, res); got != 0 {
		t.Errorf("blocked_seconds = %d for a call that did not block", got)
	}
}

// TestCheckWatchesBlocksUntilAWatchFires is the blocking path itself. The
// watch cannot fire before the wait begins -- registration sees the job
// running, and it only finishes on a later pass -- so the answer is
// produced by the wait and by nothing else.
func TestCheckWatchesBlocksUntilAWatchFires(t *testing.T) {
	src := &flipSource{
		finishAt: 3, // 1: registration, 2: first pass of the wait, 3: finished
		running:  histAd(42, 0, 2, 0),
		finished: histAd(42, 0, 4, 0),
	}
	s := watchServer(t, src)
	shortPoll(t, 20*time.Millisecond)

	if got := text(t, mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 42"})); !strings.Contains(got, "WAITING") {
		t.Fatalf("the job was already finished at registration; this would not test the wait:\n%s", got)
	}

	started := time.Now()
	res := mustCheck(t, s, map[string]interface{}{"wait_seconds": 30})
	elapsed := time.Since(started)

	if got := text(t, res); !strings.Contains(got, "1 watch fired") {
		t.Fatalf("the wait did not return the answer that arrived during it:\n%s", got)
	}
	if elapsed < watchPollInterval {
		t.Errorf("the call returned after %s, less than one poll interval: it cannot have waited", elapsed)
	}
	if n := src.passCount(); n < src.finishAt {
		t.Errorf("the queue was read %d times; the wait did not re-evaluate", n)
	}
}

// TestCheckWatchesDeadlineAnswersNotYet: running out of time is a normal
// answer. The failure this replaces is a block that outlives the client's
// own timeout, where the caller gets nothing at all -- not the progress,
// not even the watch id.
func TestCheckWatchesDeadlineAnswersNotYet(t *testing.T) {
	s := watchServer(t, &stubSource{queue: []*classad.ClassAd{histAd(42, 0, 2, 0)}})
	shortPoll(t, 100*time.Millisecond)
	id := watchIDFrom(t, text(t, mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 42"})))

	started := time.Now()
	res := mustCheck(t, s, map[string]interface{}{"wait_seconds": 1})
	elapsed := time.Since(started)

	if elapsed < time.Second {
		t.Errorf("the call returned after %s; it was asked to wait a second", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("the call overran its deadline by a long way: %s", elapsed)
	}
	got := text(t, res)
	for _, want := range []string{"Nothing new", "still waiting", "check_watches again", id} {
		if !strings.Contains(got, want) {
			t.Errorf("a wait that ran out must say so and leave the caller able to continue; %q missing:\n%s", want, got)
		}
	}
	if n := blockedSeconds(t, res); n != 1 {
		t.Errorf("blocked_seconds = %d after a one-second wait", n)
	}
	sc := structuredOf(t, res)
	if n, _ := sc["waiting_count"].(int); n != 1 {
		t.Errorf("waiting_count = %v; the watch is still registered and must be reported: %+v", sc["waiting_count"], sc)
	}
}

// TestCheckWatchesWithoutWaitSecondsDoesNotBlock: the parameter is opt-in.
// Every caller written against the old tool asks the same question and
// must get the same immediate snapshot.
func TestCheckWatchesWithoutWaitSecondsDoesNotBlock(t *testing.T) {
	s := watchServer(t, &stubSource{queue: []*classad.ClassAd{histAd(42, 0, 2, 0)}})
	shortPoll(t, time.Second)
	mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 42"})

	started := time.Now()
	res := mustCheck(t, s, map[string]interface{}{})
	elapsed := time.Since(started)

	if elapsed > 500*time.Millisecond {
		t.Errorf("check_watches blocked for %s with no wait_seconds", elapsed)
	}
	if got := blockedSeconds(t, res); got != 0 {
		t.Errorf("blocked_seconds = %d for a call that did not block", got)
	}
	if got := text(t, res); !strings.Contains(got, "Nothing new") {
		t.Errorf("expected the ordinary non-blocking report:\n%s", got)
	}
}

// TestCheckWatchesWaitIsScopedToTheNamedWatch: a caller waiting on one
// watch must not be released by another one's answer. Waking on "some
// watch fired" would hand back an answer to a question the caller did not
// ask and leave it believing the one it did ask had been settled.
func TestCheckWatchesWaitIsScopedToTheNamedWatch(t *testing.T) {
	s := watchServer(t, &stubSource{
		queue:   []*classad.ClassAd{histAd(43, 0, 2, 0)},
		history: []*classad.ClassAd{histAd(42, 0, 4, 0)},
	})
	shortPoll(t, 100*time.Millisecond)

	waiting := watchIDFrom(t, text(t, mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 43"})))
	if got := text(t, mustWatch(t, s, map[string]interface{}{"constraint": "ClusterId == 42"})); !strings.Contains(got, "FIRED") {
		t.Fatalf("the other watch was meant to have an answer waiting:\n%s", got)
	}

	started := time.Now()
	res := mustCheck(t, s, map[string]interface{}{"watch_id": waiting, "wait_seconds": 1})
	elapsed := time.Since(started)

	if elapsed < time.Second {
		t.Errorf("the wait ended after %s: another watch's answer released it", elapsed)
	}
	sc := structuredOf(t, res)
	if n, _ := sc["new_count"].(int); n != 0 {
		t.Errorf("new_count = %v; only the named watch may be reported: %+v", sc["new_count"], sc)
	}
}
