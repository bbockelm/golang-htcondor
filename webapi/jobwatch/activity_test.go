package jobwatch

import (
	"fmt"
	"testing"
	"time"
)

// The activity stream's whole job is to decide which of the many writes
// to the jobs table are worth a line on a dashboard. Almost all of them
// are not, and two of the wrong answers are actively misleading: a burst
// of invented submissions after every restart, and a completion claimed
// for a job that may have been removed.

// activityFixture returns a feed with a frozen clock and a subscriber.
func activityFixture(t *testing.T, owner string) (*Feed, <-chan ActivityEvent, time.Time) {
	t.Helper()
	now := time.Unix(1_700_000_000, 0)
	f := NewFeed(nil)
	f.now = func() time.Time { return now }
	ch, cancel := f.SubscribeActivity(owner, 16)
	t.Cleanup(cancel)
	return f, ch, now
}

// upsert builds a job ad and applies it.
func applyUpsert(f *Feed, key string, attrs string) {
	f.Apply(WatchEvent{Kind: WatchUpsert, Key: key, AdText: attrs})
}

func drainActivity(ch <-chan ActivityEvent) []ActivityEvent {
	var out []ActivityEvent
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func jobAd(cluster int, owner string, status int, extra string) string {
	return fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nJobStatus = %d\n%s",
		cluster, owner, status, extra)
}

func TestStatusChangesBecomeEvents(t *testing.T) {
	f, ch, now := activityFixture(t, "")

	// A job we already know about, idle.
	applyUpsert(f, "1.0", jobAd(1, "alice", 1, fmt.Sprintf("QDate = %d", now.Add(-time.Hour).Unix())))
	if got := drainActivity(ch); len(got) != 0 {
		t.Fatalf("first sighting of an hour-old idle job produced %v", got)
	}

	for _, step := range []struct {
		status int
		extra  string
		want   ActivityKind
		detail string
	}{
		{2, `RemoteHost = "slot1@ep.example"`, ActivityStarted, "slot1@ep.example"},
		{5, `HoldReason = "output transfer failed"`, ActivityHeld, "output transfer failed"},
		{1, "", ActivityReleased, ""},
		{2, `RemoteHost = "slot2@ep.example"`, ActivityStarted, "slot2@ep.example"},
		{4, "ExitCode = 0", ActivityCompleted, "exit 0"},
	} {
		applyUpsert(f, "1.0", jobAd(1, "alice", step.status, step.extra))
		got := drainActivity(ch)
		if len(got) != 1 {
			t.Fatalf("status %d produced %d events, want 1: %+v", step.status, len(got), got)
		}
		if got[0].Kind != step.want {
			t.Errorf("status %d gave kind %q, want %q", step.status, got[0].Kind, step.want)
		}
		if got[0].Detail != step.detail {
			t.Errorf("status %d gave detail %q, want %q", step.status, got[0].Detail, step.detail)
		}
		if got[0].Cluster != 1 || got[0].Owner != "alice" {
			t.Errorf("event lost its identity: %+v", got[0])
		}
	}
}

// The write that is not an event. On a busy access point this is the
// overwhelming majority of them, and it is the reason a stream of status
// changes is cheap enough to leave open.
func TestAttributeUpdatesAreNotEvents(t *testing.T) {
	f, ch, now := activityFixture(t, "")
	base := fmt.Sprintf("QDate = %d\nRemoteHost = \"slot1@ep\"", now.Add(-time.Hour).Unix())
	applyUpsert(f, "1.0", jobAd(1, "alice", 2, base))
	drainActivity(ch)

	for i := 0; i < 5; i++ {
		applyUpsert(f, "1.0", jobAd(1, "alice", 2, base+fmt.Sprintf("\nRemoteSysCpu = %d.0", i)))
	}
	if got := drainActivity(ch); len(got) != 0 {
		t.Errorf("five attribute updates on a running job produced %d events: %+v", len(got), got)
	}
}

// The restart burst. The watch starts at the head of the change log, so
// the first event for a job is the first time it was written since we
// connected -- which for a long-queued job is a routine update, not a
// submission. Reporting those would put thousands of fictional
// submissions on the ticker moments after every restart.
func TestFirstSightingOfAnOldJobIsSilent(t *testing.T) {
	f, ch, now := activityFixture(t, "")
	old := now.Add(-6 * time.Hour).Unix()

	applyUpsert(f, "1.0", jobAd(1, "alice", 1, fmt.Sprintf("QDate = %d", old)))
	applyUpsert(f, "2.0", jobAd(2, "alice", 2, fmt.Sprintf("QDate = %d\nJobCurrentStartDate = %d\nRemoteHost = \"slot1@ep\"", old, old)))
	applyUpsert(f, "3.0", jobAd(3, "alice", 5, fmt.Sprintf("QDate = %d\nEnteredCurrentStatus = %d\nHoldReason = \"old hold\"", old, old)))

	if got := drainActivity(ch); len(got) != 0 {
		t.Errorf("first sighting of three long-queued jobs produced %d events: %+v", len(got), got)
	}
}

// ...but a job that genuinely just arrived has to show up, or a fresh
// submission is invisible until the next restart.
func TestFirstSightingOfSomethingNewIsReported(t *testing.T) {
	f, ch, now := activityFixture(t, "")

	applyUpsert(f, "1.0", jobAd(1, "alice", 1, fmt.Sprintf("QDate = %d\nCmd = \"/home/alice/run.sh\"", now.Add(-5*time.Second).Unix())))
	got := drainActivity(ch)
	if len(got) != 1 || got[0].Kind != ActivitySubmitted {
		t.Fatalf("a five-second-old submission gave %+v, want one submitted event", got)
	}
	// The base name, not the submitter's home directory repeated on
	// every line.
	if got[0].Detail != "run.sh" {
		t.Errorf("submitted detail = %q, want the command base name", got[0].Detail)
	}

	// A job first seen already running, having started moments ago.
	applyUpsert(f, "2.0", jobAd(2, "alice", 2, fmt.Sprintf("QDate = %d\nJobCurrentStartDate = %d\nRemoteHost = \"slot9@ep\"",
		now.Add(-time.Hour).Unix(), now.Add(-10*time.Second).Unix())))
	got = drainActivity(ch)
	if len(got) != 1 || got[0].Kind != ActivityStarted {
		t.Fatalf("a job that started ten seconds ago gave %+v, want one started event", got)
	}
}

// A job leaves the queue moments after the schedd records how it went,
// and the delete carries nothing. The outcome comes from the ad the feed
// already had.
func TestDeleteReportsTheOutcomeFromTheLastAd(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		extra  string
		want   ActivityKind
		detail string
	}{
		{"completed", 4, "ExitCode = 0", ActivityCompleted, "exit 0"},
		{"failed", 4, "ExitCode = 1", ActivityCompleted, "exit 1"},
		{"signalled", 4, "ExitBySignal = true", ActivityCompleted, "killed by a signal"},
		{"removed", 3, "", ActivityRemoved, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ch, now := activityFixture(t, "")
			applyUpsert(f, "1.0", jobAd(1, "alice", 1, fmt.Sprintf("QDate = %d", now.Add(-time.Hour).Unix())))
			applyUpsert(f, "1.0", jobAd(1, "alice", tc.status, tc.extra))
			drainActivity(ch)

			f.Apply(WatchEvent{Kind: WatchDelete, Key: "1.0"})
			got := drainActivity(ch)
			if len(got) != 1 {
				t.Fatalf("delete produced %d events, want 1: %+v", len(got), got)
			}
			if got[0].Kind != tc.want || got[0].Detail != tc.detail {
				t.Errorf("delete gave %q/%q, want %q/%q", got[0].Kind, got[0].Detail, tc.want, tc.detail)
			}
		})
	}
}

// A job that vanishes while idle or running says nothing about how it
// went. Calling that a completion would put a success on the ticker for
// something that may have failed.
func TestDeleteOfAnUnfinishedJobClaimsNothing(t *testing.T) {
	f, ch, now := activityFixture(t, "")
	applyUpsert(f, "1.0", jobAd(1, "alice", 2, fmt.Sprintf("QDate = %d\nRemoteHost = \"slot1@ep\"", now.Add(-time.Hour).Unix())))
	drainActivity(ch)

	f.Apply(WatchEvent{Kind: WatchDelete, Key: "1.0"})
	if got := drainActivity(ch); len(got) != 0 {
		t.Errorf("a running job vanishing produced %+v, want nothing claimed", got)
	}
}

// Scoping is enforced where the event is fanned out, not by the caller:
// an unprivileged browser must never receive another user's job, and a
// filter applied downstream is a filter that can be forgotten.
func TestSubscribersOnlySeeTheirOwnJobs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := NewFeed(nil)
	f.now = func() time.Time { return now }

	mine, cancelMine := f.SubscribeActivity("alice", 16)
	defer cancelMine()
	all, cancelAll := f.SubscribeActivity("", 16)
	defer cancelAll()

	fresh := fmt.Sprintf("QDate = %d", now.Add(-time.Second).Unix())
	applyUpsert(f, "1.0", jobAd(1, "alice", 1, fresh))
	applyUpsert(f, "2.0", jobAd(2, "bob", 1, fresh))

	got := drainActivity(mine)
	if len(got) != 1 || got[0].Owner != "alice" {
		t.Errorf("the owner-scoped subscriber saw %+v, want only alice's job", got)
	}
	if got := drainActivity(all); len(got) != 2 {
		t.Errorf("the unscoped subscriber saw %d events, want both", len(got))
	}
}

// A browser tab that stops reading must not be able to stall the feed --
// this is the same stream the MCP watch evaluator reads from. It loses
// events instead, and is told how many.
func TestASlowSubscriberLosesEventsRatherThanStallingTheFeed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := NewFeed(nil)
	f.now = func() time.Time { return now }
	ch, cancel := f.SubscribeActivity("", 2)
	defer cancel()

	fresh := fmt.Sprintf("QDate = %d", now.Add(-time.Second).Unix())
	for i := 1; i <= 6; i++ {
		// Each Apply would block here if delivery were synchronous.
		applyUpsert(f, fmt.Sprintf("%d.0", i), jobAd(i, "alice", 1, fresh))
	}

	first := <-ch
	if first.Skipped != 0 {
		t.Errorf("the first event reports %d skipped, want 0", first.Skipped)
	}
	<-ch // second buffered event

	// Room again: the next delivery carries the count of what was lost.
	applyUpsert(f, "99.0", jobAd(99, "alice", 1, fresh))
	next := <-ch
	if next.Skipped != 4 {
		t.Errorf("after four dropped events the next reports %d", next.Skipped)
	}
	if next.Cluster != 99 {
		t.Errorf("the ticker jumped backwards: got cluster %d, want the newest", next.Cluster)
	}
}

// Cancelling has to unregister as well as close, or a long-lived daemon
// accumulates a subscriber per page load.
func TestCancellingRemovesTheSubscription(t *testing.T) {
	f := NewFeed(nil)
	_, cancel := f.SubscribeActivity("", 4)
	cancel()
	cancel() // must be safe twice

	f.mu.Lock()
	n := len(f.activitySubs)
	f.mu.Unlock()
	if n != 0 {
		t.Errorf("%d subscriptions remain after cancel", n)
	}
}
