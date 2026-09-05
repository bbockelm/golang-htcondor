package jobwatch

import (
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

func upsert(key string, ad *classad.ClassAd) WatchEvent {
	return WatchEvent{Kind: WatchUpsert, Key: key, AdText: ad.MarshalOld()}
}

func del(key string) WatchEvent { return WatchEvent{Kind: WatchDelete, Key: key} }

func warmFeed(t *testing.T) *Feed {
	t.Helper()
	f := NewFeed(nil)
	f.setWarm(true)
	return f
}

func exitAd(cluster, proc, status, code int64) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttr("ClusterId", cluster)
	ad.InsertAttr("ProcId", proc)
	ad.InsertAttr("JobStatus", status)
	ad.InsertAttr("ExitCode", code)
	ad.InsertAttrBool("ExitBySignal", false)
	ad.InsertAttrString("Owner", "alice")
	return ad
}

// TestFeedKeepsTheOutcomeThatTheQueueDestroys is the whole point. The
// attributes that say HOW a job went exist in the queue only between the
// schedd writing them and DestroyProc removing the ad -- well under a
// second -- so a poll of the queue essentially never sees them. The
// stream does: the delete carries no ad, but the upsert before it
// carries the full one.
func TestFeedKeepsTheOutcomeThatTheQueueDestroys(t *testing.T) {
	f := warmFeed(t)
	// Running, then the terminal write, then gone -- the middle event
	// being the one a 30-second poll would miss.
	f.Apply(upsert("42.0", exitAd(42, 0, 2, 0)))
	f.Apply(upsert("42.0", exitAd(42, 0, 4, 3)))
	f.Apply(del("42.0"))

	got := f.Terminal("alice", time.Now().Add(-time.Hour))
	if len(got) != 1 {
		t.Fatalf("the terminal record was not kept: %+v", got)
	}
	code, _ := got[0].EvaluateAttrInt("ExitCode")
	if code != 3 {
		t.Errorf("ExitCode = %d, want the value from the last upsert before the delete", code)
	}

	// And it resolves succeeded/failed with no history table involved.
	w, err := New("alice", "l", "ClusterId == 42", EventFailed, "", ModeAny)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Evaluate(Snapshot{History: got}).Fires {
		t.Error("a failure observed on the stream should resolve without the archive")
	}
}

// TestFeedIgnoresADeleteItNeverSawStart: a delete for a job whose
// upserts predate this subscription carries nothing usable. Recording an
// empty terminal record would report an unknown outcome as a known one.
func TestFeedIgnoresADeleteItNeverSawStart(t *testing.T) {
	f := warmFeed(t)
	f.Apply(del("99.0"))
	if got := f.Terminal("alice", time.Now().Add(-time.Hour)); len(got) != 0 {
		t.Errorf("invented a terminal record from a bare delete: %+v", got)
	}
}

// TestFeedGoesColdWhenTheStreamDrops. A dropped stream means deletes
// went by unseen, and a terminal record that was never taken cannot be
// told apart from a job still running. Answering from that partial
// picture is worse than not answering, so the feed goes cold and
// contributes nothing until it is following again.
func TestFeedGoesColdWhenTheStreamDrops(t *testing.T) {
	f := warmFeed(t)
	f.Apply(upsert("42.0", exitAd(42, 0, 4, 0)))
	f.Apply(del("42.0"))
	if len(f.Terminal("alice", time.Now().Add(-time.Hour))) != 1 {
		t.Fatal("expected a terminal record while following")
	}

	f.Reset()
	if f.Warm() {
		t.Error("a dropped stream must leave the feed cold")
	}
	if got := f.Terminal("alice", time.Now().Add(-time.Hour)); len(got) != 0 {
		t.Errorf("a cold feed must contribute nothing, not a partial picture: %+v", got)
	}
}

// TestFeedForgetsAJobThatComesBack: a released hold, or a key reused
// after a compaction reload, re-upserts a key that had been deleted.
// Leaving the terminal record would report a running job as finished.
func TestFeedForgetsAJobThatComesBack(t *testing.T) {
	f := warmFeed(t)
	for _, c := range []WatchEvent{
		upsert("42.0", exitAd(42, 0, 5, 0)),
		del("42.0"),
		upsert("42.0", exitAd(42, 0, 2, 0)),
	} {
		f.Apply(c)
	}
	if got := f.Terminal("alice", time.Now().Add(-time.Hour)); len(got) != 0 {
		t.Errorf("a job that came back is still reported as ended: %+v", got)
	}
}

// TestFeedIsOwnerScoped: the stream carries every job on the access
// point, so the filter here is what keeps one user's outcomes out of
// another's watch.
func TestFeedIsOwnerScoped(t *testing.T) {
	f := warmFeed(t)
	bob := exitAd(7, 0, 4, 0)
	bob.InsertAttrString("Owner", "bob")
	for _, c := range []WatchEvent{
		upsert("42.0", exitAd(42, 0, 4, 0)), del("42.0"),
		upsert("7.0", bob), del("7.0"),
	} {
		f.Apply(c)
	}
	got := f.Terminal("alice", time.Now().Add(-time.Hour))
	if len(got) != 1 {
		t.Fatalf("expected only alice's job: %d", len(got))
	}
	if v, _ := got[0].EvaluateAttrString("Owner"); v != "alice" {
		t.Errorf("returned %q's job to alice", v)
	}
}

// TestColdFeedContributesNothing: before the first synced event the feed
// has an arbitrary partial view, and a missing terminal record there is
// indistinguishable from a job still running.
func TestColdFeedContributesNothing(t *testing.T) {
	f := NewFeed(nil)
	f.Apply(upsert("42.0", exitAd(42, 0, 4, 0)))
	f.Apply(del("42.0"))
	if f.Warm() {
		t.Error("a feed that has not synced is not warm")
	}
	if got := f.Terminal("alice", time.Now().Add(-time.Hour)); len(got) != 0 {
		t.Errorf("a cold feed answered: %+v", got)
	}
}

// TestFeedEvictsOldRecords bounds memory. An evicted record degrades to
// the history archive; it does not produce a wrong answer.
func TestFeedEvictsOldRecords(t *testing.T) {
	f := warmFeed(t)
	f.MaxEnded = 2
	for i := int64(0); i < 5; i++ {
		key := string(rune('a' + i))
		f.Apply(upsert(key, exitAd(42, i, 4, 0)))
		at := time.Now().Add(time.Duration(i) * time.Second)
		f.now = func() time.Time { return at }
		f.Apply(del(key))
	}
	if got := len(f.Terminal("alice", time.Time{})); got > 2 {
		t.Errorf("kept %d terminal records, want at most MaxEnded=2", got)
	}

	// And the TTL drops anything older than the lookback a watch uses.
	f2 := warmFeed(t)
	f2.EndedTTL = time.Minute
	f2.Apply(upsert("z", exitAd(42, 0, 4, 0)))
	f2.now = func() time.Time { return time.Now().Add(-time.Hour) }
	f2.Apply(del("z"))
	f2.now = time.Now
	// Any later event runs the eviction sweep.
	f2.Apply(upsert("y", exitAd(42, 1, 2, 0)))
	if got := f2.Terminal("alice", time.Time{}); len(got) != 0 {
		t.Errorf("a record older than the TTL was kept: %+v", got)
	}
}

// TestFeedSurvivesAnUnreadableUpsert: a row that will not parse must
// leave no record, so the delete that follows finds nothing and the job
// falls through to the history archive -- late, rather than wrong.
func TestFeedSurvivesAnUnreadableUpsert(t *testing.T) {
	f := warmFeed(t)
	f.Apply(WatchEvent{Kind: WatchUpsert, Key: "42.0", AdText: "this is not a ClassAd"})
	f.Apply(del("42.0"))
	if got := f.Terminal("alice", time.Time{}); len(got) != 0 {
		t.Errorf("an unparseable upsert produced a terminal record: %+v", got)
	}
}

// TestFeedResetDiscardsTheOldWorld: a reset event announces a full
// replay, so everything held describes a world that no longer applies.
func TestFeedResetDiscardsTheOldWorld(t *testing.T) {
	f := warmFeed(t)
	f.Apply(upsert("42.0", exitAd(42, 0, 4, 0)))
	f.Apply(del("42.0"))
	if len(f.Terminal("alice", time.Time{})) != 1 {
		t.Fatal("expected a terminal record before the reset")
	}
	f.Apply(WatchEvent{Kind: WatchReset})
	if got := f.Terminal("alice", time.Time{}); len(got) != 0 {
		t.Errorf("state survived a reset: %+v", got)
	}
}
