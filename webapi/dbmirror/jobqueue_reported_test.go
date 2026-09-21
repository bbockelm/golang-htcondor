package dbmirror

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// A mirror that syncs the live queue advertises JobQueueCaughtUp; a
// history-only mirror does not. Without distinguishing "the ad said
// nothing about the live queue" from "the live queue is caught up at 0s
// of lag", the /info panel rendered a history-only mirror as "0s behind
// ... behind the schedd's job_queue.log" -- fresh and stale at once.
func TestParseAdRecordsWhetherLiveQueueWasReported(t *testing.T) {
	withQueue := classad.New()
	_ = withQueue.Set("JobQueueCaughtUp", true)
	_ = withQueue.Set("JobQueueSecondsSinceSync", int64(0))
	if info := ParseAd(withQueue); !info.JobQueueReported {
		t.Error("an ad carrying JobQueueCaughtUp must report the live queue")
	}

	historyOnly := classad.New()
	_ = historyOnly.Set("HistorySecondsSinceSync", int64(3))
	info := ParseAd(historyOnly)
	if info.JobQueueReported {
		t.Error("an ad with no JobQueueCaughtUp must NOT report the live queue")
	}
	// The zero values are still present; the flag is the only thing that
	// separates them from a real 0.
	if info.JobQueueCaughtUp || info.JobQueueSecondsSync != 0 {
		t.Errorf("history-only ad parsed unexpected live-queue values: %+v", info)
	}
}

// The distinction has to reach the health JSON: staleness is omitted
// (nil) for a history-only mirror so the panel shows "not reported"
// rather than a zero-value "0s behind".
func TestReportedFlagDrivesStalenessPresence(t *testing.T) {
	// This mirrors what mirrorHealth does; kept here so the dbmirror
	// package owns the invariant its Info exposes.
	historyOnly := ParseAd(classad.New())
	if historyOnly.JobQueueReported {
		t.Fatal("an empty ad must not report the live queue")
	}
}

// The same distinction for history, which had no flag at all: the panel
// rendered HistoryStaleness unconditionally, so an ad carrying no history
// figures produced a confident "0s behind" -- the exact reading
// JobQueueReported exists to prevent, on the row next to it.
func TestParseAdRecordsWhetherHistoryWasReported(t *testing.T) {
	withHistory := classad.New()
	_ = withHistory.Set("HistoryCaughtUp", true)
	_ = withHistory.Set("HistorySecondsSinceSync", int64(9))
	if info := ParseAd(withHistory); !info.HistoryReported {
		t.Error("an ad carrying HistoryCaughtUp must report history sync")
	}

	queueOnly := classad.New()
	_ = queueOnly.Set("JobQueueCaughtUp", true)
	info := ParseAd(queueOnly)
	if info.HistoryReported {
		t.Error("an ad with no HistoryCaughtUp must NOT report history sync")
	}
	// As above: the zero values are there, and the flag is the only thing
	// separating them from a measured 0.
	if info.SecondsSinceSync != 0 || info.HistoryLastSyncTime != 0 {
		t.Errorf("queue-only ad parsed unexpected history values: %+v", info)
	}
}
