package dbmirror

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestNeverSyncedSourceIsNotServed guards the failure mode where a mirror answers confidently
// about a source it never read.
//
// htcondordb creates a tailer for each of the three schedd files whether or not the daemon was
// pointed at one, and a tailer that has never opened its file reports CaughtUp = true with a zero
// lag -- truthfully, in that it is not behind anything. Read as a routing signal that says "serve
// from the mirror", and the mirror then serves an empty table as if it were the answer: no
// completed jobs, no transfers. The read succeeds, so nothing anywhere reports an error.
//
// The attribute that separates the two cases is LastSyncTime, which htcondordb writes only once a
// sync has actually completed. The ads below are the shapes a real daemon produces.
func TestNeverSyncedSourceIsNotServed(t *testing.T) {
	const base = `MyType = "HTCondorDB"; Name = "db@h"; MyAddress = "<127.0.0.1:1>"; `

	cases := []struct {
		name    string
		attrs   string
		decide  func(*Info) Decision
		wantUse bool
		wantWhy Reason
	}{
		{
			name:    "history never synced",
			attrs:   `HistoryCaughtUp = true; HistoryFileSize = 0; HistoryOffset = 0; HistoryGapDetected = false; HistoryLagBytes = 0`,
			decide:  func(i *Info) Decision { return HistoryDecision(i, nil) },
			wantUse: false, wantWhy: ReasonNeverSynced,
		},
		{
			name:    "history synced",
			attrs:   `HistoryCaughtUp = true; HistoryLastSyncTime = 1700000000; HistorySecondsSinceSync = 1; HistoryGapDetected = false; HistoryLagBytes = 0`,
			decide:  func(i *Info) Decision { return HistoryDecision(i, nil) },
			wantUse: true, wantWhy: ReasonServed,
		},
		{
			name:    "epoch never synced",
			attrs:   `EpochCaughtUp = true; EpochFileSize = 0; EpochOffset = 0; EpochGapDetected = false; EpochLagBytes = 0`,
			decide:  EpochDecision,
			wantUse: false, wantWhy: ReasonNeverSynced,
		},
		{
			name:    "epoch synced",
			attrs:   `EpochCaughtUp = true; EpochLastSyncTime = 1700000000; EpochSecondsSinceSync = 1; EpochGapDetected = false; EpochLagBytes = 0`,
			decide:  EpochDecision,
			wantUse: true, wantWhy: ReasonServed,
		},
		{
			name:    "job queue never synced",
			attrs:   `JobQueueCaughtUp = true; JobQueueFileSize = 0; JobQueueOffset = 0; JobQueueLagBytes = 0`,
			decide:  func(i *Info) Decision { return JobsDecision(i, "") },
			wantUse: false, wantWhy: ReasonNeverSynced,
		},
		{
			name:    "job queue synced",
			attrs:   `JobQueueCaughtUp = true; JobQueueLastSyncTime = 1700000000; JobQueueSecondsSinceSync = 1; JobQueueLagBytes = 0`,
			decide:  func(i *Info) Decision { return JobsDecision(i, "") },
			wantUse: true, wantWhy: ReasonServed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ad, err := classad.Parse("[ " + base + tc.attrs + " ]")
			if err != nil {
				t.Fatal(err)
			}
			d := tc.decide(ParseAd(ad))
			if d.Use != tc.wantUse || d.Reason != tc.wantWhy {
				t.Errorf("decision = {Use:%v Reason:%q Note:%q}, want {Use:%v Reason:%q}",
					d.Use, d.Reason, d.Note, tc.wantUse, tc.wantWhy)
			}
		})
	}
}
