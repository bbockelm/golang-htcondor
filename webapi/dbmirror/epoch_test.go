package dbmirror

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// epochAd builds a mirror advertisement carrying epoch-history sync health,
// the way htcondordb's dbad package publishes it.
func epochAd(t *testing.T, attrs map[string]any) *classad.ClassAd {
	t.Helper()
	ad := classad.New()
	ad.InsertAttrString("Name", "htcondordb@ap.example.org")
	ad.InsertAttrString("MyAddress", "<10.0.0.1:9618?sock=htcondordb>")
	for k, v := range attrs {
		switch val := v.(type) {
		case bool:
			ad.InsertAttrBool(k, val)
		case int64:
			ad.InsertAttr(k, val)
		case string:
			ad.InsertAttrString(k, val)
		default:
			t.Fatalf("unsupported attr type for %s", k)
		}
	}
	return ad
}

// TestEpochDecisionServesACaughtUpMirror is the case the whole addition exists
// for: transfer records live in JOB_EPOCH_HISTORY, so a consumer reading them
// needs to know whether that source is drained -- which the ad reports and
// nothing here previously parsed.
func TestEpochDecisionServesACaughtUpMirror(t *testing.T) {
	info := ParseAd(epochAd(t, map[string]any{
		"EpochCaughtUp":         true,
		"EpochSecondsSinceSync": int64(3),
		"EpochLagBytes":         int64(0),
		"EpochGapDetected":      false,
	}))
	if !info.EpochReported {
		t.Fatal("EpochReported false for an ad that carries EpochCaughtUp")
	}
	if d := EpochDecision(info); !d.Use {
		t.Errorf("declined a caught-up mirror: %s (%s)", d.Reason, d.Note)
	}
}

// TestEpochDecisionDeclinesAMirrorThatDoesNotTailEpochs: a mirror syncing only
// job_queue.log and history advertises none of the Epoch attributes. Those parse
// to false/0, which without the reported flag is indistinguishable from "caught
// up, no lag" -- the same trap JobQueueReported exists for.
func TestEpochDecisionDeclinesAMirrorThatDoesNotTailEpochs(t *testing.T) {
	info := ParseAd(epochAd(t, map[string]any{
		"JobQueueCaughtUp": true, // syncs the queue, but not epochs
	}))
	if info.EpochReported {
		t.Fatal("EpochReported true for an ad with no Epoch attributes")
	}
	d := EpochDecision(info)
	if d.Use {
		t.Error("served epoch reads from a mirror that does not tail JOB_EPOCH_HISTORY")
	}
	if d.Reason != ReasonNoMirror {
		t.Errorf("Reason = %q, want %q", d.Reason, ReasonNoMirror)
	}
}

func TestEpochDecisionDeclinesOnGapAndStaleness(t *testing.T) {
	gap := ParseAd(epochAd(t, map[string]any{
		"EpochCaughtUp":    true,
		"EpochGapDetected": true,
	}))
	if d := EpochDecision(gap); d.Use || d.Reason != ReasonHistoryGap {
		t.Errorf("gap: Use=%v Reason=%q", d.Use, d.Reason)
	}

	stale := ParseAd(epochAd(t, map[string]any{
		"EpochCaughtUp":         true,
		"EpochSecondsSinceSync": EpochToleranceSecs + 1,
	}))
	if d := EpochDecision(stale); d.Use || d.Reason != ReasonStale {
		t.Errorf("stale: Use=%v Reason=%q", d.Use, d.Reason)
	}

	behind := ParseAd(epochAd(t, map[string]any{
		"EpochCaughtUp": false,
		"EpochLagBytes": int64(4096),
	}))
	if d := EpochDecision(behind); d.Use || d.Reason != ReasonNotCaughtUp {
		t.Errorf("behind: Use=%v Reason=%q", d.Use, d.Reason)
	}
}

// TestCaughtUpLagBytesLeeway: the knob lets a consumer accept a syncer that is a
// little behind rather than only one that reached EOF. Default zero keeps the
// strict behavior, which is what routing had before this existed.
func TestCaughtUpLagBytesLeeway(t *testing.T) {
	behind := ParseAd(epochAd(t, map[string]any{
		"EpochCaughtUp": false,
		"EpochLagBytes": int64(4096),
	}))

	if d := EpochDecision(behind); d.Use {
		t.Error("a 4 KB lag was accepted with the default (strict) tolerance")
	}

	old := CaughtUpLagBytes
	t.Cleanup(func() { CaughtUpLagBytes = old })

	CaughtUpLagBytes = 10 << 10 // 10 KB
	if d := EpochDecision(behind); !d.Use {
		t.Errorf("a 4 KB lag was declined under a 10 KB tolerance: %s", d.Note)
	}

	// Still bounded: past the tolerance it declines again.
	wayBehind := ParseAd(epochAd(t, map[string]any{
		"EpochCaughtUp": false,
		"EpochLagBytes": int64(1 << 20),
	}))
	if d := EpochDecision(wayBehind); d.Use {
		t.Error("a 1 MB lag passed a 10 KB tolerance")
	}
}

// TestLagLeewayIgnoresMirrorsThatDoNotReportIt is the absent-versus-zero trap
// again, now for the byte tolerance: an older mirror advertises no EpochLagBytes,
// which parses to 0 and would otherwise look like a perfectly drained syncer the
// moment anyone widened the tolerance.
func TestLagLeewayIgnoresMirrorsThatDoNotReportIt(t *testing.T) {
	old := CaughtUpLagBytes
	t.Cleanup(func() { CaughtUpLagBytes = old })
	CaughtUpLagBytes = 10 << 10

	noLag := ParseAd(epochAd(t, map[string]any{
		"EpochCaughtUp": false, // reports the flag, but not the byte count
	}))
	if noLag.EpochLagReported {
		t.Fatal("EpochLagReported true for an ad with no EpochLagBytes")
	}
	if d := EpochDecision(noLag); d.Use {
		t.Error("a mirror that reports no lag was treated as zero bytes behind")
	}
}

// TestLeewayAppliesToTheLiveQueueToo: the same knob governs JobsDecision, so a
// consumer that widens it gets consistent behavior across sources rather than
// one gate quietly stricter than the other.
func TestLeewayAppliesToTheLiveQueueToo(t *testing.T) {
	behind := ParseAd(epochAd(t, map[string]any{
		"JobQueueCaughtUp":         false,
		"JobQueueLagBytes":         int64(2048),
		"JobQueueSecondsSinceSync": int64(1),
	}))
	if d := JobsDecision(behind, ""); d.Use {
		t.Error("live queue accepted a 2 KB lag with the default tolerance")
	}

	old := CaughtUpLagBytes
	t.Cleanup(func() { CaughtUpLagBytes = old })
	CaughtUpLagBytes = 10 << 10
	if d := JobsDecision(behind, ""); !d.Use {
		t.Errorf("live queue declined a 2 KB lag under a 10 KB tolerance: %s", d.Note)
	}
}
