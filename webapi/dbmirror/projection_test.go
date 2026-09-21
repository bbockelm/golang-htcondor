package dbmirror

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// The mirror ad must be fetched in full. A QueryOptions carrying no
// Projection does not mean "everything": it falls back to the collector
// default, which is six machine-ad attributes and none of the ones this
// package parses.
func TestMirrorQueryAsksForEveryAttribute(t *testing.T) {
	proj := mirrorQueryOptions().GetEffectiveProjection(htcondor.DefaultCollectorProjection())
	if proj != nil {
		t.Errorf("the mirror query projects %v; it must request all attributes (nil), or the sync-health "+
			"attributes are stripped before ParseAd ever sees them", proj)
	}
}

// The failure this guards against, stated as the test that would have
// caught it: an ad reduced to the collector's default projection parses
// into an Info that reports no live-queue sync, no history sync and no
// time travel -- not as an error, but as confident zeroes.
func TestDefaultProjectionWouldStripEverythingParseAdReads(t *testing.T) {
	full := classad.New()
	full.InsertAttrString("MyType", AdType)
	full.InsertAttrString("Name", "db@ap2001")
	full.InsertAttrString("MyAddress", "<128.105.68.112:9618>")
	full.InsertAttrBool("JobQueueCaughtUp", false)
	full.InsertAttr("JobQueueLagBytes", int64(1671914))
	full.InsertAttr("JobQueueLastSyncTime", int64(1790001757))
	full.InsertAttr("JobQueueSecondsSinceSync", int64(17))
	full.InsertAttrBool("TimeTravelEnabled", true)

	if got := ParseAd(full); !got.JobQueueReported || !got.TimeTravelEnabled {
		t.Fatalf("the unprojected ad should parse completely: JobQueueReported=%v TimeTravelEnabled=%v",
			got.JobQueueReported, got.TimeTravelEnabled)
	}

	// Now the same ad as the collector would have returned it under the
	// default projection.
	reduced := classad.New()
	for _, attr := range htcondor.DefaultCollectorProjection() {
		if v, ok := full.EvaluateAttrString(attr); ok {
			reduced.InsertAttrString(attr, v)
		}
	}
	got := ParseAd(reduced)
	if got.Address == "" {
		t.Fatal("MyAddress is in the default projection, so routing kept working -- which is why this hid")
	}
	if got.JobQueueReported {
		t.Error("the reduced ad cannot report live-queue sync")
	}
	if got.TimeTravelEnabled {
		t.Error("the reduced ad cannot report time travel")
	}
}
