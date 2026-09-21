package dbmirror

import (
	"reflect"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// Every attribute ParseAd reads has to be in the projection. One that is
// not parses as absent rather than failing, which is indistinguishable
// from the mirror not advertising it -- so this fills an ad from the
// projection alone and requires ParseAd to populate all of Info from it.
// A new read added without a matching projection entry leaves its field
// zero here.
func TestProjectionCoversEverythingParseAdReads(t *testing.T) {
	// A non-zero value per projected attribute, so a populated field is
	// distinguishable from an unset one.
	values := map[string]any{
		"Name": "db@ap2001", "MyAddress": "<128.105.68.112:9618>",
		"TimeTravelEnabled":  true,
		"HistoryGapDetected": true, "HistoryLastSyncTime": int64(1790001700),
		"HistorySecondsSinceSync": int64(9), "HistoryLagBytes": int64(4096),
		"JobQueueCaughtUp": true, "JobQueueLastSyncTime": int64(1790001757),
		"JobQueueSecondsSinceSync": int64(17), "JobQueueLagBytes": int64(1671914),
		"EpochCaughtUp": true, "EpochGapDetected": true, "EpochLastSyncTime": int64(1790001710),
		"EpochSecondsSinceSync": int64(11), "EpochLagBytes": int64(512),
	}

	ad := classad.New()
	for _, attr := range mirrorAdAttrs() {
		v, ok := values[attr]
		if !ok {
			t.Fatalf("%s is projected but this test has no value for it; add one so the field it fills is checked", attr)
		}
		switch x := v.(type) {
		case bool:
			ad.InsertAttrBool(attr, x)
		case int64:
			ad.InsertAttr(attr, x)
		case string:
			ad.InsertAttrString(attr, x)
		}
	}

	info := reflect.ValueOf(*ParseAd(ad))
	for i := 0; i < info.NumField(); i++ {
		if info.Field(i).IsZero() {
			t.Errorf("Info.%s came out zero: ParseAd reads an attribute that mirrorAdAttrs does not name",
				info.Type().Field(i).Name)
		}
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
