package issues

import (
	"context"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Records from a federation hub carry ScheddName; two APs' 1.0 are two
// jobs.

// TestAHoldOnOneAPDoesNotHideTheSameIDsHoldOnAnother: the held-now
// deduplication keys on the AP too.
func TestAHoldOnOneAPDoesNotHideTheSameIDsHoldOnAnother(t *testing.T) {
	src := &fakeSource{
		jobs: []*classad.ClassAd{
			ad(t, `[ ScheddName = "ap1"; ClusterId = 1; ProcId = 0; Owner = "derek"; HoldReason = "Job credentials are not available"; HoldReasonCode = 4; EnteredCurrentStatus = 900 ]`),
		},
		epochs: []*classad.ClassAd{
			ad(t, `[ ScheddName = "ap2"; ClusterId = 1; ProcId = 0; Owner = "derek"; VacateReason = "Job credentials are not available"; VacateReasonCode = 4; EpochWriteDate = 900 ]`),
		},
	}
	set, err := Collect(context.Background(), src, Options{Window: time.Hour, IncludeEnded: true,
		Now: func() time.Time { return time.Unix(1000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Records) != 2 {
		t.Fatalf("records = %d, want 1.0 on ap1 and 1.0 on ap2", len(set.Records))
	}
	c := NewClusterer()
	for _, r := range set.Records {
		c.Add(r)
	}
	clusters := c.Clusters(RenderOptions{Granularity: 0.5})
	if len(clusters) != 1 || len(clusters[0].Schedds) != 2 {
		t.Fatalf("clusters %+v: want one problem spread over both APs", clusters)
	}
	for _, ex := range clusters[0].Examples {
		if ex.Schedd == "" {
			t.Errorf("example %+v has no AP", ex)
		}
	}
}
