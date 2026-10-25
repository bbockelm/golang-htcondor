package mcpserver

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// windowMirror is an archive holding three jobs submitted at q: 11 and 12
// as the mirror would stamp them, and 10 stamped two days before it was
// submitted, which the mirror never does. A QDate window matches all
// three as written; 10 is missing from an answer only if the read
// restated the window on EnteredHistoryTime.
func windowMirror(t *testing.T, q int64) *dbrpc.Client {
	t.Helper()
	hub := multiaptest.NewHub(t)
	dbc, closer, err := hub.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closer)
	for _, r := range []struct{ cluster, entered int64 }{{10, q - 2*86400}, {11, q + 100}, {12, q + 200}} {
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = \"alice\"\nJobStatus = 4\nQDate = %d\nEnteredHistoryTime = %d",
			r.cluster, q, r.entered)
		if err := dbc.ArchiveAppend(context.Background(), "history", ad); err != nil {
			t.Fatal(err)
		}
	}
	return dbc
}

func TestMirrorHistoryReadsRestateTheWindow(t *testing.T) {
	const q = 1757000000
	window := fmt.Sprintf("QDate >= %d && QDate < %d", q, q+86400)
	want := []int64{11, 12}
	dbc := windowMirror(t, q)

	records, _, d := readMirrorHistory(context.Background(), dbc, window, []string{"ClusterId"}, 10)
	if !d.Use {
		t.Fatalf("readMirrorHistory declined: %+v", d)
	}
	if got := sortedClusters(t, records); !slices.Equal(got, want) {
		t.Errorf("readMirrorHistory: clusters %v, want %v", got, want)
	}

	rows, _, err := queryHistoryArchive(context.Background(), dbc, window, []string{"ClusterId"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	var ads []*classad.ClassAd
	for _, r := range rows {
		ad, err := classad.ParseOld(r)
		if err != nil {
			t.Fatal(err)
		}
		ads = append(ads, ad)
	}
	if got := sortedClusters(t, ads); !slices.Equal(got, want) {
		t.Errorf("queryHistoryArchive: clusters %v, want %v", got, want)
	}
}

func sortedClusters(t *testing.T, records []*classad.ClassAd) []int64 {
	t.Helper()
	out := clusters(t, records)
	slices.Sort(out)
	return out
}
