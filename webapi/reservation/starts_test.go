package reservation

import (
	"context"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func startAd(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatalf("ParseOld(%q): %v", text, err)
	}
	return ad
}

// TestStartsFromAdsKeepsTheExpression is the property the whole
// provisioning path rests on: START must come back as its text, not as
// the true/false it evaluates to. Composing against "false" would leave
// a machine admitting nothing for the life of the startd, with no way to
// take the attribute back.
func TestStartsFromAdsKeepsTheExpression(t *testing.T) {
	ad := startAd(t, "Machine = \"wn1.example\"\nName = \"slot1@wn1.example\"\nPartitionableSlot = true\nSTART = Owner =?= \"alice\"\n")
	got := StartsFromAds([]*classad.ClassAd{ad})
	if len(got) != 1 {
		t.Fatalf("got %d machines, want 1: %v", len(got), got)
	}
	expr := got["wn1.example"]
	if !strings.Contains(expr, "alice") {
		t.Errorf("START came back as %q, want the expression text", expr)
	}
	if expr == "true" || expr == "false" {
		t.Errorf("START came back evaluated as %q", expr)
	}
}

// TestStartsFromAdsPrefersThePartitionableSlot: a dynamic slot's START
// can be narrowed by the job on it; the p-slot's is what governs
// admission.
func TestStartsFromAdsPrefersThePartitionableSlot(t *testing.T) {
	dyn := startAd(t, "Machine = \"wn1\"\nName = \"slot1_1@wn1\"\nDynamicSlot = true\nSTART = False\n")
	part := startAd(t, "Machine = \"wn1\"\nName = \"slot1@wn1\"\nPartitionableSlot = true\nSTART = Owner =?= \"alice\"\n")
	for _, order := range [][]*classad.ClassAd{{dyn, part}, {part, dyn}} {
		got := StartsFromAds(order)
		if !strings.Contains(got["wn1"], "alice") {
			t.Errorf("got %q, want the partitionable slot's START whichever order the ads arrive in", got["wn1"])
		}
	}
}

func TestStartsFromAdsSkipsUnusableAds(t *testing.T) {
	ads := []*classad.ClassAd{
		nil,
		startAd(t, "Name = \"slot1@nomachine\"\nSTART = True\n"),              // no Machine
		startAd(t, "Machine = \"wn2\"\nName = \"slot1@wn2\"\n"),               // no START
		startAd(t, "Machine = \"wn3\"\nName = \"slot1@wn3\"\nSTART = \"\"\n"), // empty START
	}
	if got := StartsFromAds(ads); len(got) != 0 {
		t.Errorf("got %v, want nothing usable", got)
	}
}

func TestCollectorStartsSendsTheSiteConstraint(t *testing.T) {
	q := &fakeQuerier{}
	src := CollectorStarts{Query: q, Only: "TeachingNode =?= True"}
	if _, err := src.Starts(context.Background()); err != nil {
		t.Fatalf("Starts: %v", err)
	}
	if !strings.Contains(q.constraint, "TeachingNode") {
		t.Errorf("the site expression did not reach the collector: %q", q.constraint)
	}
	if !strings.Contains(q.constraint, "BackfillSlot") {
		t.Errorf("the census constraint was lost: %q", q.constraint)
	}
}
