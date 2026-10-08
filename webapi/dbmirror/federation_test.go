package dbmirror

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func spokeAd(t *testing.T, name, addr, schedd string, syncing, caughtUp bool, extra string) *classad.ClassAd {
	t.Helper()
	text := "MyType = \"HTCondorDB\"\nName = \"" + name + "\"\nMyAddress = \"" + addr + "\""
	if schedd != "" {
		text += "\nMirroredScheddName = \"" + schedd + "\"\nMirroredScheddAddress = \"<" + schedd + ":9618>\""
	}
	if syncing {
		text += "\nSyncing = true"
	}
	if caughtUp {
		text += "\nJobQueueCaughtUp = true"
	} else {
		text += "\nJobQueueCaughtUp = false"
	}
	if extra != "" {
		text += "\n" + extra
	}
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

func TestParseAdFederationFields(t *testing.T) {
	info := ParseAd(spokeAd(t, "db1", "<1:1>", "ap1.example.org", true, true, `FederationConstraint = "true"`))
	if info.MirroredScheddName != "ap1.example.org" || info.MirroredScheddAddress != "<ap1.example.org:9618>" ||
		!info.Syncing || info.FederationConstraint != "true" {
		t.Errorf("ParseAd = %+v", info)
	}
	for _, a := range []string{"MirroredScheddName", "MirroredScheddAddress", "FederationConstraint", "Syncing"} {
		found := false
		for _, p := range mirrorAdAttrs() {
			found = found || p == a
		}
		if !found {
			t.Errorf("mirrorAdAttrs lacks %s", a)
		}
	}
}

func TestPickSpokesPairsByMirroredName(t *testing.T) {
	ads := []*classad.ClassAd{
		spokeAd(t, "db-ap1", "<10.0.0.1:1>", "ap1.example.org", true, true, ""),
		// A spoke on a different host than its schedd: pairing is by name.
		spokeAd(t, "db-ap2", "<10.9.9.9:1>", "AP2.example.org", true, false, ""),
		// No schedd named: not a spoke.
		spokeAd(t, "db-plain", "<10.0.0.3:1>", "", true, true, ""),
		// A hub is never a spoke, whatever it says.
		spokeAd(t, "hub", "<10.0.0.4:1>", "ap4.example.org", true, true, `FederationConstraint = "true"`),
		// No address: unusable.
		spokeAd(t, "db-noaddr", "", "ap5.example.org", true, true, ""),
		// HA pair, one current: it wins. A caught-up spoke that is not
		// syncing is not current.
		spokeAd(t, "db-ap6-a", "<10.0.0.6:1>", "ap6.example.org", false, true, ""),
		spokeAd(t, "db-ap6-b", "<10.0.0.7:1>", "ap6.example.org", true, true, ""),
		// HA pair, both current: declined, not guessed.
		spokeAd(t, "db-ap7-a", "<10.0.0.8:1>", "ap7.example.org", true, true, ""),
		spokeAd(t, "db-ap7-b", "<10.0.0.9:1>", "ap7.example.org", true, true, ""),
	}
	by, declined := PickSpokes(ads)
	set := &SpokeSet{bySchedd: by, Declined: declined}
	if got := set.For("ap1.example.org"); got == nil || got.Name != "db-ap1" {
		t.Errorf("ap1 -> %+v", got)
	}
	if got := set.For("ap2.example.org"); got == nil || got.Name != "db-ap2" {
		t.Errorf("ap2 (case-insensitive) -> %+v", got)
	}
	for _, n := range []string{"ap4.example.org", "ap5.example.org", "ap7.example.org", ""} {
		if got := set.For(n); got != nil {
			t.Errorf("%q -> %+v, want none", n, got)
		}
	}
	if got := set.For("ap6.example.org"); got == nil || got.Name != "db-ap6-b" {
		t.Errorf("ap6 -> %+v, want the caught-up one", got)
	}
	if !strings.Contains(declined["ap7.example.org"], "not guessing") {
		t.Errorf("declined = %v", declined)
	}
	if names := set.Names(); len(names) != 3 {
		t.Errorf("Names = %v", names)
	}
	if spokeQueryOptions().Limit != -1 {
		t.Error("spoke discovery must ask for every ad (Limit -1)")
	}
}
