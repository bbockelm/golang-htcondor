package htcondor

import (
	"reflect"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestPlacementdQueryModifications(t *testing.T) {
	f := newFakePlacementdV2(t, []*classad.ClassAd{
		mustParseAd(t, `[MyType = "PlacementModification"; Id = 42; ChangesetId = 17; Time = 1760000000;
			Channel = "cedar"; Actor = "condor@ap.example"; OnBehalfOf = "alice"; PeerAddress = "<10.0.0.5:9618>";
			Comment = "new course"; Operation = "update"; EntityType = "account"; EntityId = "a-uuid";
			Changes = [ Projects = { {"A"}, {"A", "B"} }; DefaultProject = { undefined, "A" };
			            Requestable = { 0, 1 }; ExpiresAt = { 1767225600, undefined } ]]`),
		mustParseAd(t, `[MyType = "PlacementModification"; Id = 7; ChangesetId = 1; Time = 1750000000;
			Channel = "mapfile"; Actor = "mapfile"; Operation = "adopt"; EntityType = "account"; EntityId = "a-uuid";
			Changes = [ ]]`),
		summaryAd(t),
	}, nil)

	objs, err := NewPlacementd(f.addr).Query(placementTestContext(t), PlacementQuery{
		TargetType: PlacementTargetModification,
		EntityID:   "a-uuid",
		Limit:      20,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got, _ := f.queryReq.EvaluateAttrString("TargetType"); got != "Modification" {
		t.Errorf("TargetType = %q", got)
	}
	if got, _ := f.queryReq.EvaluateAttrString("EntityId"); got != "a-uuid" {
		t.Errorf("EntityId = %q", got)
	}
	if got, _ := f.queryReq.EvaluateAttrInt("Limit"); got != 20 {
		t.Errorf("Limit = %d", got)
	}

	if len(objs) != 2 || objs[0].Modification == nil || objs[1].Modification == nil {
		t.Fatalf("objs = %+v", objs)
	}
	m := objs[0].Modification
	if m.ID != 42 || m.ChangesetID != 17 || m.Time.Unix() != 1760000000 || m.Channel != PlacementChannelCedar ||
		m.Actor != "condor@ap.example" || m.OnBehalfOf != "alice" || m.PeerAddress != "<10.0.0.5:9618>" ||
		m.Comment != "new course" || m.Operation != "update" || m.EntityType != "account" || m.EntityID != "a-uuid" {
		t.Errorf("modification = %+v", m)
	}
	want := map[string]PlacementFieldChange{
		"Projects":       {Old: []string{"A"}, New: []string{"A", "B"}},
		"DefaultProject": {Old: nil, New: "A"},
		"Requestable":    {Old: int64(0), New: int64(1)},
		"ExpiresAt":      {Old: int64(1767225600), New: nil},
	}
	if !reflect.DeepEqual(m.Changes, want) {
		t.Errorf("Changes = %#v\nwant      %#v", m.Changes, want)
	}
	if adopt := objs[1].Modification; adopt.Operation != "adopt" || len(adopt.Changes) != 0 || adopt.Changes == nil {
		t.Errorf("adopt = %+v", adopt)
	}
}

// Old/New as a nested ad is accepted too.
func TestPlacementModificationNestedAdChange(t *testing.T) {
	m := decodePlacementModification(mustParseAd(t, `[Id = "9"; Changes = [ Label = [ Old = "Read"; New = "Read only" ] ]]`))
	if m.ID != 9 {
		t.Errorf("ID = %d", m.ID)
	}
	if got := m.Changes["Label"]; got.Old != "Read" || got.New != "Read only" {
		t.Errorf("Label = %+v", got)
	}
}

func TestPlacementEntityModificationID(t *testing.T) {
	obj := decodePlacementObject(mustParseAd(t,
		`[MyType = "PlacementProject"; Id = "p1"; Version = 42; ModificationId = 42; Name = "ProjA"]`), "")
	if obj.Project == nil || obj.Project.ModificationID != 42 || obj.Project.Version != 42 {
		t.Errorf("project = %+v", obj.Project)
	}
}
