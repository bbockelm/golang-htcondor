package htcondor

import (
	"strconv"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// The placementd's audit log: one PlacementModification per entity touched by
// a committed PLACEMENT_EDIT batch or a mapfile reload. Query it with
// TargetType PlacementTargetModification, optionally narrowed by EntityID;
// results come newest first.

// Channels a modification can arrive through.
const (
	// PlacementChannelCedar is a PLACEMENT_EDIT batch.
	PlacementChannelCedar = "cedar"
	// PlacementChannelMapfile is a mapfile reload.
	PlacementChannelMapfile = "mapfile"
	// PlacementChannelMigration is the one-time import of rows that
	// existed before the audit log did.
	PlacementChannelMigration = "migration"
)

// PlacementFieldChange is one field's value before and after a modification.
// Old and New hold string, int64, float64, bool, []string, []any (a list of
// mixed values), or nil for undefined (absent before, or cleared).
type PlacementFieldChange struct {
	Old any
	New any
}

// PlacementModification is one audit-log entry: one entity changed by one
// change set.
type PlacementModification struct {
	// ID is the modification's id. An entity's Version is the ID of its
	// latest modification.
	ID int64
	// ChangesetID groups the modifications one batch or reload made.
	ChangesetID int64
	Time        time.Time
	// Channel is one of the PlacementChannel* constants.
	Channel string
	// Actor is the authenticated peer for a PLACEMENT_EDIT batch, or
	// "mapfile" / "migration".
	Actor string
	// OnBehalfOf is the person the peer said it acted for. It is
	// recorded, not verified.
	OnBehalfOf  string
	PeerAddress string
	Comment     string
	// Operation is create, update, delete, adopt, reclaim or handoff.
	Operation string
	// EntityType is identity, account, project or authorization.
	EntityType string
	// EntityID is the entity's uuid; it outlives a deleted entity.
	EntityID string
	// Changes maps each changed field to its old and new value. An adopt
	// changes no fields.
	Changes map[string]PlacementFieldChange
}

func decodePlacementModification(ad *classad.ClassAd) *PlacementModification {
	m := &PlacementModification{}
	m.ID = placementInt(ad, "Id")
	m.ChangesetID = placementInt(ad, "ChangesetId")
	m.Time = placementUnix(ad, "Time")
	m.Channel, _ = ad.EvaluateAttrString("Channel")
	m.Actor, _ = ad.EvaluateAttrString("Actor")
	m.OnBehalfOf, _ = ad.EvaluateAttrString("OnBehalfOf")
	m.PeerAddress, _ = ad.EvaluateAttrString("PeerAddress")
	m.Comment, _ = ad.EvaluateAttrString("Comment")
	m.Operation, _ = ad.EvaluateAttrString("Operation")
	m.EntityType, _ = ad.EvaluateAttrString("EntityType")
	m.EntityID, _ = ad.EvaluateAttrString("EntityId")

	m.Changes = map[string]PlacementFieldChange{}
	changes, err := ad.EvaluateAttr("Changes").ClassAdValue()
	if err != nil || changes == nil {
		return m
	}
	for _, field := range changes.GetAttributes() {
		v := changes.EvaluateAttr(field)
		switch {
		case v.IsList():
			// The design's form: Field = { old, new }.
			pair, err := v.ListValue()
			if err != nil || len(pair) != 2 {
				continue
			}
			m.Changes[field] = PlacementFieldChange{Old: placementGoValue(pair[0]), New: placementGoValue(pair[1])}
		case v.IsClassAd():
			// Also accept [ Old = ...; New = ... ].
			inner, err := v.ClassAdValue()
			if err != nil || inner == nil {
				continue
			}
			m.Changes[field] = PlacementFieldChange{
				Old: placementGoValue(inner.EvaluateAttr("Old")),
				New: placementGoValue(inner.EvaluateAttr("New")),
			}
		}
	}
	return m
}

// placementInt reads an integer attribute, accepting a numeric string too.
func placementInt(ad *classad.ClassAd, attr string) int64 {
	if v, ok := ad.EvaluateAttrInt(attr); ok {
		return v
	}
	if s, ok := ad.EvaluateAttrString(attr); ok {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			return v
		}
	}
	return 0
}

// placementGoValue converts a ClassAd value to plain Go. A list of strings
// becomes []string; any other list becomes []any.
func placementGoValue(v classad.Value) any {
	switch {
	case v.IsUndefined(), v.IsError():
		return nil
	case v.IsBool():
		b, _ := v.BoolValue()
		return b
	case v.IsInteger():
		i, _ := v.IntValue()
		return i
	case v.IsReal():
		f, _ := v.RealValue()
		return f
	case v.IsString():
		s, _ := v.StringValue()
		return s
	case v.IsList():
		elems, err := v.ListValue()
		if err != nil {
			return nil
		}
		strs := make([]string, 0, len(elems))
		mixed := make([]any, 0, len(elems))
		allStrings := true
		for _, e := range elems {
			g := placementGoValue(e)
			mixed = append(mixed, g)
			if s, ok := g.(string); ok {
				strs = append(strs, s)
			} else {
				allStrings = false
			}
		}
		if allStrings {
			return strs
		}
		return mixed
	}
	return nil
}
