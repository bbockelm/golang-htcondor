package httpserver

import (
	"net/http"
	"strconv"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// The placementd's audit log, read through PLACEMENT_QUERY with TargetType
// Modification:
//
//	GET /api/v1/placement/admin/history?entity_id=&constraint=&limit=
//	GET /api/v1/placement/admin/{kind}/{id}/history?limit=
//
// Both are admin-only and need API version 2, like the rest of the
// directory; handlePlacementAdmin has checked both before routing here.

const (
	placementHistoryDefaultLimit = 100
	placementHistoryMaxLimit     = 1000
)

// placementFieldChangeJSON is one field's value before and after a change.
// A null means absent before (a create) or cleared after.
type placementFieldChangeJSON struct {
	Old any `json:"old"`
	New any `json:"new"`
}

// placementModificationJSON is one history entry.
type placementModificationJSON struct {
	ID          int64      `json:"id"`
	ChangesetID int64      `json:"changeset_id"`
	Time        *time.Time `json:"time,omitempty"`
	// Channel is cedar (an edit), mapfile (a map file reload) or
	// migration (the import of rows that predate the history).
	Channel string `json:"channel"`
	// Actor is who authenticated to the placementd; OnBehalfOf is who
	// they said they acted for, when anyone.
	Actor       string                              `json:"actor"`
	OnBehalfOf  string                              `json:"on_behalf_of,omitempty"`
	PeerAddress string                              `json:"peer_address,omitempty"`
	Comment     string                              `json:"comment,omitempty"`
	Operation   string                              `json:"operation"`
	EntityType  string                              `json:"entity_type"`
	EntityID    string                              `json:"entity_id"`
	Changes     map[string]placementFieldChangeJSON `json:"changes"`
}

func (s *Handler) handlePlacementHistory(w http.ResponseWriter, r *http.Request, entityID string) {
	q := r.URL.Query()
	limit := placementHistoryDefaultLimit
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > placementHistoryMaxLimit {
			s.writeError(w, http.StatusBadRequest, "limit must be an integer from 1 to 1000")
			return
		}
		limit = n
	}
	objs, err := s.placementd.Query(placementContext(r), htcondor.PlacementQuery{
		TargetType:   htcondor.PlacementTargetModification,
		EntityID:     entityID,
		Requirements: q.Get("constraint"),
		Limit:        limit,
	})
	if err != nil {
		s.writePlacementAdminError(w, "query history", err, nil)
		return
	}
	out := make([]placementModificationJSON, 0, len(objs))
	for _, o := range objs {
		if o.Modification != nil {
			out = append(out, placementModificationToJSON(o.Modification))
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"history": out})
}

func placementModificationToJSON(m *htcondor.PlacementModification) placementModificationJSON {
	out := placementModificationJSON{
		ID:          m.ID,
		ChangesetID: m.ChangesetID,
		Time:        optionalTime(m.Time),
		Channel:     m.Channel,
		Actor:       m.Actor,
		OnBehalfOf:  m.OnBehalfOf,
		PeerAddress: m.PeerAddress,
		Comment:     m.Comment,
		Operation:   m.Operation,
		EntityType:  m.EntityType,
		EntityID:    m.EntityID,
		Changes:     make(map[string]placementFieldChangeJSON, len(m.Changes)),
	}
	for field, c := range m.Changes {
		out.Changes[field] = placementFieldChangeJSON{Old: c.Old, New: c.New}
	}
	return out
}
