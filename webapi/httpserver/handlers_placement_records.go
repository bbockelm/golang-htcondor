package httpserver

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// The admin record views: the schedd's user and project records for the
// accounts and projects the placementd hands out, with their job counters,
// and Suspend / Unsuspend (DISABLE_USERREC / ENABLE_USERREC). Ported from
// placement-webapp's user and project detail pages.
//
// Routes, all behind requireAdmin:
//
//	GET  /api/v1/placement/records/projects
//	GET  /api/v1/placement/records/{accounts|projects}/{name}
//	POST /api/v1/placement/records/{accounts|projects}/{name}/{suspend|unsuspend}
//
// Only names the placementd knows -- an AP account one of its identities maps
// to, or a project on one of its lines -- are served. The schedd calls run
// with this server's credential, which is a schedd administrator; the
// restriction keeps this page to the records it is about.

// placementRecordStats are the counters a record view shows, when the schedd
// publishes them.
var placementRecordStats = []string{
	"NumIdle", "NumRunning", "NumHeld", "NumSuspended", "NumCompleted", "NumRemoved", "NumJobs",
	"NumSchedulerIdle", "NumSchedulerRunning", "NumSchedulerHeld",
	"NumSchedulerCompleted", "NumSchedulerRemoved", "NumSchedulerJobs",
	"TotalCompletedJobs", "TotalRemovedJobs",
}

// placementRecordResponse is one schedd record.
type placementRecordResponse struct {
	Kind string `json:"kind"` // "account" or "project"
	Name string `json:"name"`
	// Found is false when the schedd has no record: nothing has been
	// submitted under this name yet. Such a name is enabled.
	Found         bool             `json:"found"`
	Enabled       bool             `json:"enabled"`
	DisableReason string           `json:"disable_reason,omitempty"`
	Stats         map[string]int64 `json:"stats,omitempty"`
	// Members are the placementd identities (accounts) or AP accounts
	// (projects) attached to this name.
	Members []string `json:"members,omitempty"`
}

func (s *Handler) handlePlacementRecordsPath(w http.ResponseWriter, r *http.Request, rest string) {
	if !s.requirePlacementd(w, r) {
		return
	}
	if s.placementRecords() == nil {
		s.writeError(w, http.StatusServiceUnavailable, "No schedd is available.")
		return
	}
	parts := strings.Split(rest, "/")
	kind := map[string]htcondor.UserRecordKind{"accounts": htcondor.UserRecordOwner, "projects": htcondor.UserRecordProject}
	k, ok := kind[parts[0]]
	if !ok {
		s.writeError(w, http.StatusNotFound, "Placement endpoint not found")
		return
	}
	if len(parts) == 1 {
		if k != htcondor.UserRecordProject || r.Method != http.MethodGet {
			s.writeError(w, http.StatusNotFound, "Placement endpoint not found")
			return
		}
		s.handlePlacementProjectList(w, r)
		return
	}
	name, err := url.PathUnescape(parts[1])
	if err != nil || name == "" || len(parts) > 3 {
		s.writeError(w, http.StatusNotFound, "Placement endpoint not found")
		return
	}

	members, known, err := s.placementRecordMembers(r, k, name)
	if err != nil {
		s.writePlacementError(w, "list placement users", err)
		return
	}
	if !known {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("%q is not managed by the placementd", name))
		return
	}

	if len(parts) == 2 {
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		s.writePlacementRecord(w, r, k, name, members)
		return
	}
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	switch parts[2] {
	case "suspend", "unsuspend":
		s.handlePlacementRecordSuspend(w, r, k, name, parts[2] == "suspend", members)
	default:
		s.writeError(w, http.StatusNotFound, "Placement endpoint not found")
	}
}

// placementRecordMembers reports whether the placementd knows name as an AP
// account or project, and who it belongs to.
func (s *Handler) placementRecordMembers(r *http.Request, kind htcondor.UserRecordKind, name string) ([]string, bool, error) {
	users, err := s.placementd.QueryUsers(placementContext(r), "")
	if err != nil {
		return nil, false, err
	}
	seen := map[string]bool{}
	var members []string
	known := false
	for _, u := range users {
		match := ""
		if kind == htcondor.UserRecordOwner {
			if u.APUserID == name {
				match = u.UserName
			}
		} else {
			for _, p := range u.Projects {
				if strings.EqualFold(p, name) {
					match = u.APUserID
				}
			}
		}
		if match == "" {
			continue
		}
		known = true
		if !seen[match] {
			seen[match] = true
			members = append(members, match)
		}
	}
	sort.Strings(members)
	return members, known, nil
}

func (s *Handler) queryPlacementRecord(r *http.Request, kind htcondor.UserRecordKind, name string) (*htcondor.UserRecord, error) {
	records := s.placementRecords()
	ctx := htcondor.WithDaemonCredential(r.Context(), "placement admin: schedd record")
	var recs []htcondor.UserRecord
	var err error
	if kind == htcondor.UserRecordOwner {
		recs, err = records.QueryUserRecords(ctx, &htcondor.UserRecordQueryOptions{
			Constraint: "User == " + classadString(name),
		})
	} else {
		recs, err = records.QueryProjectRecords(ctx, &htcondor.UserRecordQueryOptions{
			Constraint: "Name == " + classadString(name),
		})
	}
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	return &recs[0], nil
}

func placementRecordView(kind htcondor.UserRecordKind, name string, rec *htcondor.UserRecord, members []string) placementRecordResponse {
	out := placementRecordResponse{Kind: "account", Name: name, Enabled: true, Members: members}
	if kind == htcondor.UserRecordProject {
		out.Kind = "project"
	}
	if rec == nil {
		return out
	}
	out.Found = true
	out.Enabled = !rec.IsDisabled()
	if !out.Enabled {
		out.DisableReason = rec.DisableReason
	}
	if rec.Ad != nil {
		out.Stats = map[string]int64{}
		for _, attr := range placementRecordStats {
			if v, ok := rec.Ad.EvaluateAttrInt(attr); ok {
				out.Stats[attr] = v
			}
		}
	}
	return out
}

func (s *Handler) writePlacementRecord(w http.ResponseWriter, r *http.Request, kind htcondor.UserRecordKind, name string, members []string) {
	rec, err := s.queryPlacementRecord(r, kind, name)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Failed to query the schedd: %v", err))
		return
	}
	s.writeJSON(w, http.StatusOK, placementRecordView(kind, name, rec, members))
}

func (s *Handler) handlePlacementRecordSuspend(w http.ResponseWriter, r *http.Request, kind htcondor.UserRecordKind,
	name string, suspend bool, members []string) {
	admin, _ := s.getSessionFromRequest(r)
	adminName := ""
	if admin != nil {
		adminName = admin.Username
	}
	records := s.placementRecords()
	ctx := htcondor.WithDaemonCredential(r.Context(), "placement admin: suspend/unsuspend, admin-gated")

	var res *htcondor.UserRecordActionResult
	var err error
	state := "unsuspended"
	if suspend {
		state = "suspended"
		res, err = records.DisableUserRecord(ctx, kind, name, state+" by "+adminName+" via web UI")
	} else {
		res, err = records.EnableUserRecord(ctx, kind, name)
	}
	if err != nil {
		var uerr *htcondor.UserRecordError
		if errors.As(err, &uerr) && uerr.Code == htcondor.UserRecordErrNotFound {
			s.writeError(w, http.StatusNotFound,
				fmt.Sprintf("The schedd has no record for %q; nothing has been submitted under it yet.", name))
			return
		}
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("The schedd refused the change: %v", err))
		return
	}
	if res.NumAds == 0 {
		s.writeError(w, http.StatusNotFound,
			fmt.Sprintf("The schedd has no record for %q; nothing has been submitted under it yet.", name))
		return
	}
	s.logger.Info(logging.DestinationSecurity, "Placement record "+state,
		"kind", string(kind), "name", name, "admin", adminName)

	rec, err := s.queryPlacementRecord(r, kind, name)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Failed to query the schedd: %v", err))
		return
	}
	s.writeJSON(w, http.StatusOK, placementRecordView(kind, name, rec, members))
}

// placementProjectSummary is one row of the projects list.
type placementProjectSummary struct {
	Name    string `json:"name"`
	Found   bool   `json:"found"`
	Enabled bool   `json:"enabled"`
	// Members is how many AP accounts may bind tokens to the project.
	Members int `json:"members"`
}

// handlePlacementProjectList lists every project the placementd knows, with
// its schedd record's enabled state.
func (s *Handler) handlePlacementProjectList(w http.ResponseWriter, r *http.Request) {
	users, err := s.placementd.QueryUsers(placementContext(r), "")
	if err != nil {
		s.writePlacementError(w, "list placement users", err)
		return
	}
	members := map[string]map[string]bool{}
	display := map[string]string{}
	for _, u := range users {
		for _, p := range u.Projects {
			key := strings.ToLower(p)
			if members[key] == nil {
				members[key] = map[string]bool{}
				display[key] = p
			}
			if u.APUserID != "" {
				members[key][u.APUserID] = true
			}
		}
	}

	ctx := htcondor.WithDaemonCredential(r.Context(), "placement admin: project records")
	recs, err := s.placementRecords().QueryProjectRecords(ctx, &htcondor.UserRecordQueryOptions{
		Projection: []string{"Name", "Enabled"},
	})
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Failed to query the schedd: %v", err))
		return
	}
	byName := map[string]*htcondor.UserRecord{}
	for i := range recs {
		byName[strings.ToLower(recs[i].User)] = &recs[i]
	}

	out := make([]placementProjectSummary, 0, len(members))
	for key, m := range members {
		row := placementProjectSummary{Name: display[key], Enabled: true, Members: len(m)}
		if rec := byName[key]; rec != nil {
			row.Found = true
			row.Enabled = !rec.IsDisabled()
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	s.writeJSON(w, http.StatusOK, map[string]any{"projects": out})
}
