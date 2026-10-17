package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Admin CRUD over the placementd's directory: identities, accounts, projects
// and authorizations, through PLACEMENT_QUERY and PLACEMENT_EDIT. Every route
// is admin-gated like the rest of /api/v1/placement, and answers 501 against
// a placementd that does not advertise PlacementdApiVersion >= 2.
//
// The daemon is called with this access point's own credential (see
// placementContext), so the daemon's audit trail names the access point; the
// admin who asked is logged here.

const placementAdminPrefix = "/api/v1/placement/admin"

// placementKinds maps a URL collection name to the wire TargetType.
var placementKinds = map[string]string{
	"identities":     htcondor.PlacementTargetIdentity,
	"accounts":       htcondor.PlacementTargetAccount,
	"projects":       htcondor.PlacementTargetProject,
	"authorizations": htcondor.PlacementTargetAuthorization,
}

// placementFieldKind is how a JSON field is converted to a ClassAd value.
type placementFieldKind int

const (
	placementFieldString placementFieldKind = iota
	placementFieldList
	placementFieldBool
	placementFieldTime
)

type placementFieldSpec struct {
	attr string
	kind placementFieldKind
}

// placementWritableFields are the writable attributes of each TargetType,
// keyed by their JSON names (§6.3 of the placementd design).
var placementWritableFields = map[string]map[string]placementFieldSpec{
	htcondor.PlacementTargetIdentity: {
		"foreign_id":   {"ForeignId", placementFieldString},
		"account":      {"Account", placementFieldString},
		"expires_at":   {"ExpiresAt", placementFieldTime},
		"display_name": {"DisplayName", placementFieldString},
		"comment":      {"Comment", placementFieldString},
	},
	htcondor.PlacementTargetAccount: {
		"name":            {"Name", placementFieldString},
		"authorizations":  {"Authorizations", placementFieldList},
		"projects":        {"Projects", placementFieldList},
		"default_project": {"DefaultProject", placementFieldString},
	},
	htcondor.PlacementTargetProject: {
		"name":        {"Name", placementFieldString},
		"description": {"Description", placementFieldString},
	},
	htcondor.PlacementTargetAuthorization: {
		"name":        {"Name", placementFieldString},
		"label":       {"Label", placementFieldString},
		"color":       {"Color", placementFieldString},
		"description": {"Description", placementFieldString},
		"requestable": {"Requestable", placementFieldBool},
	},
}

// --- Response shapes ---

type placementEntityJSON struct {
	ID         string     `json:"id"`
	Source     string     `json:"source,omitempty"`
	Version    int64      `json:"version"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	ModifiedBy string     `json:"modified_by,omitempty"`
}

type placementIdentityJSON struct {
	placementEntityJSON
	ForeignID string `json:"foreign_id"`
	AccountID string `json:"account_id,omitempty"`
	Account   string `json:"account,omitempty"`
	// ExpiresAt absent means the mapping never expires.
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	Expired             bool       `json:"expired"`
	DisplayName         string     `json:"display_name,omitempty"`
	Comment             string     `json:"comment,omitempty"`
	Authorizations      []string   `json:"authorizations"`
	Projects            []string   `json:"projects"`
	DefaultProject      string     `json:"default_project,omitempty"`
	LastTokenExpiration *time.Time `json:"last_token_expiration,omitempty"`
}

type placementAccountJSON struct {
	placementEntityJSON
	Name           string   `json:"name"`
	Authorizations []string `json:"authorizations"`
	Projects       []string `json:"projects"`
	DefaultProject string   `json:"default_project,omitempty"`
	Identities     []string `json:"identities"`
}

type placementProjectJSON struct {
	placementEntityJSON
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Accounts    []string `json:"accounts"`
}

type placementAuthorizationRecordJSON struct {
	placementEntityJSON
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Color       string `json:"color,omitempty"`
	Description string `json:"description,omitempty"`
	Requestable bool   `json:"requestable"`
}

type placementMapfileProblemJSON struct {
	Kind    string `json:"kind,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Key     string `json:"key,omitempty"`
	Message string `json:"message,omitempty"`
}

type placementMapfileStatusJSON struct {
	LoadTime              *time.Time                    `json:"load_time,omitempty"`
	LoadAttemptTime       *time.Time                    `json:"load_attempt_time,omitempty"`
	OK                    bool                          `json:"ok"`
	Quarantined           int                           `json:"quarantined"`
	Conflicts             int                           `json:"conflicts"`
	UserMapfile           string                        `json:"user_mapfile,omitempty"`
	AuthorizationsMapfile string                        `json:"authorizations_mapfile,omitempty"`
	Problems              []placementMapfileProblemJSON `json:"problems"`
}

// placementEditResultJSON is one operation's outcome.
type placementEditResultJSON struct {
	Index     int    `json:"index"`
	ID        string `json:"id,omitempty"`
	Version   int64  `json:"version,omitempty"`
	Warning   string `json:"warning,omitempty"`
	ErrorCode int    `json:"error_code,omitempty"`
	Error     string `json:"error,omitempty"`
}

// placementBatchResponse answers a batch, or a single-operation edit.
type placementBatchResponse struct {
	// Committed is false on a dry run: nothing was written.
	Committed bool                      `json:"committed"`
	DryRun    bool                      `json:"dry_run"`
	Results   []placementEditResultJSON `json:"results"`
}

// placementAdminErrorBody is ErrorResponse plus what a UI needs to act on a
// placementd refusal.
type placementAdminErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
	// PlacementCode and PlacementError are the daemon's code and its name.
	PlacementCode  int    `json:"placement_code,omitempty"`
	PlacementError string `json:"placement_error,omitempty"`
	// OwnedBy names the source that owns a row the edit may not change.
	OwnedBy string `json:"owned_by,omitempty"`
	// CascadeRequired means the delete would succeed with cascade=true.
	CascadeRequired bool `json:"cascade_required,omitempty"`
	// Results are the per-operation outcomes of a failed batch.
	Results []placementEditResultJSON `json:"results,omitempty"`
}

// --- Request shapes ---

// placementBatchRequest is POST /placement/admin/batch.
type placementBatchRequest struct {
	DryRun     bool                    `json:"dry_run"`
	Operations []placementBatchOpInput `json:"operations"`
}

type placementBatchOpInput struct {
	Operation       string                     `json:"operation"`
	TargetType      string                     `json:"target_type"`
	ID              string                     `json:"id,omitempty"`
	Name            string                     `json:"name,omitempty"`
	ExpectedVersion int64                      `json:"expected_version,omitempty"`
	Cascade         bool                       `json:"cascade,omitempty"`
	Fields          map[string]json.RawMessage `json:"fields,omitempty"`
}

// --- Routing ---

// handlePlacementAdmin serves /api/v1/placement/admin/*.
func (s *Handler) handlePlacementAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.requirePlacementd(w, r) {
		return
	}
	if v := s.placementAPIVersion(r.Context()); v < htcondor.PlacementdAPIVersionDirectory {
		s.writeError(w, http.StatusNotImplemented, fmt.Sprintf(
			"This placementd does not support directory management (API version %d; %d is required).",
			v, htcondor.PlacementdAPIVersionDirectory))
		return
	}

	path := strings.Trim(strings.TrimPrefix(r.URL.Path, placementAdminPrefix), "/")
	parts := strings.Split(path, "/")

	switch path {
	case "mapfile-status":
		s.handlePlacementMapfileStatus(w, r)
		return
	case "adopt-all":
		if !placementMethod(s, w, r, http.MethodPost) {
			return
		}
		s.runPlacementEdit(w, r, "adopt all", []htcondor.PlacementOp{{
			Operation:  htcondor.PlacementOpAdopt,
			TargetType: htcondor.PlacementTargetAll,
		}}, placementDryRun(r), http.StatusOK)
		return
	case "batch":
		if !placementMethod(s, w, r, http.MethodPost) {
			return
		}
		s.handlePlacementBatch(w, r)
		return
	}

	target, ok := placementKinds[parts[0]]
	if !ok {
		s.writeError(w, http.StatusNotFound, "Placement admin endpoint not found")
		return
	}
	switch len(parts) {
	case 1:
		switch r.Method {
		case http.MethodGet:
			s.handlePlacementAdminList(w, r, parts[0], target)
		case http.MethodPost:
			s.handlePlacementAdminCreate(w, r, target)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	case 2:
		id := parts[1]
		switch r.Method {
		case http.MethodGet:
			s.handlePlacementAdminGet(w, r, target, id)
		case http.MethodPatch:
			s.handlePlacementAdminUpdate(w, r, target, id)
		case http.MethodDelete:
			s.handlePlacementAdminDelete(w, r, target, id)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	case 3:
		if parts[2] != "adopt" {
			s.writeError(w, http.StatusNotFound, "Placement admin endpoint not found")
			return
		}
		if !placementMethod(s, w, r, http.MethodPost) {
			return
		}
		s.handlePlacementAdminAdopt(w, r, target, parts[1])
	default:
		s.writeError(w, http.StatusNotFound, "Placement admin endpoint not found")
	}
}

func placementMethod(s *Handler, w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return false
	}
	return true
}

func placementDryRun(r *http.Request) bool {
	return placementQueryBool(r, "dry_run")
}

func placementQueryBool(r *http.Request, key string) bool {
	switch strings.ToLower(r.URL.Query().Get(key)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// --- Reads ---

func (s *Handler) handlePlacementAdminList(w http.ResponseWriter, r *http.Request, kind, target string) {
	q := r.URL.Query()
	query := htcondor.PlacementQuery{
		TargetType:   target,
		Name:         q.Get("name"),
		Requirements: q.Get("constraint"),
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 0 {
			s.writeError(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		query.Limit = n
	}
	objs, err := s.placementd.Query(placementContext(r), query)
	if err != nil {
		s.writePlacementAdminError(w, "query "+kind, err, nil)
		return
	}
	out := make([]any, 0, len(objs))
	for _, o := range objs {
		if v := placementObjectJSON(o); v != nil {
			out = append(out, v)
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{kind: out})
}

func (s *Handler) handlePlacementAdminGet(w http.ResponseWriter, r *http.Request, target, id string) {
	objs, err := s.placementd.Query(placementContext(r), htcondor.PlacementQuery{TargetType: target, ID: id, Limit: 1})
	if err != nil {
		s.writePlacementAdminError(w, "query "+strings.ToLower(target), err, nil)
		return
	}
	for _, o := range objs {
		if v := placementObjectJSON(o); v != nil {
			s.writeJSON(w, http.StatusOK, v)
			return
		}
	}
	s.writeError(w, http.StatusNotFound, fmt.Sprintf("No %s with id %s", strings.ToLower(target), id))
}

func (s *Handler) handlePlacementMapfileStatus(w http.ResponseWriter, r *http.Request) {
	if !placementMethod(s, w, r, http.MethodGet) {
		return
	}
	objs, err := s.placementd.Query(placementContext(r), htcondor.PlacementQuery{TargetType: htcondor.PlacementTargetMapfileStatus})
	if err != nil {
		s.writePlacementAdminError(w, "query mapfile status", err, nil)
		return
	}
	for _, o := range objs {
		if o.MapfileStatus != nil {
			s.writeJSON(w, http.StatusOK, placementMapfileStatusToJSON(o.MapfileStatus))
			return
		}
	}
	s.writeError(w, http.StatusBadGateway, "The placementd returned no mapfile status")
}

// --- Writes ---

func (s *Handler) handlePlacementAdminCreate(w http.ResponseWriter, r *http.Request, target string) {
	raw, ok := s.decodePlacementObject(w, r)
	if !ok {
		return
	}
	fields, err := placementFieldsFromJSON(target, raw, false)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(fields) == 0 {
		s.writeError(w, http.StatusBadRequest, "The request body sets no fields")
		return
	}
	s.runPlacementEdit(w, r, "create "+strings.ToLower(target), []htcondor.PlacementOp{{
		Operation:  htcondor.PlacementOpCreate,
		TargetType: target,
		Fields:     fields,
	}}, placementDryRun(r), http.StatusCreated)
}

func (s *Handler) handlePlacementAdminUpdate(w http.ResponseWriter, r *http.Request, target, id string) {
	raw, ok := s.decodePlacementObject(w, r)
	if !ok {
		return
	}
	expected, err := placementExpectedVersion(raw)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	fields, err := placementFieldsFromJSON(target, raw, true)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(fields) == 0 {
		s.writeError(w, http.StatusBadRequest, "The request body changes no fields")
		return
	}
	s.runPlacementEdit(w, r, "update "+strings.ToLower(target), []htcondor.PlacementOp{{
		Operation:       htcondor.PlacementOpUpdate,
		TargetType:      target,
		ID:              id,
		ExpectedVersion: expected,
		Fields:          fields,
	}}, placementDryRun(r), http.StatusOK)
}

func (s *Handler) handlePlacementAdminDelete(w http.ResponseWriter, r *http.Request, target, id string) {
	var expected int64
	if v := r.URL.Query().Get("expected_version"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			s.writeError(w, http.StatusBadRequest, "expected_version must be a positive integer")
			return
		}
		expected = n
	}
	s.runPlacementEdit(w, r, "delete "+strings.ToLower(target), []htcondor.PlacementOp{{
		Operation:       htcondor.PlacementOpDelete,
		TargetType:      target,
		ID:              id,
		ExpectedVersion: expected,
		Cascade:         placementQueryBool(r, "cascade"),
	}}, placementDryRun(r), http.StatusOK)
}

func (s *Handler) handlePlacementAdminAdopt(w http.ResponseWriter, r *http.Request, target, id string) {
	var expected int64
	// The body is optional: {"expected_version": N}.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		raw := map[string]json.RawMessage{}
		if err := json.Unmarshal(body, &raw); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
			return
		}
		if expected, err = placementExpectedVersion(raw); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(raw) > 0 {
			s.writeError(w, http.StatusBadRequest, "An adopt takes only expected_version")
			return
		}
	}
	s.runPlacementEdit(w, r, "adopt "+strings.ToLower(target), []htcondor.PlacementOp{{
		Operation:       htcondor.PlacementOpAdopt,
		TargetType:      target,
		ID:              id,
		ExpectedVersion: expected,
	}}, placementDryRun(r), http.StatusOK)
}

func (s *Handler) handlePlacementBatch(w http.ResponseWriter, r *http.Request) {
	var req placementBatchRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	if len(req.Operations) == 0 {
		s.writeError(w, http.StatusBadRequest, "operations is empty")
		return
	}
	ops := make([]htcondor.PlacementOp, 0, len(req.Operations))
	for i, in := range req.Operations {
		op := htcondor.PlacementOp{
			Operation:       in.Operation,
			TargetType:      in.TargetType,
			ID:              in.ID,
			Name:            in.Name,
			ExpectedVersion: in.ExpectedVersion,
			Cascade:         in.Cascade,
		}
		if len(in.Fields) > 0 {
			if _, known := placementWritableFields[in.TargetType]; !known {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("operations[%d]: %q takes no fields", i, in.TargetType))
				return
			}
			fields, err := placementFieldsFromJSON(in.TargetType, in.Fields, in.Operation == htcondor.PlacementOpUpdate)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("operations[%d]: %v", i, err))
				return
			}
			op.Fields = fields
		}
		ops = append(ops, op)
	}
	s.runPlacementEdit(w, r, "apply batch", ops, req.DryRun || placementDryRun(r), http.StatusOK)
}

// runPlacementEdit sends ops and writes the response.
func (s *Handler) runPlacementEdit(w http.ResponseWriter, r *http.Request, what string, ops []htcondor.PlacementOp, dryRun bool, okStatus int) {
	admin := ""
	if session, ok := s.getSessionFromRequest(r); ok {
		admin = session.Username
	}
	results, err := s.placementd.Edit(placementContext(r), ops, dryRun)
	out := make([]placementEditResultJSON, 0, len(results))
	for _, res := range results {
		out = append(out, placementEditResultJSON{
			Index:     res.Index,
			ID:        res.ID,
			Version:   res.Version,
			Warning:   res.Warning,
			ErrorCode: res.ErrorCode,
			Error:     res.ErrorString,
		})
	}

	// The daemon's audit names this access point, which made the call;
	// this line names the admin who asked for it.
	if s.logger != nil {
		summary := make([]string, 0, len(ops))
		for _, op := range ops {
			sel := op.ID
			if sel == "" {
				sel = op.Name
			}
			summary = append(summary, strings.TrimSpace(op.Operation+" "+op.TargetType+" "+sel))
		}
		s.logger.Info(logging.DestinationSecurity, "Placement directory edit",
			"admin", admin, "operations", strings.Join(summary, "; "),
			"dry_run", dryRun, "error", err)
	}

	if err != nil {
		s.writePlacementAdminError(w, what, err, out)
		return
	}
	s.writeJSON(w, okStatus, placementBatchResponse{Committed: !dryRun, DryRun: dryRun, Results: out})
}

// decodePlacementObject reads a JSON object body, keeping each field raw so
// that an explicit null (clear) can be told from an absent field (unchanged).
func (s *Handler) decodePlacementObject(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, bool) {
	raw := map[string]json.RawMessage{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return nil, false
	}
	return raw, true
}

// placementExpectedVersion removes expected_version from raw and returns it;
// absent is 0.
func placementExpectedVersion(raw map[string]json.RawMessage) (int64, error) {
	v, ok := raw["expected_version"]
	if !ok {
		return 0, nil
	}
	delete(raw, "expected_version")
	if string(v) == "null" {
		return 0, nil
	}
	var n int64
	if err := json.Unmarshal(v, &n); err != nil || n < 1 {
		return 0, fmt.Errorf("expected_version must be a positive integer")
	}
	return n, nil
}

// placementFieldsFromJSON converts JSON fields to ClassAd attributes. On an
// update an explicit null clears the attribute (sent as undefined); on a
// create it is the same as leaving the field out.
func placementFieldsFromJSON(target string, raw map[string]json.RawMessage, update bool) (map[string]any, error) {
	specs, ok := placementWritableFields[target]
	if !ok {
		return nil, fmt.Errorf("unknown target type %q", target)
	}
	fields := make(map[string]any, len(raw))
	for key, val := range raw {
		spec, ok := specs[key]
		if !ok {
			return nil, fmt.Errorf("unknown field %q for %s", key, strings.ToLower(target))
		}
		if string(bytes.TrimSpace(val)) == "null" {
			if update {
				fields[spec.attr] = nil
			}
			continue
		}
		v, err := placementFieldValue(spec, val)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		fields[spec.attr] = v
	}
	return fields, nil
}

func placementFieldValue(spec placementFieldSpec, val json.RawMessage) (any, error) {
	switch spec.kind {
	case placementFieldString:
		var s string
		if err := json.Unmarshal(val, &s); err != nil {
			return nil, fmt.Errorf("must be a string")
		}
		return s, nil
	case placementFieldList:
		var l []string
		if err := json.Unmarshal(val, &l); err != nil {
			return nil, fmt.Errorf("must be a list of strings")
		}
		if l == nil {
			l = []string{}
		}
		return l, nil
	case placementFieldBool:
		var b bool
		if err := json.Unmarshal(val, &b); err != nil {
			return nil, fmt.Errorf("must be true or false")
		}
		return b, nil
	case placementFieldTime:
		// An RFC 3339 timestamp, or Unix seconds.
		var s string
		if err := json.Unmarshal(val, &s); err == nil {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return nil, fmt.Errorf("must be an RFC 3339 timestamp, Unix seconds, or null")
			}
			return t, nil
		}
		var n int64
		if err := json.Unmarshal(val, &n); err != nil || n <= 0 {
			return nil, fmt.Errorf("must be an RFC 3339 timestamp, Unix seconds, or null")
		}
		return time.Unix(n, 0), nil
	}
	return nil, fmt.Errorf("unsupported field")
}

// --- Errors ---

// placementAdminErrorStatus maps a placementd error code from the directory
// commands to an HTTP status; the older codes keep their existing mapping.
func placementAdminErrorStatus(code int) int {
	switch code {
	case htcondor.PlacementErrNotFound:
		return http.StatusNotFound
	case htcondor.PlacementErrVersionMismatch,
		htcondor.PlacementErrOwnedBySource,
		htcondor.PlacementErrStillReferenced,
		htcondor.PlacementErrDuplicate:
		return http.StatusConflict
	case htcondor.PlacementErrInvalidArgument, htcondor.PlacementErrUnknownType:
		return http.StatusBadRequest
	}
	return placementErrorStatus(code)
}

func (s *Handler) writePlacementAdminError(w http.ResponseWriter, op string, err error, results []placementEditResultJSON) {
	var perr *htcondor.PlacementError
	if !errors.As(err, &perr) {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Failed to %s: %v", op, err))
		return
	}
	status := placementAdminErrorStatus(perr.Code)
	body := placementAdminErrorBody{
		Error:          http.StatusText(status),
		Message:        perr.Message,
		Code:           status,
		PlacementCode:  perr.Code,
		PlacementError: perr.Name(),
		Results:        results,
	}
	switch perr.Code {
	case htcondor.PlacementErrOwnedBySource:
		body.OwnedBy = htcondor.PlacementSourceMapfile
	case htcondor.PlacementErrStillReferenced:
		body.CascadeRequired = true
	}
	s.writeJSON(w, status, body)
}

// --- Conversions ---

func placementMetaJSON(m htcondor.PlacementEntityMeta) placementEntityJSON {
	return placementEntityJSON{
		ID:         m.ID,
		Source:     m.Source,
		Version:    m.Version,
		CreatedAt:  optionalTime(m.CreatedAt),
		UpdatedAt:  optionalTime(m.UpdatedAt),
		ModifiedBy: m.ModifiedBy,
	}
}

func nonNilStrings(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// placementObjectJSON renders one query result, or nil for a result type
// this API does not list (a MapfileStatus ad in an entity listing).
func placementObjectJSON(o htcondor.PlacementObject) any {
	switch {
	case o.Identity != nil:
		i := o.Identity
		return placementIdentityJSON{
			placementEntityJSON: placementMetaJSON(i.PlacementEntityMeta),
			ForeignID:           i.ForeignID,
			AccountID:           i.AccountID,
			Account:             i.Account,
			ExpiresAt:           optionalTime(i.ExpiresAt),
			Expired:             i.Expired,
			DisplayName:         i.DisplayName,
			Comment:             i.Comment,
			Authorizations:      nonNilStrings(i.Authorizations),
			Projects:            nonNilStrings(i.Projects),
			DefaultProject:      i.DefaultProject,
			LastTokenExpiration: optionalTime(i.LastTokenExpiration),
		}
	case o.Account != nil:
		a := o.Account
		return placementAccountJSON{
			placementEntityJSON: placementMetaJSON(a.PlacementEntityMeta),
			Name:                a.Name,
			Authorizations:      nonNilStrings(a.Authorizations),
			Projects:            nonNilStrings(a.Projects),
			DefaultProject:      a.DefaultProject,
			Identities:          nonNilStrings(a.Identities),
		}
	case o.Project != nil:
		p := o.Project
		return placementProjectJSON{
			placementEntityJSON: placementMetaJSON(p.PlacementEntityMeta),
			Name:                p.Name,
			Description:         p.Description,
			Accounts:            nonNilStrings(p.Accounts),
		}
	case o.Authorization != nil:
		a := o.Authorization
		return placementAuthorizationRecordJSON{
			placementEntityJSON: placementMetaJSON(a.PlacementEntityMeta),
			Name:                a.Name,
			Label:               a.Label,
			Color:               a.Color,
			Description:         a.Description,
			Requestable:         a.Requestable,
		}
	}
	return nil
}

func placementMapfileStatusToJSON(st *htcondor.PlacementMapfileStatus) placementMapfileStatusJSON {
	out := placementMapfileStatusJSON{
		LoadTime:              optionalTime(st.LoadTime),
		LoadAttemptTime:       optionalTime(st.LoadAttemptTime),
		OK:                    st.OK,
		Quarantined:           st.Quarantined,
		Conflicts:             st.Conflicts,
		UserMapfile:           st.UserMapfile,
		AuthorizationsMapfile: st.AuthorizationsMapfile,
		Problems:              make([]placementMapfileProblemJSON, 0, len(st.Problems)),
	}
	for _, p := range st.Problems {
		out.Problems = append(out.Problems, placementMapfileProblemJSON{
			Kind: p.Kind, File: p.File, Line: p.Line, Key: p.Key, Message: p.Message,
		})
	}
	return out
}
