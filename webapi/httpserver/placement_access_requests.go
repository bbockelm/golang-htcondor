package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Access requests: somebody who signs in with a placement identity the
// placementd does not map can ask for access, and an administrator approves
// (onboarding them in the directory) or denies. The requests live in this
// server's database; the placementd records only who has access.
//
// A request never grants anything. Approval is one PLACEMENT_EDIT batch,
// made for the approving admin, so every limit the placementd puts on its
// directory applies to it; the request is marked approved only once that
// batch committed.

// Request states.
const (
	accessRequestPending   = "pending"
	accessRequestApproved  = "approved"
	accessRequestDenied    = "denied"
	accessRequestWithdrawn = "withdrawn"
)

// Limits on what a requester may write.
const (
	// accessRequestMaxNote is the longest note, and the longest reason or
	// comment an administrator gives, in bytes.
	accessRequestMaxNote = 2048
	// accessRequestMaxProjects is the most projects one request names.
	accessRequestMaxProjects = 10
	// accessRequestMaxProjectLen is the longest project name, in
	// characters.
	accessRequestMaxProjectLen = 64
	// accessRequestListLimit is the most requests one listing returns.
	accessRequestListLimit = 500
)

var (
	// errAccessRequestPending: the identity already has a pending request.
	errAccessRequestPending = errors.New("a request is already pending")
	// errAccessRequestNotPending: the request was decided or withdrawn.
	errAccessRequestNotPending = errors.New("the request is no longer pending")
)

// placementAccessRequest is one row of placement_access_requests.
type placementAccessRequest struct {
	ID           int64
	Identity     string
	IDPSubject   string
	DisplayName  string
	Email        string
	Projects     []string
	Note         string
	Status       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DecidedBy    string
	DecidedAt    time.Time
	DecisionNote string
	Account      string
	ChangesetID  int64
}

// placementAccessRequestStore reads and writes placement_access_requests.
type placementAccessRequestStore struct {
	db  *sql.DB
	now func() time.Time
}

const accessRequestColumns = `id, identity, idp_subject, display_name, email, requested_projects, note, status,
	created_at, updated_at, decided_by, decided_at, decision_note, account, changeset_id`

func scanAccessRequest(row interface{ Scan(...any) error }) (*placementAccessRequest, error) {
	var (
		req                         placementAccessRequest
		projects                    string
		created, updated, decidedAt int64
	)
	if err := row.Scan(&req.ID, &req.Identity, &req.IDPSubject, &req.DisplayName, &req.Email, &projects,
		&req.Note, &req.Status, &created, &updated, &req.DecidedBy, &decidedAt, &req.DecisionNote,
		&req.Account, &req.ChangesetID); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(projects), &req.Projects); err != nil {
		req.Projects = nil
	}
	req.CreatedAt = time.Unix(created, 0).UTC()
	req.UpdatedAt = time.Unix(updated, 0).UTC()
	if decidedAt > 0 {
		req.DecidedAt = time.Unix(decidedAt, 0).UTC()
	}
	return &req, nil
}

// create stores a new pending request. It returns errAccessRequestPending
// when the identity already has one: the partial unique index decides, so
// two concurrent requests cannot both succeed.
func (st *placementAccessRequestStore) create(ctx context.Context, req placementAccessRequest) (*placementAccessRequest, error) {
	projects, err := json.Marshal(nonNilStrings(req.Projects))
	if err != nil {
		return nil, err
	}
	now := st.now().Unix()
	res, err := st.db.ExecContext(ctx,
		`INSERT INTO placement_access_requests
		   (identity, idp_subject, display_name, email, requested_projects, note, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.Identity, req.IDPSubject, req.DisplayName, req.Email, string(projects), req.Note,
		accessRequestPending, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, errAccessRequestPending
		}
		return nil, fmt.Errorf("storing the access request: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("storing the access request: %w", err)
	}
	return st.get(ctx, id)
}

// get returns one request, or nil when there is none with that id.
func (st *placementAccessRequestStore) get(ctx context.Context, id int64) (*placementAccessRequest, error) {
	req, err := scanAccessRequest(st.db.QueryRowContext(ctx,
		`SELECT `+accessRequestColumns+` FROM placement_access_requests WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return req, err
}

// latest returns identity's most recent request, or nil.
func (st *placementAccessRequestStore) latest(ctx context.Context, identity string) (*placementAccessRequest, error) {
	req, err := scanAccessRequest(st.db.QueryRowContext(ctx,
		`SELECT `+accessRequestColumns+` FROM placement_access_requests
		 WHERE identity = ? ORDER BY id DESC LIMIT 1`, identity))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return req, err
}

// list returns requests newest first: those in status, or every one when
// status is "".
func (st *placementAccessRequestStore) list(ctx context.Context, status string) ([]placementAccessRequest, error) {
	query := `SELECT ` + accessRequestColumns + ` FROM placement_access_requests`
	var args []any
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, accessRequestListLimit)
	rows, err := st.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []placementAccessRequest{}
	for rows.Next() {
		req, err := scanAccessRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *req)
	}
	return out, rows.Err()
}

// countPending is the number of pending requests.
func (st *placementAccessRequestStore) countPending(ctx context.Context) (int, error) {
	var n int
	err := st.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM placement_access_requests WHERE status = ?`, accessRequestPending).Scan(&n)
	return n, err
}

// withdraw marks identity's pending request withdrawn and returns it, or
// nil when it has none.
func (st *placementAccessRequestStore) withdraw(ctx context.Context, identity string) (*placementAccessRequest, error) {
	var id int64
	err := st.db.QueryRowContext(ctx,
		`SELECT id FROM placement_access_requests WHERE identity = ? AND status = ?`,
		identity, accessRequestPending).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	res, err := st.db.ExecContext(ctx,
		`UPDATE placement_access_requests SET status = ?, updated_at = ?
		 WHERE id = ? AND identity = ? AND status = ?`,
		accessRequestWithdrawn, st.now().Unix(), id, identity, accessRequestPending)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		// Decided between the read and the write.
		return nil, nil
	}
	return st.get(ctx, id)
}

// placementAccessDecision is what an administrator decided.
type placementAccessDecision struct {
	Status      string
	By          string
	Note        string
	Account     string
	ChangesetID int64
}

// decide records a decision on a pending request. It returns
// errAccessRequestNotPending when the request is no longer pending, and
// sql.ErrNoRows when there is no such request.
func (st *placementAccessRequestStore) decide(ctx context.Context, id int64, d placementAccessDecision) (*placementAccessRequest, error) {
	if d.Status != accessRequestApproved && d.Status != accessRequestDenied {
		return nil, fmt.Errorf("unknown decision %q", d.Status)
	}
	now := st.now().Unix()
	res, err := st.db.ExecContext(ctx,
		`UPDATE placement_access_requests
		 SET status = ?, updated_at = ?, decided_by = ?, decided_at = ?, decision_note = ?,
		     account = ?, changeset_id = ?
		 WHERE id = ? AND status = ?`,
		d.Status, now, d.By, now, d.Note, d.Account, d.ChangesetID, id, accessRequestPending)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 1 {
		return st.get(ctx, id)
	}
	cur, err := st.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, sql.ErrNoRows
	}
	return cur, errAccessRequestNotPending
}

// cleanAccessRequestProjects checks and normalizes requested project names:
// trimmed, none empty, no control characters, at most
// accessRequestMaxProjectLen characters each and accessRequestMaxProjects
// in all, duplicates (ignoring case) dropped.
func cleanAccessRequestProjects(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !utf8.ValidString(p) || strings.IndexFunc(p, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("a project name contains a character that is not allowed")
		}
		if utf8.RuneCountInString(p) > accessRequestMaxProjectLen {
			return nil, fmt.Errorf("a project name is longer than %d characters", accessRequestMaxProjectLen)
		}
		key := strings.ToLower(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	if len(out) > accessRequestMaxProjects {
		return nil, fmt.Errorf("a request can name at most %d projects", accessRequestMaxProjects)
	}
	return out, nil
}

// cleanAccessRequestText checks free text from a requester or an
// administrator: valid UTF-8, at most accessRequestMaxNote bytes, no control
// characters other than newline and tab. It returns the text trimmed.
func cleanAccessRequestText(what, s string) (string, error) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if len(s) > accessRequestMaxNote {
		return "", fmt.Errorf("the %s is longer than %d bytes", what, accessRequestMaxNote)
	}
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("the %s is not valid text", what)
	}
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0 {
		return "", fmt.Errorf("the %s contains a character that is not allowed", what)
	}
	return s, nil
}
