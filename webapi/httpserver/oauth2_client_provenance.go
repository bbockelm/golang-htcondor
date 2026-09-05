package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Client provenance: where an OAuth2 client came from, what it calls
// itself, and whether anyone still uses it.
//
// The admin client list used to show an id, some redirect URIs and a
// created-at. For a dynamically registered client the id is
// "client_<unixnano>", so the list was a wall of near-identical rows
// with no way to tell a live integration from months-old registration
// churn. These are the fields that make the list readable.

// ClientOrigin says how a client came to exist. The empty value is
// meaningful and is not the same as "not dynamic": it marks a row that
// predates the column, where the answer was never recorded. Rendering
// that as "not dynamically registered" would assert something nobody
// checked.
type ClientOrigin string

const (
	// ClientOriginUnknown is a row that predates provenance tracking.
	ClientOriginUnknown ClientOrigin = ""
	// ClientOriginDynamic is a client that registered itself through
	// /mcp/oauth2/register (RFC 7591).
	ClientOriginDynamic ClientOrigin = "dynamic"
	// ClientOriginSeeded is a client this server created at startup.
	ClientOriginSeeded ClientOrigin = "seeded"
)

// maxRecentUsers caps the rolling sample of subjects kept per client.
// Three is enough to tell "one service account" from "a team" from "the
// whole pool" without turning a client row into an audit log; the tokens
// table is where per-issuance history already lives.
const maxRecentUsers = 3

// clientUse is one entry in a client's recent-users sample.
type clientUse struct {
	Subject string    `json:"subject"`
	At      time.Time `json:"at"`
}

// clientProvenance is the stored half of a client's identity, read back
// for the admin list.
type clientProvenance struct {
	Name        string
	Notes       string
	Origin      ClientOrigin
	LastUsedAt  *time.Time
	RecentUsers []clientUse
}

// setClientProvenance records how a newly created client came to exist.
// Called right after CreateClient rather than folded into it: CreateClient
// implements a fosite storage interface whose signature we do not own.
//
// A failure here is logged by the caller and not fatal. The client is
// already usable; losing its label degrades the admin UI rather than the
// OAuth2 flow, and refusing the registration over it would be worse.
func setClientProvenance(ctx context.Context, db *sql.DB, clientID, name string, origin ClientOrigin) error {
	_, err := db.ExecContext(ctx,
		`UPDATE oauth2_clients SET client_name = ?, origin = ? WHERE id = ?`,
		name, string(origin), clientID)
	return err
}

// setClientNotes replaces an operator's annotation for a client.
func setClientNotes(ctx context.Context, db *sql.DB, clientID, notes string) (bool, error) {
	res, err := db.ExecContext(ctx,
		`UPDATE oauth2_clients SET notes = ? WHERE id = ?`, notes, clientID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		// The driver could not tell us. Treat it as found rather than
		// reporting a 404 for a write that probably landed.
		return true, nil //nolint:nilerr // see comment
	}
	return n > 0, nil
}

// scanProvenance reads the provenance columns off a client row. It
// tolerates a missing or malformed recent_users blob: a client row that
// will not render is worse than one rendering without its user sample.
func scanProvenance(name, notes, origin string, lastUsed sql.NullTime, recentUsers string) clientProvenance {
	p := clientProvenance{
		Name:   name,
		Notes:  notes,
		Origin: ClientOrigin(origin),
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		p.LastUsedAt = &t
	}
	if recentUsers != "" {
		var users []clientUse
		if err := json.Unmarshal([]byte(recentUsers), &users); err == nil {
			p.RecentUsers = users
		}
	}
	return p
}

// clientUsageRecorder records "this client obtained a token, for this
// subject" without writing to the database on every token request.
//
// Token issuance is not a hot path the way request authentication is,
// but it is not rare either: a client with a short access-token lifetime
// refreshes on a timer, and several of them together would turn an
// admin-UI nicety into a steady write load on the same SQLite file that
// serves sessions. So writes are coalesced -- the recorder keeps the
// newest state per client in memory and flushes on an interval, which
// collapses any number of refreshes in that window into one UPDATE.
//
// The cost of coalescing is that the last few seconds of usage are lost
// if the process dies. That is the right trade for a "last used"
// display: it is already approximate, and Close flushes so an orderly
// shutdown keeps it.
type clientUsageRecorder struct {
	db       *sql.DB
	interval time.Duration

	mu      sync.Mutex
	pending map[string]*pendingClientUse

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

// pendingClientUse is the not-yet-written state for one client. users is
// the merged sample, newest first, already capped.
type pendingClientUse struct {
	lastUsed time.Time
	users    []clientUse
	// loaded is whether users was seeded from the stored value. The
	// first flush after startup has to merge with what is in the
	// database, or a single new user would erase the other two.
	loaded bool
}

// defaultUsageFlushInterval is how long usage may sit unwritten. Long
// enough to collapse a refresh storm, short enough that an admin
// reloading the page after signing in somewhere sees it.
const defaultUsageFlushInterval = 60 * time.Second

// newClientUsageRecorder starts the background flusher. db may be nil,
// in which case every method is a no-op -- the OAuth2 provider is
// optional and callers should not have to check.
func newClientUsageRecorder(db *sql.DB, interval time.Duration) *clientUsageRecorder {
	if interval <= 0 {
		interval = defaultUsageFlushInterval
	}
	r := &clientUsageRecorder{
		db:       db,
		interval: interval,
		pending:  make(map[string]*pendingClientUse),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if db == nil {
		close(r.done)
		return r
	}
	go r.loop()
	return r
}

// Record notes that clientID issued a token for subject. It never
// blocks on the database. An empty subject still records the use --
// a client-credentials style grant has no end user, and "used at
// 14:02 by nobody in particular" is still worth showing.
func (r *clientUsageRecorder) Record(clientID, subject string, at time.Time) {
	if r == nil || r.db == nil || clientID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	p := r.pending[clientID]
	if p == nil {
		p = &pendingClientUse{}
		r.pending[clientID] = p
	}
	if at.After(p.lastUsed) {
		p.lastUsed = at
	}
	if subject != "" {
		p.users = mergeRecentUsers(p.users, clientUse{Subject: subject, At: at})
	}
}

// mergeRecentUsers puts use at the front, drops any earlier entry for
// the same subject, and caps the result. Deduplicating by subject is
// what makes the sample useful: three entries for one busy service
// account would say less than one entry each for three people.
func mergeRecentUsers(existing []clientUse, use clientUse) []clientUse {
	out := make([]clientUse, 0, maxRecentUsers)
	out = append(out, use)
	for _, e := range existing {
		if e.Subject == use.Subject {
			continue
		}
		if len(out) == maxRecentUsers {
			break
		}
		out = append(out, e)
	}
	return out
}

func (r *clientUsageRecorder) loop() {
	defer close(r.done)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.flush(context.Background())
		case <-r.stop:
			// Flush what accumulated since the last tick so an orderly
			// shutdown does not drop it.
			r.flush(context.Background())
			return
		}
	}
}

// flush writes every pending client's state. Errors are dropped: this
// is a display field, the next tick will retry with newer data anyway,
// and there is no caller to report to.
func (r *clientUsageRecorder) flush(ctx context.Context) {
	r.mu.Lock()
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return
	}
	batch := r.pending
	r.pending = make(map[string]*pendingClientUse)
	r.mu.Unlock()

	for clientID, p := range batch {
		if err := r.writeOne(ctx, clientID, p); err != nil {
			// Put the entry back so the next tick retries it, unless
			// something newer already arrived for that client.
			r.mu.Lock()
			if _, superseded := r.pending[clientID]; !superseded {
				r.pending[clientID] = p
			}
			r.mu.Unlock()
		}
	}
}

// writeOne merges a client's pending state with what is stored and
// writes it back. The read-merge-write is why this is not a plain
// UPDATE: the recent-users sample spans process restarts, so the first
// write after startup has to see the stored entries or it would replace
// three known users with the one it just saw.
func (r *clientUsageRecorder) writeOne(ctx context.Context, clientID string, p *pendingClientUse) error {
	if !p.loaded {
		var stored string
		err := r.db.QueryRowContext(ctx,
			`SELECT recent_users FROM oauth2_clients WHERE id = ?`, clientID).Scan(&stored)
		if err != nil {
			if err == sql.ErrNoRows {
				// The client was deleted between issuing a token and
				// this flush. Nothing to update, and no point retrying.
				return nil
			}
			return fmt.Errorf("reading recent users for %s: %w", clientID, err)
		}
		var existing []clientUse
		if stored != "" {
			_ = json.Unmarshal([]byte(stored), &existing)
		}
		// The pending entries are newer than anything stored, so they
		// keep their positions and the stored ones fill in behind.
		merged := p.users
		for _, e := range existing {
			if len(merged) >= maxRecentUsers {
				break
			}
			if containsSubject(merged, e.Subject) {
				continue
			}
			merged = append(merged, e)
		}
		p.users = merged
		p.loaded = true
	}

	encoded, err := json.Marshal(p.users)
	if err != nil {
		return fmt.Errorf("encoding recent users for %s: %w", clientID, err)
	}
	if len(p.users) == 0 {
		// Leave whatever sample is stored rather than blanking it: a
		// client-credentials grant with no subject should not erase the
		// users we already know about.
		_, err = r.db.ExecContext(ctx,
			`UPDATE oauth2_clients SET last_used_at = ? WHERE id = ?`, p.lastUsed, clientID)
		return err
	}
	_, err = r.db.ExecContext(ctx,
		`UPDATE oauth2_clients SET last_used_at = ?, recent_users = ? WHERE id = ?`,
		p.lastUsed, string(encoded), clientID)
	return err
}

func containsSubject(users []clientUse, subject string) bool {
	for _, u := range users {
		if u.Subject == subject {
			return true
		}
	}
	return false
}

// Close stops the flusher after one final write. Safe to call more than
// once and on a nil recorder.
func (r *clientUsageRecorder) Close() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.stop) })
	<-r.done
}

// FlushNow writes pending state immediately. For tests and for the
// places that want the admin UI to reflect an action right away.
func (r *clientUsageRecorder) FlushNow(ctx context.Context) {
	if r == nil || r.db == nil {
		return
	}
	r.flush(ctx)
}

// markSeededClient labels a client this server created itself, so the
// admin list can tell it apart from one that registered over the wire.
// Failure is logged, not returned: the client works either way and the
// caller is a best-effort startup path.
func (h *Handler) markSeededClient(ctx context.Context, clientID, name string) {
	if h.oauth2Provider == nil {
		return
	}
	if err := setClientProvenance(ctx, h.oauth2Provider.GetStorage().GetDB(),
		clientID, name, ClientOriginSeeded); err != nil {
		h.logger.Warn(logging.DestinationHTTP, "Failed to label seeded OAuth2 client",
			"client_id", clientID, "error", err)
	}
}
