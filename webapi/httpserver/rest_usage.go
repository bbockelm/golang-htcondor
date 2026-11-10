package httpserver

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/usagestats"
	"github.com/ory/fosite"
)

// REST usage counting: the same treatment MCP tool calls get, applied
// to the REST API.
//
// The hard part is not the counting -- usagestats does that -- but
// attribution. The metrics middleware sees a request on its way in and
// a status code on its way out, and knows nothing about who sent it:
// identity is resolved deep inside each handler, by
// createAuthenticatedContext, on a context DERIVED from the request's
// rather than written back to it. So this file installs a mutable
// record on the way in, the authentication paths stamp it as they
// resolve things, and the wrapper reads it back on the way out.
//
// A pointer in a context is normally a smell. Here it is the only
// thing that works short of rewriting every handler's signature: the
// value is not known when the context is created, and the code that
// learns it is several frames below the code that needs it.

// restCall is the mutable per-request record.
//
// Guarded by a mutex because a handler may resolve identity from more
// than one goroutine -- a streaming endpoint that authenticates and
// then fans out does exactly that -- and a torn read of a string
// header is a crash, not a wrong number.
type restCall struct {
	mu     sync.Mutex
	actor  string
	client string
}

func (c *restCall) setActor(v string) {
	if c == nil || v == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.actor = v
}

// setClient records how the caller reached us. First writer wins: the
// authentication path knows more than the fallback does, and a later,
// vaguer answer must not overwrite a specific one.
func (c *restCall) setClient(v string) {
	if c == nil || v == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == "" {
		c.client = v
	}
}

func (c *restCall) read() (actor, client string) {
	if c == nil {
		return "", ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.actor, c.client
}

type restCallKey struct{}

func withRESTCall(ctx context.Context, c *restCall) context.Context {
	return context.WithValue(ctx, restCallKey{}, c)
}

func restCallFrom(ctx context.Context) *restCall {
	c, _ := ctx.Value(restCallKey{}).(*restCall)
	return c
}

// noteRESTActor records the identity a request authenticated as.
//
// Safe to call from anywhere with a request-derived context, including
// one with no record installed (a test, an MCP request, work started
// on a background context): it is then a map lookup and a return.
func noteRESTActor(ctx context.Context, user string) {
	restCallFrom(ctx).setActor(user)
}

// noteRESTClient records what the caller is, when the authentication
// path knows something better than the User-Agent.
func noteRESTClient(ctx context.Context, client string) {
	restCallFrom(ctx).setClient(client)
}

// Client values with a meaning of their own. The OAuth2 one is a
// PREFIX over the client id rather than the client's display name:
// the durable table should not change its mind about a series because
// an admin renamed a client, and the id is what Prometheus can safely
// keep. The name is resolved for display only -- see clientNameCache.
const (
	// restClientWebUI is this server's own single-page app, which is
	// the only thing that authenticates with the session cookie.
	restClientWebUI = "web UI"
	// restClientOAuthPrefix is followed by the OAuth2 client id.
	restClientOAuthPrefix = "oauth:"
	// restClientAPIKeyPrefix is followed by the API key's name, which
	// an admin chose and which is already what the API keys page
	// shows.
	restClientAPIKeyPrefix = "api key:"
)

// oauthClientLabel is the client string recorded for an OAuth2 grant:
// the client id behind a prefix. The id rather than the display name
// because the stats are durable and a name is not -- see
// clientNameCache, which translates one into the other for display.
func oauthClientLabel(ar fosite.AccessRequester) string {
	if ar == nil || ar.GetClient() == nil {
		return ""
	}
	id := ar.GetClient().GetID()
	if id == "" {
		return ""
	}
	return restClientOAuthPrefix + id
}

// maxClientLength bounds a client string built from a User-Agent. The
// product token is normally under 30 characters; the bound is for a
// caller that sends something else.
const maxClientLength = 48

// restClientFromUserAgent reduces a User-Agent to its product token:
// "curl/8.4.0" to "curl", "python-httpx/0.27.0" to "python-httpx".
//
// The version is dropped on purpose. Keeping it would mint a new
// series on every client upgrade -- and, for a browser, on every
// patch release of every browser -- which is exactly the unbounded
// growth the label ceiling exists to stop, except that it would be
// reached through the durable table as well.
func restClientFromUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return ""
	}
	if i := strings.IndexAny(ua, "/ "); i > 0 {
		ua = ua[:i]
	}
	if len(ua) > maxClientLength {
		ua = ua[:maxClientLength]
	}
	return ua
}

// restOutcome maps a status code onto the REST outcome vocabulary.
//
// The split is by what an operator would do about it: 'denied' is
// policy working, 'rate_limited' is policy working under load,
// 'not_found' is usually a stale client or a job that has left the
// queue, 'client_error' is a request this server understood and
// judged wrong, and 'error' is this server failing. A single
// "non-2xx" bucket would report all five as the same incident.
func restOutcome(status int) string {
	switch {
	case status < 400:
		// 1xx, 2xx and 3xx. A redirect is this server answering
		// correctly -- the sign-in flow is mostly redirects -- and
		// counting those as failures would make every login look like
		// one.
		return usagestats.OutcomeOK
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return usagestats.OutcomeDenied
	case status == http.StatusNotFound:
		return usagestats.OutcomeNotFound
	case status == http.StatusTooManyRequests:
		return usagestats.OutcomeRateLimited
	case status < 500:
		return usagestats.OutcomeClientError
	default:
		return usagestats.OutcomeError
	}
}

// restUsageName is what a request is counted under: the method and the
// route template, as "GET /api/v1/jobs/{id}".
//
// The method is part of the name because GET and DELETE on one path
// are different operations carrying different risk, and a page that
// folded them together could not answer "who is removing jobs".
//
// Returns "" for a request this page does not count. The REST API is
// /api/v1; health probes, static assets, the sign-in redirects and the
// MCP endpoints are either not it or counted elsewhere -- MCP has its
// own store, and letting its traffic appear in both would double-count
// the same calls on one page.
func restUsageName(method, path string) string {
	if !strings.HasPrefix(path, "/api/v1/") {
		return ""
	}
	return normalizeMethod(method) + " " + classifyRoute(path)
}

// recordRESTCall counts one finished request.
func (h *Handler) recordRESTCall(name string, c *restCall, status int, d time.Duration) {
	if h.restStats == nil || name == "" {
		return
	}
	actor, client := c.read()
	h.restStats.Record(name, actor, client, restOutcome(status), d)
}

// clientNameCache turns an OAuth2 client id into the name the admin
// Clients page shows.
//
// It exists so the request path never has to: resolving a name is a
// database read, and the thing that needs it is a page an admin loads
// occasionally. The stats keep the id, which is stable and bounded;
// this translates ids to names when the summary is rendered, and only
// then.
type clientNameCache struct {
	mu      sync.Mutex
	names   map[string]string
	fetched time.Time
}

// clientNameTTL is how long a resolved set of names is reused. Short
// enough that renaming a client shows up on the next page load or two,
// long enough that a 30-second refresh does not read the table every
// time.
const clientNameTTL = time.Minute

func newClientNameCache() *clientNameCache {
	return &clientNameCache{names: map[string]string{}}
}

// resolve replaces "oauth:<id>" with the client's name where one is
// known, leaving every other client string alone.
//
// An id with no name -- a client deleted since it last called, or one
// registered without a name -- keeps the "oauth:<id>" form. That is
// deliberately not prettified: it says the series belongs to an OAuth2
// client this server can no longer describe, which is different from a
// client that calls itself something.
func (c *clientNameCache) resolve(ctx context.Context, db *sql.DB, client string) string {
	if c == nil || !strings.HasPrefix(client, restClientOAuthPrefix) {
		return client
	}
	id := strings.TrimPrefix(client, restClientOAuthPrefix)
	if name := c.lookup(ctx, db, id); name != "" {
		return name
	}
	return client
}

func (c *clientNameCache) lookup(ctx context.Context, db *sql.DB, id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if db != nil && time.Since(c.fetched) > clientNameTTL {
		c.refreshLocked(ctx, db)
	}
	return c.names[id]
}

// refreshLocked re-reads the client names. A failure leaves the
// previous map in place and is not reported: the caller's fallback --
// showing the id -- is a correct answer, and an admin page that
// refused to render because it could not prettify a label would be a
// worse one.
func (c *clientNameCache) refreshLocked(ctx context.Context, db *sql.DB) {
	// Mark the attempt whatever happens, so a database that is down
	// does not turn every page load into another failing query.
	c.fetched = time.Now()
	rows, err := db.QueryContext(ctx, `SELECT id, client_name FROM oauth2_clients`)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	names := map[string]string{}
	for rows.Next() {
		var id string
		var name sql.NullString
		if err := rows.Scan(&id, &name); err != nil {
			continue
		}
		if n := strings.TrimSpace(name.String); n != "" {
			names[id] = n
		}
	}
	if rows.Err() != nil {
		return
	}
	c.names = names
}
