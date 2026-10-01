package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// This file answers "which harness is calling us".
//
// MCP has an answer built in: the client sends clientInfo{name,version}
// on initialize. Nothing else in the protocol identifies the caller --
// a tools/call carries a session id and nothing more -- so the name has
// to be remembered from initialize and looked up again on each call.
// That is what clientRegistry does.
//
// The fallbacks matter as much as the primary, because a session can be
// missing for ordinary reasons rather than hostile ones: stdio has no
// session concept at all, a server restart loses the registry while
// clients keep their session ids, and some clients send no clientInfo.
// In each case the HTTP User-Agent is used instead, and failing that
// the call is recorded as "unknown" rather than dropped.

// clientInfoKey carries the resolved client name for one request.
type clientInfoKey struct{}

// WithClientInfo records the calling harness's identity on the context.
// Called by the transport, which is the only layer that can see either
// the session id or the User-Agent.
func WithClientInfo(ctx context.Context, name string) context.Context {
	if name == "" {
		return ctx
	}
	return context.WithValue(ctx, clientInfoKey{}, name)
}

// ClientInfoFromContext returns the calling harness's identity, or ""
// when nothing identified it.
func ClientInfoFromContext(ctx context.Context) string {
	name, _ := ctx.Value(clientInfoKey{}).(string)
	return name
}

// clientEntry is one remembered session.
type clientEntry struct {
	name string
	seen time.Time
}

// clientRegistry remembers what each MCP session said it was at
// initialize.
//
// It is capped and swept because it is keyed by a value the CLIENT
// chooses. An unbounded map keyed by caller-supplied strings is a
// memory leak with a user-facing trigger, however well-behaved the
// clients in front of it happen to be today.
type clientRegistry struct {
	mu      sync.Mutex
	entries map[string]clientEntry
	max     int
	ttl     time.Duration
	now     func() time.Time
}

const (
	// defaultClientRegistryMax bounds remembered sessions. Well above
	// the number of concurrent MCP clients an access point sees.
	defaultClientRegistryMax = 4096
	// defaultClientRegistryTTL drops a session not seen for this long.
	// MCP sessions are long-lived -- an editor can hold one open for a
	// working day -- so this is generous.
	defaultClientRegistryTTL = 24 * time.Hour
)

func newClientRegistry() *clientRegistry {
	return &clientRegistry{
		entries: map[string]clientEntry{},
		max:     defaultClientRegistryMax,
		ttl:     defaultClientRegistryTTL,
		now:     time.Now,
	}
}

// Remember records the name a session declared at initialize.
func (r *clientRegistry) Remember(sessionID, name string) {
	if sessionID == "" || name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	if _, exists := r.entries[sessionID]; !exists && len(r.entries) >= r.max {
		// Full and this is a new session. Drop the registration rather
		// than evicting someone else's: the call still gets counted,
		// just against its User-Agent.
		return
	}
	r.entries[sessionID] = clientEntry{name: name, seen: r.now()}
}

// Lookup returns the name a session declared, refreshing its liveness
// so an active session is not swept out from under itself.
func (r *clientRegistry) Lookup(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[sessionID]
	if !ok {
		return ""
	}
	e.seen = r.now()
	r.entries[sessionID] = e
	return e.name
}

// sweepLocked drops entries past their TTL. Called on write, which is
// enough: the map only grows on write, so it cannot bloat between them.
func (r *clientRegistry) sweepLocked() {
	cutoff := r.now().Add(-r.ttl)
	for id, e := range r.entries {
		if e.seen.Before(cutoff) {
			delete(r.entries, id)
		}
	}
}

// clientInfoFromInitialize pulls clientInfo.name (and version) out of
// an initialize request's params.
//
// Returns "" when the client sent no clientInfo, which is legal: the
// field is optional in the MCP schema, and plenty of clients omit it.
func clientInfoFromInitialize(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var req struct {
		ClientInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return ""
	}
	return NormalizeClientName(req.ClientInfo.Name, req.ClientInfo.Version)
}

// NormalizeClientName turns a self-declared client name (or a
// User-Agent) into the string recorded against a tool call.
//
// It does NOT map onto an allowlist of known harnesses. An allowlist
// would need editing every time a new MCP client appears, and would
// silently report the new one as "other" until somebody noticed. The
// bounding that keeps the Prometheus label space finite happens in the
// toolstats package, over observed call volume, and applies to any
// value however it was spelled. What happens here is only sanitising:
// a label value has to be printable, bounded in length, and free of the
// characters that would make the exposition format ambiguous.
//
// The version is appended when present, because "which version of the
// harness" is most of the value of knowing the harness at all -- a
// regression that arrives with a client release is otherwise invisible.
func NormalizeClientName(name, version string) string {
	name = sanitizeLabel(name, 48)
	if name == "" {
		return ""
	}
	if version = sanitizeLabel(version, 24); version != "" {
		return name + "/" + version
	}
	return name
}

// sanitizeLabel reduces s to a bounded, printable token.
func sanitizeLabel(s string, limit int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		case r == ' ' || r == '/':
			// A User-Agent is "name/version (comment)"; the separator
			// becomes part of the token rather than splitting it, so
			// "python-httpx/0.27" stays one readable value.
			b.WriteRune('-')
		default:
			// Dropped: anything else would have to be escaped in the
			// exposition format, and a label value that needs escaping
			// is a label value somebody chose badly.
		}
		if b.Len() >= limit {
			break
		}
	}
	return strings.Trim(b.String(), "-._")
}
