package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Caps on long-lived streams: the SSE watches, the activity stream, the
// Jupyter event stream and the share-URL wait.
//
// Each one holds a connection, a goroutine and -- where no mirror feed
// can answer -- a schedd poll, for up to half an hour. Without a cap one
// caller opening streams faster than they end has no limit but the
// process's descriptors, and every poll they start lands on the schedd.
const (
	// defaultMaxStreamsPerUser is how many streams one identity may hold
	// at once: several tabs each watching a few jobs, with room to spare.
	defaultMaxStreamsPerUser = 16
	// defaultMaxStreams is how many streams the server holds in all.
	defaultMaxStreams = 2048
	// streamRetryAfter is the Retry-After a refused stream is given, in
	// seconds.
	streamRetryAfter = "30"
)

// streamLimiter counts open streams per identity and in all.
type streamLimiter struct {
	maxPerUser int
	maxTotal   int

	mu      sync.Mutex
	total   int
	perUser map[string]int
}

func newStreamLimiter(maxPerUser, maxTotal int) *streamLimiter {
	return &streamLimiter{maxPerUser: maxPerUser, maxTotal: maxTotal, perUser: map[string]int{}}
}

// acquire claims a stream for who and returns its release, or reports
// false when who, or the server, is at its cap. An empty who is counted
// like any other identity, so callers nobody named share one budget
// rather than each getting their own.
func (l *streamLimiter) acquire(who string) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.perUser[who] >= l.maxPerUser {
		return nil, false
	}
	l.total++
	l.perUser[who]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.perUser[who] <= 1 {
				delete(l.perUser, who)
			} else {
				l.perUser[who]--
			}
		})
	}, true
}

func (h *Handler) streamLimits() *streamLimiter {
	h.streamLimiterOnce.Do(func() {
		if h.streamLimiterVal == nil {
			h.streamLimiterVal = newStreamLimiter(defaultMaxStreamsPerUser, defaultMaxStreams)
		}
	})
	return h.streamLimiterVal
}

// admitStream claims a stream slot for who before a long-lived response
// is committed. When who or the server is at its cap it answers 429 and
// reports false; otherwise the caller must call the returned release when
// the stream ends.
func (h *Handler) admitStream(w http.ResponseWriter, who string) (func(), bool) {
	release, ok := h.streamLimits().acquire(who)
	if !ok {
		w.Header().Set("Retry-After", streamRetryAfter)
		h.writeError(w, http.StatusTooManyRequests,
			"too many streams are open; close one, or try again later")
		return nil, false
	}
	return release, true
}

// authenticateStream authenticates a request for a long-lived stream and
// claims its slot (see admitStream). On false the response has been
// written; otherwise the caller must call release when the stream ends.
func (h *Handler) authenticateStream(w http.ResponseWriter, r *http.Request) (context.Context, func(), bool) {
	ctx, needsRedirect, err := h.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			h.redirectToLogin(w, r)
			return nil, nil, false
		}
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return nil, nil, false
	}
	release, ok := h.admitStream(w, htcondor.GetAuthenticatedUserFromContext(ctx))
	if !ok {
		return nil, nil, false
	}
	return ctx, release, true
}
