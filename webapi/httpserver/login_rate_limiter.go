package httpserver

import (
	"container/list"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// LoginRateLimiter is a token bucket per key -- a source address, a
// username -- for endpoints an unauthenticated caller can reach.
//
// The key space is chosen by the caller, so the table is bounded: no
// goroutine per key, and at most maxKeys entries. Entries are kept in
// recency order. One untouched for longer than its bucket takes to
// refill is indistinguishable from a new one and is dropped as the
// limiter is used; past the cap the least recently used entry goes,
// which is never the key somebody is busy hammering.
type LoginRateLimiter struct {
	mu      sync.Mutex
	rate    rate.Limit // requests per second
	burst   int        // maximum burst size
	maxKeys int
	keys    map[string]*list.Element
	lru     *list.List // of *loginLimiterEntry, most recently used first
	now     func() time.Time
}

type loginLimiterEntry struct {
	key     string
	limiter *rate.Limiter
	lastUse time.Time
}

// loginLimiterMaxKeys bounds the keys one limiter tracks.
const loginLimiterMaxKeys = 10000

// NewLoginRateLimiter creates a new login rate limiter
// rate: maximum requests per second per key
// burst: maximum burst size per key
func NewLoginRateLimiter(r rate.Limit, b int) *LoginRateLimiter {
	return &LoginRateLimiter{
		rate:    r,
		burst:   b,
		maxKeys: loginLimiterMaxKeys,
		keys:    make(map[string]*list.Element),
		lru:     list.New(),
		now:     time.Now,
	}
}

// refill is how long an empty bucket takes to fill.
func (l *LoginRateLimiter) refill() time.Duration {
	if l.rate <= 0 {
		return 0
	}
	return time.Duration(float64(l.burst) / float64(l.rate) * float64(time.Second))
}

// Allow spends one attempt from key's budget and reports whether there
// was one to spend.
func (l *LoginRateLimiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if refill := l.refill(); refill > 0 {
		for back := l.lru.Back(); back != nil; back = l.lru.Back() {
			e := back.Value.(*loginLimiterEntry)
			if now.Sub(e.lastUse) < refill {
				break
			}
			l.lru.Remove(back)
			delete(l.keys, e.key)
		}
	}

	var e *loginLimiterEntry
	if elem, ok := l.keys[key]; ok {
		e = elem.Value.(*loginLimiterEntry)
		l.lru.MoveToFront(elem)
	} else {
		for l.lru.Len() >= l.maxKeys {
			back := l.lru.Back()
			l.lru.Remove(back)
			delete(l.keys, back.Value.(*loginLimiterEntry).key)
		}
		e = &loginLimiterEntry{key: key, limiter: rate.NewLimiter(l.rate, l.burst)}
		l.keys[key] = l.lru.PushFront(e)
	}
	e.lastUse = now
	return e.limiter.AllowN(now, 1)
}

// size is the number of keys currently tracked.
func (l *LoginRateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.Len()
}
