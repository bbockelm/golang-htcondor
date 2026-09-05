package httpserver

import (
	"sync"
	"time"
)

// defaultSuperuserArmTTL is how long superuser mode stays armed before it
// disarms itself.
//
// An admin who turns the mode on to fix one job and then walks away should not
// leave a session that silently acts on other people's jobs for the rest of
// the day. The banner is the primary defence against inadvertent action; this
// is the one that works when nobody is looking at the screen.
const defaultSuperuserArmTTL = 30 * time.Minute

// superuserSessions tracks which browser sessions currently have superuser
// mode armed.
//
// Deliberately in memory rather than in the http_sessions table. A restart
// disarms every session, which is the right default for a mode this
// dangerous: coming back up in a state where some browser somewhere is still
// authorised to act as anyone, with nobody having re-affirmed it, is worse
// than making an admin click the button again.
type superuserSessions struct {
	mu  sync.RWMutex
	on  map[string]time.Time // session id -> when it disarms
	ttl time.Duration
}

func newSuperuserSessions(ttl time.Duration) *superuserSessions {
	if ttl <= 0 {
		ttl = defaultSuperuserArmTTL
	}
	return &superuserSessions{on: make(map[string]time.Time), ttl: ttl}
}

// Arm turns the mode on for a session and returns when it will disarm.
func (s *superuserSessions) Arm(sessionID string) time.Time {
	until := time.Now().Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.on[sessionID] = until
	return until
}

// Disarm turns it off.
func (s *superuserSessions) Disarm(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.on, sessionID)
}

// Armed reports whether the mode is on for a session, and until when.
//
// Expiry is enforced on read rather than by a sweeper: the only thing that
// matters is that an expired session cannot act, and checking here means that
// is true the instant it expires regardless of when a sweep would have run.
func (s *superuserSessions) Armed(sessionID string) (bool, time.Time) {
	if sessionID == "" {
		return false, time.Time{}
	}
	s.mu.RLock()
	until, ok := s.on[sessionID]
	s.mu.RUnlock()
	if !ok {
		return false, time.Time{}
	}
	if time.Now().After(until) {
		// Drop the stale entry so the map does not grow without bound
		// across a long-lived process.
		s.mu.Lock()
		if cur, still := s.on[sessionID]; still && !cur.After(time.Now()) {
			delete(s.on, sessionID)
		}
		s.mu.Unlock()
		return false, time.Time{}
	}
	return true, until
}

// Count returns how many sessions currently have the mode armed, for the
// admin view and for logging at shutdown.
func (s *superuserSessions) Count() int {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, until := range s.on {
		if until.After(now) {
			n++
		}
	}
	return n
}
