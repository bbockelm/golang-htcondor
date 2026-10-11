package apassign

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Defaults for Options.
const (
	// DefaultTimeout bounds one backend's answer. A slow backend is a
	// slow submit, so this is a hard limit, not the HTTP client default.
	DefaultTimeout = 2 * time.Second
	// DefaultStale is how long a user's last known good answer is used
	// while the backend that should answer is failing.
	DefaultStale = time.Hour
	// DefaultCacheSize caps the per-user cache.
	DefaultCacheSize = 10000
	// MaxTTL caps how long any answer is reused, whatever its backend
	// asked for: a remote service that answers "forever" must not pin a
	// user to an AP until the next restart.
	MaxTTL = time.Hour
	// fallbackTTL is the TTL of an answer whose backend states none.
	fallbackTTL = time.Minute
)

// SourceDefault is Assignment.Source for HTTP_API_AP_ASSIGNMENT_DEFAULT.
const SourceDefault = "default"

// Backend is one link of the chain.
type Backend struct {
	// Name is the backend as configured ("static", "mapfile", "rest"),
	// and the Source of its answers.
	Name     string
	Assigner Assigner
	// DefaultTTL is the TTL of an answer that states none; zero means a
	// minute.
	DefaultTTL time.Duration
}

// Logger receives what the chain has to say. A nil Logger is silent.
type Logger interface {
	Error(msg string, args ...any)
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}

// Options tunes a Chain. The zero value is the default.
type Options struct {
	// Default is HTTP_API_AP_ASSIGNMENT_DEFAULT: the answer when every
	// backend says ErrNoAnswer. Empty refuses such a user with 403.
	Default string
	// Stale is HTTP_API_AP_ASSIGNMENT_STALE_SECONDS; zero means
	// DefaultStale, negative means a backend error is never covered.
	Stale time.Duration
	// Timeout per backend; zero means DefaultTimeout.
	Timeout time.Duration
	// CacheSize caps the per-user cache; zero means DefaultCacheSize.
	CacheSize int
	// InSet resolves a schedd name to the AP set's spelling of it, and
	// reports whether it is a member at all. Nil accepts every name
	// (single-AP mode has no set to check against).
	InSet func(name string) (string, bool)
	// Usable reports why a member cannot take work right now (absent
	// from the collector, untrusted), or nil.
	Usable func(name string) error
	// Now replaces the clock, for tests.
	Now    func() time.Time
	Logger Logger
}

// generationer is a backend whose answers can change without its TTL
// running out -- a mapfile that was edited. A cached answer from an older
// generation is not reused.
type generationer interface{ Generation() uint64 }

// reloader is a backend with state to re-read on reconfigure.
type reloader interface{ Reload() error }

// errNone is the outcome when no backend answered and there is no
// default.
var errNone = errors.New("no backend answered")

// outcome is one resolution: an assignment, ErrDenied or errNone.
type outcome struct {
	a   Assignment
	err error
}

type entry struct {
	out outcome
	// at is when the answer was obtained: the last-known-good window
	// runs from here.
	at      time.Time
	expires time.Time
	gen     uint64
}

// Chain asks its backends in order; the first to answer wins.
//
// Everything a backend should not have to get right on its own is here:
//
//   - Errors do not fall through. A broken backend must not silently send
//     everyone to the next backend or the default. On error the user's
//     last known good answer is used for up to Options.Stale, then the
//     request is refused with 503.
//   - Each backend has a hard timeout.
//   - Answers are cached per user and kind for their TTL, capped.
//   - Answers are validated against the AP set: a typo or a remote
//     service cannot send work outside it.
type Chain struct {
	backends []Backend
	opts     Options

	mu      sync.Mutex
	cache   map[string]*entry
	lastErr string // the last backend failure logged, so an outage logs once
}

// NewChain builds a chain. An empty chain is allowed: every user then
// gets the default, or 403 without one.
func NewChain(backends []Backend, opts Options) (*Chain, error) {
	seen := map[string]bool{}
	for i, b := range backends {
		if b.Assigner == nil {
			return nil, fmt.Errorf("access point assignment backend %q has no implementation", b.Name)
		}
		if seen[b.Name] {
			return nil, fmt.Errorf("access point assignment backend %q is listed twice", b.Name)
		}
		seen[b.Name] = true
		if _, ok := b.Assigner.(*Static); ok && i != len(backends)-1 {
			return nil, fmt.Errorf("access point assignment backend %q answers for everyone, so %q after it would never be asked; "+
				"put it last", b.Name, backends[i+1].Name)
		}
	}
	if opts.Stale == 0 {
		opts.Stale = DefaultStale
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.CacheSize <= 0 {
		opts.CacheSize = DefaultCacheSize
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	opts.Default = strings.TrimSpace(opts.Default)
	return &Chain{backends: backends, opts: opts, cache: map[string]*entry{}}, nil
}

// Backends names the backends in order.
func (c *Chain) Backends() []string {
	out := make([]string, len(c.backends))
	for i, b := range c.backends {
		out[i] = b.Name
	}
	return out
}

// Default is the configured last-resort schedd, or "".
func (c *Chain) Default() string { return c.opts.Default }

// Reload re-reads every backend's state (a mapfile, a token file) and
// drops cached answers. Called on reconfigure. A backend that fails to
// reload keeps what it had; the first such error is returned.
func (c *Chain) Reload() error {
	var first error
	for _, b := range c.backends {
		if r, ok := b.Assigner.(reloader); ok {
			if err := r.Reload(); err != nil && first == nil {
				first = fmt.Errorf("%s: %w", b.Name, err)
			}
		}
	}
	c.Invalidate()
	return first
}

// Invalidate drops every cached answer, last known good ones included.
func (c *Chain) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = map[string]*entry{}
}

// generation is the sum of the backends' generations: it changes when
// any of them does.
func (c *Chain) generation() uint64 {
	var g uint64
	for _, b := range c.backends {
		if gb, ok := b.Assigner.(generationer); ok {
			g += gb.Generation()
		}
	}
	return g
}

func cacheKey(req Request) string { return req.Kind + "\x00" + req.User }

// Assign implements Assigner: the user's validated assignment.
func (c *Chain) Assign(ctx context.Context, req Request) (Assignment, error) {
	return c.Resolve(ctx, req)
}

// Resolve returns the user's assignment, validated against the AP set.
// It does not check that the home AP can take work right now; Target
// does, for whichever AP a submission actually goes to.
func (c *Chain) Resolve(ctx context.Context, req Request) (Assignment, error) {
	if strings.TrimSpace(req.User) == "" {
		return Assignment{}, errorf(http.StatusUnauthorized, "", nil, "the caller's identity could not be established")
	}
	out, err := c.outcome(ctx, req)
	if err != nil {
		return Assignment{}, err
	}
	switch {
	case errors.Is(out.err, ErrDenied):
		return Assignment{}, errorf(http.StatusForbidden, ReasonDenied, ErrDenied,
			"you may not submit work through this server (refused by the %s access point assignment)", out.a.Source)
	case out.err != nil:
		return Assignment{}, errorf(http.StatusForbidden, ReasonNoAssignment, ErrNoAnswer, "no access point is assigned to you")
	}
	return c.validate(out.a, req.User)
}

// Target picks the AP a submission goes to: the home AP, or explicit when
// it names the home AP or an alternate. The AP must be able to take work
// now. It returns the AP's name and the assignment it came from.
func (c *Chain) Target(ctx context.Context, req Request, explicit string) (string, Assignment, error) {
	a, err := c.Resolve(ctx, req)
	if err != nil {
		return "", Assignment{}, err
	}
	target := a.Schedd
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		name, ok := a.Allows(explicit)
		if !ok {
			msg := fmt.Sprintf("you may submit to %s", a.Schedd)
			if len(a.Alternates) > 0 {
				msg += " or " + strings.Join(a.Alternates, ", ")
			}
			return "", a, errorf(http.StatusForbidden, ReasonTargetNotAllowed, nil, "%s, not %s", msg, explicit)
		}
		target = name
	}
	if c.opts.Usable != nil {
		if err := c.opts.Usable(target); err != nil {
			return "", a, errorf(http.StatusServiceUnavailable, ReasonTargetUnusable, err,
				"access point %s cannot take new work right now: %v", target, err)
		}
	}
	return target, a, nil
}

// validate resolves the assignment's names against the AP set. A home AP
// outside the set is a 503 and an error log: work is never sent outside
// the set, and a configuration that tries to is the operator's to fix,
// not the user's. An alternate outside the set is dropped, and logged.
func (c *Chain) validate(a Assignment, user string) (Assignment, error) {
	if c.opts.InSet == nil {
		return a, nil
	}
	name, ok := c.opts.InSet(a.Schedd)
	if !ok {
		c.logError("Access point assignment names an access point outside the AP set; refusing to submit",
			"user", user, "schedd", a.Schedd, "source", a.Source)
		return Assignment{}, errorf(http.StatusServiceUnavailable, ReasonInvalid, nil,
			"your access point assignment names %q, which is not an access point this server serves; "+
				"the server's administrators have been told", a.Schedd)
	}
	out := a
	out.Schedd = name
	out.Alternates = nil
	for _, alt := range a.Alternates {
		n, ok := c.opts.InSet(alt)
		if !ok {
			c.logError("Access point assignment names an alternate outside the AP set; ignoring it",
				"user", user, "alternate", alt, "source", a.Source)
			continue
		}
		if _, dup := out.Allows(n); dup {
			continue
		}
		out.Alternates = append(out.Alternates, n)
	}
	return out, nil
}

// outcome returns the cached answer, a fresh one, or -- when a backend
// fails -- the last known good one. A backend failure with nothing
// recent to fall back on is a 503.
func (c *Chain) outcome(ctx context.Context, req Request) (outcome, error) {
	key := cacheKey(req)
	gen := c.generation()
	now := c.opts.Now()
	c.mu.Lock()
	e, ok := c.cache[key]
	if ok && e.gen == gen && now.Before(e.expires) {
		out := e.out
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()

	out, ttl, err := c.ask(ctx, req)
	now = c.opts.Now()
	if err != nil {
		c.mu.Lock()
		e, ok := c.cache[key]
		var lkg *outcome
		if ok && c.opts.Stale > 0 && now.Sub(e.at) <= c.opts.Stale {
			o := e.out
			lkg = &o
		}
		logIt := err.Error() != c.lastErr
		c.lastErr = err.Error()
		c.mu.Unlock()
		if lkg != nil {
			if logIt {
				c.logWarn("Access point assignment backend failed; using last known good answers",
					"error", err, "stale_limit", c.opts.Stale)
			}
			lkg.a.Stale = true
			return *lkg, nil
		}
		c.logError("Access point assignment backend failed, and this user has no recent answer to fall back on",
			"user", req.User, "error", err)
		return outcome{}, errorf(http.StatusServiceUnavailable, ReasonUnavailable, err,
			"access point assignment is unavailable right now; try again shortly")
	}
	c.mu.Lock()
	c.lastErr = ""
	c.put(key, &entry{out: out, at: now, expires: now.Add(ttl), gen: gen}, now)
	c.mu.Unlock()
	return out, nil
}

// ask runs the chain once.
func (c *Chain) ask(ctx context.Context, req Request) (outcome, time.Duration, error) {
	shortest := time.Duration(0)
	for _, b := range c.backends {
		def := b.DefaultTTL
		if def <= 0 {
			def = fallbackTTL
		}
		if shortest == 0 || def < shortest {
			shortest = def
		}
		a, err := c.call(ctx, b, req)
		switch {
		case err == nil:
			if strings.TrimSpace(a.Schedd) == "" {
				return outcome{}, 0, fmt.Errorf("%s answered with no schedd", b.Name)
			}
			a.Schedd = strings.TrimSpace(a.Schedd)
			if a.Source == "" {
				a.Source = b.Name
			}
			ttl := a.TTL
			if ttl <= 0 {
				ttl = def
			}
			ttl = min(ttl, MaxTTL)
			a.TTL = ttl
			a.Stale = false
			return outcome{a: a}, ttl, nil
		case errors.Is(err, ErrNoAnswer):
			continue
		case errors.Is(err, ErrDenied):
			return outcome{a: Assignment{Source: b.Name}, err: ErrDenied}, min(def, MaxTTL), nil
		default:
			return outcome{}, 0, fmt.Errorf("%s: %w", b.Name, err)
		}
	}
	if shortest == 0 {
		shortest = fallbackTTL
	}
	if c.opts.Default != "" {
		return outcome{a: Assignment{Schedd: c.opts.Default, Source: SourceDefault, TTL: shortest}}, shortest, nil
	}
	return outcome{err: errNone}, shortest, nil
}

// call asks one backend, giving up after the timeout even if the backend
// ignores its context.
func (c *Chain) call(ctx context.Context, b Backend, req Request) (Assignment, error) {
	tctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	type result struct {
		a   Assignment
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- result{err: fmt.Errorf("panicked: %v", p)}
			}
		}()
		a, err := b.Assigner.Assign(tctx, req)
		ch <- result{a, err}
	}()
	select {
	case r := <-ch:
		return r.a, r.err
	case <-tctx.Done():
		return Assignment{}, fmt.Errorf("no answer within %s: %w", c.opts.Timeout, tctx.Err())
	}
}

// put stores an entry, evicting to stay within the cap: first entries
// past both their TTL and the last-known-good window, then the oldest.
// c.mu is held.
func (c *Chain) put(key string, e *entry, now time.Time) {
	if _, ok := c.cache[key]; !ok && len(c.cache) >= c.opts.CacheSize {
		for k, old := range c.cache {
			if now.After(old.expires) && (c.opts.Stale <= 0 || now.Sub(old.at) > c.opts.Stale) {
				delete(c.cache, k)
			}
		}
		for len(c.cache) >= c.opts.CacheSize {
			oldestKey, oldestAt := "", time.Time{}
			for k, old := range c.cache {
				if oldestKey == "" || old.at.Before(oldestAt) {
					oldestKey, oldestAt = k, old.at
				}
			}
			delete(c.cache, oldestKey)
		}
	}
	c.cache[key] = e
}

// cached reports how many answers are cached. Tests only.
func (c *Chain) cached() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cache)
}

func (c *Chain) logError(msg string, args ...any) {
	if c.opts.Logger != nil {
		c.opts.Logger.Error(msg, args...)
	}
}

func (c *Chain) logWarn(msg string, args ...any) {
	if c.opts.Logger != nil {
		c.opts.Logger.Warn(msg, args...)
	}
}
