// Package appolicy reads the part of an access point's configuration that
// decides how a user's jobs are submitted and treated -- job limits,
// submit requirements, transforms, request defaults, the system hold and
// remove policy, transfer limits, DAGMan throttles -- and renders it as
// prose an agent can act on.
//
// The values come from the SCHEDD (DC_CONFIG_VAL), never from this
// server's own configuration. The server may run in a container with a
// configuration of its own; what applies to a job is what the access
// point's daemons were configured with.
//
// What is read is an allowlist. An HTCondor configuration holds paths,
// hostnames and secrets, and nothing outside the knobs named here is ever
// asked for or returned.
package appolicy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ConfigSource is the part of *htcondor.Schedd the policy is read through.
type ConfigSource interface {
	ConfigVal(ctx context.Context, name string) (value string, ok bool, err error)
}

// Defaults for a Cache.
const (
	// DefaultTTL is how long one reading of an access point's policy is
	// served. Configuration changes rarely, and each knob costs the
	// schedd a connection.
	DefaultTTL = 10 * time.Minute
	// DefaultConcurrency bounds the connections one reading opens at once.
	DefaultConcurrency = 8
	// DefaultFetchTimeout bounds one reading of every knob.
	DefaultFetchTimeout = 60 * time.Second
	// maxNames bounds each *_NAMES list. A list longer than this is a
	// configuration mistake, and following it would open a connection
	// per name.
	maxNames = 32
)

// Value is one knob as the schedd reported it.
type Value struct {
	// Raw is the value, trimmed, or "" when unset.
	Raw string
	// Set is true when the knob has a non-empty value.
	Set bool
	// Err is why the schedd could not be asked; Raw and Set are then
	// meaningless.
	Err error
	// Asked is false for a knob this reading never requested.
	Asked bool
}

// Snapshot is one reading of an access point's policy.
type Snapshot struct {
	// AccessPoint names the access point, as the caller did.
	AccessPoint string
	// FetchedAt is when the reading finished.
	FetchedAt time.Time
	values    map[string]Value
	// truncated records *_NAMES lists cut at maxNames, by list knob.
	truncated map[string]int
}

// Get returns one knob. A knob this reading never asked for comes back
// with Asked false.
func (s *Snapshot) Get(name string) Value {
	if s == nil {
		return Value{}
	}
	return s.values[strings.ToUpper(name)]
}

// NewSnapshot builds a Snapshot from known values, for tests and for a
// caller that read the knobs some other way. Every knob not named reads
// as asked and unset.
func NewSnapshot(ap string, at time.Time, values map[string]string) *Snapshot {
	upper := make(map[string]string, len(values))
	for k, v := range values {
		upper[strings.ToUpper(k)] = v
	}
	s := &Snapshot{AccessPoint: ap, FetchedAt: at, values: map[string]Value{}, truncated: map[string]int{}}
	for _, name := range knobsToRead(func(name string) string { return upper[strings.ToUpper(name)] }) {
		raw := strings.TrimSpace(upper[strings.ToUpper(name)])
		s.values[strings.ToUpper(name)] = Value{Raw: raw, Set: raw != "", Asked: true}
	}
	for k, v := range upper {
		if _, ok := s.values[k]; !ok {
			raw := strings.TrimSpace(v)
			s.values[k] = Value{Raw: raw, Set: raw != "", Asked: true}
		}
	}
	return s
}

// Cache holds one Snapshot per access point.
//
// A reading is shared by everyone who asks during it, and is made on a
// context detached from the caller who started it: an agent that gives
// up must not cancel the reading every other waiter is waiting on. It
// keeps that caller's values -- the credentials the schedd is asked
// with among them -- since the configuration is the same whoever asks.
type Cache struct {
	ttl          time.Duration
	concurrency  int
	fetchTimeout time.Duration
	now          func() time.Time

	mu      sync.Mutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	snap     *Snapshot
	err      error
	inflight chan struct{}
}

// Option configures a Cache.
type Option func(*Cache)

// WithTTL sets how long a reading is served.
func WithTTL(d time.Duration) Option { return func(c *Cache) { c.ttl = d } }

// WithConcurrency bounds the connections one reading opens at once.
func WithConcurrency(n int) Option { return func(c *Cache) { c.concurrency = n } }

// WithClock replaces the clock, for tests.
func WithClock(now func() time.Time) Option { return func(c *Cache) { c.now = now } }

// NewCache returns an empty Cache.
func NewCache(opts ...Option) *Cache {
	c := &Cache{
		ttl:          DefaultTTL,
		concurrency:  DefaultConcurrency,
		fetchTimeout: DefaultFetchTimeout,
		now:          time.Now,
		entries:      map[string]*cacheEntry{},
	}
	for _, o := range opts {
		o(c)
	}
	if c.concurrency < 1 {
		c.concurrency = 1
	}
	return c
}

// TTL reports how long a reading is served.
func (c *Cache) TTL() time.Duration {
	if c == nil {
		return 0
	}
	return c.ttl
}

// Get returns the access point's policy, reading it from src when the
// cached reading is missing or older than the TTL.
//
// It fails only when the schedd cannot be asked at all. A knob it
// refuses or does not know comes back unknown or unset, and a reading
// that fails outright still returns the previous one, if there is one:
// configuration an hour old describes the access point better than none.
//
// A nil Cache reads every time and keeps nothing.
func (c *Cache) Get(ctx context.Context, ap string, src ConfigSource) (*Snapshot, error) {
	if src == nil {
		return nil, fmt.Errorf("no schedd to read the access point's configuration from")
	}
	if c == nil {
		return NewCache().Get(ctx, ap, src)
	}
	key := strings.ToLower(ap)

	c.mu.Lock()
	e := c.entries[key]
	if e == nil {
		e = &cacheEntry{}
		c.entries[key] = e
	}
	if e.snap != nil && c.now().Sub(e.snap.FetchedAt) < c.ttl {
		snap := e.snap
		c.mu.Unlock()
		return snap, nil
	}
	done := e.inflight
	if done == nil {
		done = make(chan struct{})
		e.inflight = done
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.fetchTimeout)
		go func() {
			defer cancel()
			snap, err := c.fetch(fctx, ap, src)
			c.mu.Lock()
			if err == nil {
				e.snap = snap
			}
			e.err = err
			e.inflight = nil
			c.mu.Unlock()
			close(done)
		}()
	}
	c.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		c.mu.Lock()
		stale := e.snap
		c.mu.Unlock()
		if stale != nil {
			return stale, nil
		}
		return nil, ctx.Err()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if e.snap != nil {
		return e.snap, nil
	}
	return nil, e.err
}

// Cached returns the reading held for an access point, however old, or
// nil. It never contacts the schedd.
func (c *Cache) Cached(ap string) *Snapshot {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[strings.ToLower(ap)]; e != nil {
		return e.snap
	}
	return nil
}

// fetch reads every knob the policy covers.
//
// The first knob is read alone: when it fails, the schedd is taken to be
// unreachable, and the reading ends there rather than paying a
// connection timeout per knob. After that each knob fails on its own.
func (c *Cache) fetch(ctx context.Context, ap string, src ConfigSource) (*Snapshot, error) {
	snap := &Snapshot{AccessPoint: ap, values: map[string]Value{}, truncated: map[string]int{}}

	static := staticKnobs()
	first := readKnob(ctx, src, static[0])
	if first.Err != nil {
		return nil, fmt.Errorf("could not read the configuration of access point %s: %w", ap, first.Err)
	}
	snap.values[static[0]] = first
	c.readAll(ctx, src, static[1:], snap)

	var named []string
	for _, l := range namedLists {
		names, cut := splitNames(snap.Get(l.names).Raw)
		if cut > 0 {
			snap.truncated[l.names] = cut
		}
		for _, n := range names {
			for _, suffix := range l.suffixes {
				named = append(named, strings.ToUpper(l.prefix+n+suffix))
			}
		}
	}
	c.readAll(ctx, src, named, snap)

	snap.FetchedAt = c.now()
	return snap, nil
}

// readAll reads names concurrently, at most c.concurrency at a time.
func (c *Cache) readAll(ctx context.Context, src ConfigSource, names []string, snap *Snapshot) {
	// Settle what to read before any reader runs: snap.values is
	// written by the readers, so it cannot be consulted alongside them.
	todo := make([]string, 0, len(names))
	queued := map[string]bool{}
	for _, name := range names {
		if _, done := snap.values[name]; done || queued[name] {
			continue
		}
		queued[name] = true
		todo = append(todo, name)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.concurrency)
	for _, name := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			v := readKnob(ctx, src, name)
			mu.Lock()
			snap.values[name] = v
			mu.Unlock()
		}(name)
	}
	wg.Wait()
}

// readKnob reads one knob. daemon core reports an unset parameter as the
// literal "Not defined" (CONFIG_VAL) or a null string (DC_CONFIG_VAL);
// both, and an empty value, are "unset".
func readKnob(ctx context.Context, src ConfigSource, name string) Value {
	raw, ok, err := src.ConfigVal(ctx, name)
	if err != nil {
		return Value{Err: err, Asked: true}
	}
	raw = strings.TrimSpace(raw)
	if !ok || strings.HasPrefix(raw, "Not defined") {
		raw = ""
	}
	return Value{Raw: raw, Set: raw != "", Asked: true}
}

// splitNames splits a *_NAMES list the way the schedd does (comma and
// whitespace separated), dropping the reserved word NAMES -- which would
// name the list itself -- and repeats, compared without case, as the
// names are. It returns at most maxNames, and how many it dropped.
func splitNames(list string) (names []string, dropped int) {
	seen := map[string]bool{}
	for _, n := range strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		u := strings.ToUpper(n)
		if u == "NAMES" || seen[u] {
			continue
		}
		seen[u] = true
		if len(names) == maxNames {
			dropped++
			continue
		}
		names = append(names, n)
	}
	return names, dropped
}

// knobsToRead lists every knob a reading asks for, given a way to look
// up the *_NAMES lists. Used by NewSnapshot so a hand-built Snapshot
// answers the same questions a fetched one does.
func knobsToRead(lookup func(string) string) []string {
	out := staticKnobs()
	for _, l := range namedLists {
		names, _ := splitNames(lookup(l.names))
		for _, n := range names {
			for _, suffix := range l.suffixes {
				out = append(out, l.prefix+n+suffix)
			}
		}
	}
	return out
}
