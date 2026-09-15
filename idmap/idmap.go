// Package idmap resolves an identity asserted by an OIDC provider to a
// local Unix account, by matching the token's subject against accounts'
// GECOS fields.
//
// Sites exist where the name in the token and the name of the account are
// simply different strings, related only by a directory entry:
//
//	tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/bash
//
// The subject is "tatannen"; the account is "tannenba". Nothing derives
// one from the other, so the mapping has to be looked up.
//
// # Why this is an index and not a lookup
//
// Every user database indexes accounts by name and by uid. None indexes
// them by GECOS, and the SSSD client this repo already uses
// (droppriv's lookup strategies) exposes no enumeration at all. So the
// useful direction -- subject to account -- is the one the system cannot
// answer directly, and has to be inverted here by reading the whole
// account list once and keeping the result.
//
// # Trust
//
// This mapping is an authorization decision: its output selects whose
// jobs the caller can see. Two properties follow, and both are enforced
// rather than documented:
//
//   - A subject matching more than one account resolves to NOBODY. A
//     duplicate GECOS is a directory mistake or an attempt to be someone
//     else; either way, picking one of them would be picking a victim.
//   - An index hit is confirmed by a forward lookup before it is used.
//     The forward direction is the one the system actually supports, so
//     it is the one that gets the last word: an index built minutes ago
//     cannot promote an account that no longer has that GECOS.
package idmap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNoMatch means no account carries this subject as its GECOS.
	ErrNoMatch = errors.New("no account has this subject as its GECOS")

	// ErrAmbiguous means several accounts do. Resolution fails: see the
	// package comment on why this does not choose.
	ErrAmbiguous = errors.New("several accounts have this subject as their GECOS")
)

// Account is one entry of the account database, reduced to the fields
// this package needs.
type Account struct {
	Username string
	Gecos    string
	UID      uint32
}

// Enumerator lists the account database. Implementations differ in how
// much of it they can see -- /etc/passwd alone, or everything NSS
// resolves -- which is why the choice is the caller's.
type Enumerator interface {
	Enumerate(ctx context.Context) ([]Account, error)
	// Name identifies the source in logs, so an operator reading
	// "resolved 0 accounts" can tell which database was empty.
	Name() string
}

// Verifier re-checks a candidate account by the forward lookup the
// system supports natively. droppriv's cached lookup chain satisfies
// this.
type Verifier interface {
	// GecosOf returns the account's current GECOS. A missing account
	// must return an error, not an empty string, so that "deleted" is
	// never mistaken for "GECOS cleared".
	GecosOf(ctx context.Context, username string) (string, error)
}

// Resolver maps subjects to local account names.
type Resolver struct {
	enum     Enumerator
	verifier Verifier
	ttl      time.Duration
	now      func() time.Time

	mu        sync.RWMutex
	byGecos   map[string]string // gecos -> username, absent when ambiguous
	ambiguous map[string]int    // gecos -> how many accounts claim it
	builtAt   time.Time
	count     int
}

// Option configures a Resolver.
type Option func(*Resolver)

// WithTTL sets how long an index is used before it is rebuilt. The
// account list is read in full on every rebuild, so this trades
// staleness against load on the directory.
func WithTTL(d time.Duration) Option { return func(r *Resolver) { r.ttl = d } }

// WithClock replaces the clock, for tests.
func WithClock(f func() time.Time) Option { return func(r *Resolver) { r.now = f } }

// New returns a Resolver over the given account source. verifier may be
// nil, which skips the forward re-check -- acceptable only when the
// enumerator reads the same database the rest of the system does.
func New(enum Enumerator, verifier Verifier, opts ...Option) *Resolver {
	r := &Resolver{
		enum:     enum,
		verifier: verifier,
		ttl:      5 * time.Minute,
		now:      time.Now,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Resolve returns the local account whose GECOS equals subject.
//
// The subject is compared to the whole GECOS field, exactly. GECOS is
// conventionally comma-separated, and matching only a component would
// mean an account could carry somebody else's identity in a field nobody
// reads -- so a comma is simply part of the string here, and a subject
// containing one is as unlikely to match as it should be.
func (r *Resolver) Resolve(ctx context.Context, subject string) (string, error) {
	if subject == "" {
		// An account with an empty GECOS is ordinary. A caller with an
		// empty subject is not, and must never collide with one.
		return "", fmt.Errorf("%w: empty subject", ErrNoMatch)
	}
	if err := r.ensureFresh(ctx); err != nil {
		return "", err
	}

	r.mu.RLock()
	username, ok := r.byGecos[subject]
	dupes := r.ambiguous[subject]
	r.mu.RUnlock()

	if dupes > 1 {
		return "", fmt.Errorf("%w: %q is the GECOS of %d accounts", ErrAmbiguous, subject, dupes)
	}
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrNoMatch, subject)
	}

	if r.verifier != nil {
		gecos, err := r.verifier.GecosOf(ctx, username)
		if err != nil {
			return "", fmt.Errorf("confirming %q still maps to %q: %w", username, subject, err)
		}
		if gecos != subject {
			// The index is behind the database. Refusing is right even
			// though a rebuild might agree: the account this would have
			// returned is, right now, somebody whose GECOS is not this
			// subject.
			return "", fmt.Errorf("%w: the index said %q, but its GECOS is now %q",
				ErrNoMatch, username, gecos)
		}
	}
	return username, nil
}

// Stats reports what the current index holds, for logging and /readyz.
func (r *Resolver) Stats() (accounts, ambiguous int, builtAt time.Time) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	amb := 0
	for _, n := range r.ambiguous {
		if n > 1 {
			amb++
		}
	}
	return r.count, amb, r.builtAt
}

// AmbiguousGecos lists the GECOS values shared by more than one account,
// so an operator can be told which directory entries to fix rather than
// discovering them one failed login at a time.
func (r *Resolver) AmbiguousGecos() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for g, n := range r.ambiguous {
		if n > 1 {
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}

// Refresh rebuilds the index now, regardless of TTL.
func (r *Resolver) Refresh(ctx context.Context) error { return r.build(ctx) }

func (r *Resolver) ensureFresh(ctx context.Context) error {
	r.mu.RLock()
	fresh := r.builtAt.After(time.Time{}) && r.now().Sub(r.builtAt) < r.ttl
	r.mu.RUnlock()
	if fresh {
		return nil
	}
	return r.build(ctx)
}

func (r *Resolver) build(ctx context.Context) error {
	accounts, err := r.enum.Enumerate(ctx)
	if err != nil {
		return fmt.Errorf("enumerating accounts via %s: %w", r.enum.Name(), err)
	}

	byGecos := make(map[string]string, len(accounts))
	counts := make(map[string]int, len(accounts))
	for _, a := range accounts {
		g := strings.TrimSpace(a.Gecos)
		if g == "" {
			// Accounts with no GECOS are the overwhelming majority on a
			// normal system; they cannot be anybody's subject.
			continue
		}
		counts[g]++
		byGecos[g] = a.Username
	}
	// Ambiguous entries are removed rather than left to a count check, so
	// that a future caller reading byGecos directly cannot get a winner.
	for g, n := range counts {
		if n > 1 {
			delete(byGecos, g)
		}
	}

	r.mu.Lock()
	r.byGecos = byGecos
	r.ambiguous = counts
	r.builtAt = r.now()
	r.count = len(accounts)
	r.mu.Unlock()
	return nil
}
