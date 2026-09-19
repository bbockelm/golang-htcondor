// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/idmap"
	"github.com/bbockelm/golang-htcondor/logging"
)

// localIdentity turns the identity an OIDC provider asserts into the
// local account that owns this user's jobs, and reads that account's
// group membership from the system rather than from the token.
//
// It exists for deployments where the provider knows a person by one
// name and the access point knows them by another, related only through
// the account database:
//
//	tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/bash
//
// and where what a person may do is expressed in Unix groups that the
// token says nothing about.
//
// The two halves are configured INDEPENDENTLY, because they answer to
// different deployments. A container that holds no account database
// wants neither and keeps the token's own claims. A host whose accounts
// and groups are the real authority wants both. A host where the subject
// already IS the login name, but whose groups are in the directory,
// wants only the second.
//
// Whichever halves are enabled are all-or-nothing at request time: a
// caller the enabled halves cannot answer for does not get a session.
// Falling back to the token's claims would mean the weaker authorization
// basis engages exactly when the stronger one is broken, and the people
// most likely to trip it are the ones whose accounts are misconfigured.
// warmUpTimeout bounds the startup index build.
const warmUpTimeout = 30 * time.Second

// How hard to keep trying after a startup that found no directory.
//
// A container starts this daemon and its SSSD sidecar at the same instant,
// so the first index is built against a directory that is not answering
// yet -- and SSSD does not serve an enumeration until its own first pass
// over the directory completes, which on a real one takes minutes. These
// bound a quiet retry over that window: often enough to be ready before
// the first person logs in, few enough that a host with no directory at
// all pays for a handful of extra passwd reads and then stops.
const (
	startupRetryInterval = 20 * time.Second
	startupRetryWindow   = 5 * time.Minute
)

type localIdentity struct {
	// resolver maps the asserted subject to a local account. Nil leaves
	// the subject alone, which is right when it is already a login name.
	resolver *idmap.Resolver
	// groups reads membership from the system. Nil keeps the token's
	// groups claim, which is the default and the only thing that works
	// where there is no account database to read.
	groups droppriv.GroupLookup
	logger *logging.Logger

	// Retry pacing for the startup re-index, as fields so a test does not
	// have to wait out the real window.
	retryInterval time.Duration
	retryWindow   time.Duration
}

// mapsAccount reports whether the asserted subject is translated.
func (l *localIdentity) mapsAccount() bool { return l != nil && l.resolver != nil }

// sourcesGroups reports whether membership comes from the system rather
// than from the token.
func (l *localIdentity) sourcesGroups() bool { return l != nil && l.groups != nil }

// groupSourceName names the lookup chain membership will be read from,
// e.g. "cached(stdlib)" or "cached(chain(stdlib,sssd))".
//
// Worth logging at startup because the chain is chosen per build: with
// cgo it is getgrouplist(3), which consults every service in
// nsswitch.conf; without cgo -- which is how the release binaries and
// container are built -- it is this package's own chain, which speaks
// files and sss and marks anything else degraded. An operator whose
// directory groups are not arriving needs to see which of those they got.
func (l *localIdentity) groupSourceName() string {
	if !l.sourcesGroups() {
		return ""
	}
	return l.groups.Name()
}

// newLocalIdentity builds the mapper from operator configuration.
//
// passwdFile, when set, is read instead of /etc/passwd -- useful where
// accounts are local, and the only thing a test can point at. Either
// way the index can only hold accounts that something will enumerate,
// which in practice means the ones present locally; see the comment in
// idmap/enumerate.go for why that is not the limitation it looks like.
func newLocalIdentity(strategies []idmap.Strategy, systemGroups bool, passwdFile string, ttl time.Duration, stripDomain bool, logger *logging.Logger) *localIdentity {
	if len(strategies) == 0 && !systemGroups {
		return nil
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	l := &localIdentity{
		logger:        logger,
		retryInterval: startupRetryInterval,
		retryWindow:   startupRetryWindow,
	}
	if systemGroups {
		// Order from nsswitch.conf, so this agrees with the rest of the
		// machine rather than preferring a source of its own.
		l.groups = droppriv.NewSystemGroupLookup(ttl)
	}
	if len(strategies) == 0 {
		return l
	}

	// Both halves come from droppriv: enumeration to build the index, and
	// a by-name lookup to re-check every hit before it is believed.
	//
	// The verifier must read the same database the index came from. With
	// the system default, that re-check is os/user -- which under cgo is
	// getpwnam_r, so it reaches a directory account that nothing could
	// have enumerated. With an operator-supplied file it is that file,
	// because the system would not know those accounts at all.
	enum := &idmap.SystemAccounts{Path: passwdFile}
	var ver idmap.Verifier = idmap.SystemGecos{}
	if passwdFile != "" {
		ver = idmap.FileGecos{Path: passwdFile}
	}

	l.resolver = idmap.New(enum, ver,
		idmap.WithTTL(ttl),
		idmap.WithStrategies(strategies...),
		idmap.WithStripDomain(stripDomain))
	return l
}

// warmUp builds the index once at startup and says what it found.
//
// An operator should learn that the account database looks empty, or
// that two accounts claim the same identity, while reading the startup
// log -- not from one user's failed login weeks later.
func (l *localIdentity) warmUp(ctx context.Context) {
	// Bounded: warmUp runs before the listener is open, so a directory
	// that has stopped answering would otherwise hold the daemon in
	// startup with no port, no /readyz and no log line. Failing here is
	// survivable -- the index is rebuilt on first use -- whereas never
	// returning is not.
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, warmUpTimeout)
	defer cancel()

	if !l.mapsAccount() {
		// Only groups are being sourced locally; there is no index.
		return
	}
	if err := l.resolver.Refresh(ctx); err != nil {
		l.logger.Error(logging.DestinationHTTP,
			"Could not read the account database; every login will be refused until this works",
			"error", err)
		return
	}
	accounts, ambiguous, _ := l.resolver.Stats()
	l.logger.Info(logging.DestinationHTTP, "Indexed accounts by GECOS for identity mapping",
		"accounts", accounts, "ambiguous", ambiguous)
	if accounts == 0 {
		l.logger.Warn(logging.DestinationHTTP,
			"The account database enumerated to nothing, so no login can be mapped. "+
				"If accounts live in a directory, SSSD lists them only with `enumerate = true`")
	}
	// Distinct from an empty index, and far more confusing without a line
	// of its own: the index was built, it just does not cover the
	// directory. In a container this is usually a startup ordering
	// problem -- the daemon indexes before the SSSD sidecar is answering
	// -- and it clears itself on the first rebuild after the TTL.
	if derr := l.resolver.Degraded(); derr != nil {
		l.logger.Warn(logging.DestinationHTTP,
			"The account index is incomplete: a directory could not be read, so logins that map to "+
				"a directory account will be refused until it can be. This is being retried",
			"error", derr, "indexed", accounts)
	}
	// The index reflects whatever was readable at t=0, which in a container
	// is usually before the directory is answering at all. Keep trying in
	// the background for a few minutes so the pod is usable by the time
	// somebody arrives, instead of serving that first snapshot until the
	// TTL expires AND a login happens to trigger a rebuild.
	go l.retryStartupIndex(context.WithoutCancel(parent), accounts)
	// Only meaningful when the login-name strategy is also in play, and
	// then worth saying out loud: the subject naming one of these
	// resolves to somebody else's account.
	if shadowed := l.resolver.ShadowedUsernames(); len(shadowed) > 0 {
		l.logger.Warn(logging.DestinationHTTP,
			"Some login names are also another account's GECOS; a subject naming one resolves to that other account",
			"names", shadowed)
	}
	if ambiguous > 0 {
		// Naming them is the difference between a fixable report and a
		// mystery, and these are account names, not secrets.
		l.logger.Warn(logging.DestinationHTTP,
			"Several accounts share a GECOS; nobody presenting one of these can log in",
			"gecos", l.resolver.AmbiguousGecos())
	}
}

// retryStartupIndex re-indexes every retryInterval until the directory
// shows up or retryWindow expires.
//
// The stopping rule is that the account count GREW. That is the only
// observable which separates the two cases that look identical at
// startup: a directory that was not answering yet, and a host that simply
// has no directory. The first one resolves itself and we stop; the second
// costs a handful of passwd reads across the window and then stops too.
//
// Deliberately not a permanent background refresher: once the window
// closes the ordinary TTL takes over, so a long-lived process is not
// enumerating a large directory on a timer forever.
func (l *localIdentity) retryStartupIndex(ctx context.Context, startingCount int) {
	if l.retryInterval <= 0 || l.retryWindow <= 0 {
		return
	}
	ticker := time.NewTicker(l.retryInterval)
	defer ticker.Stop()
	deadline := time.NewTimer(l.retryWindow)
	defer deadline.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-ticker.C:
		}

		refreshCtx, cancel := context.WithTimeout(ctx, warmUpTimeout)
		err := l.resolver.Refresh(refreshCtx)
		cancel()
		if err != nil {
			// Expected while the directory is still coming up; the startup
			// log already said the index is incomplete, and repeating that
			// every interval would bury it.
			continue
		}

		accounts, ambiguous, _ := l.resolver.Stats()
		if accounts <= startingCount {
			continue
		}
		l.logger.Info(logging.DestinationHTTP,
			"The account index picked up the directory after start; logins can now map to directory accounts",
			"accounts", accounts, "ambiguous", ambiguous, "was", startingCount)
		return
	}
}

// resolve applies whichever halves are configured.
//
// tokenGroups is what the provider asserted; it is returned unchanged
// unless this deployment reads membership from the system, in which case
// the token's claim is not consulted at all.
func (l *localIdentity) resolve(ctx context.Context, subject string, tokenGroups []string) (account string, groups []string, err error) {
	account, groups = subject, tokenGroups

	if l.mapsAccount() {
		account, err = l.resolver.Resolve(ctx, subject)
		if err != nil {
			return "", nil, err
		}
	}
	if l.sourcesGroups() {
		// Deliberately keyed on the mapped account: the groups that
		// matter are the ones belonging to the account whose jobs this
		// session will read.
		groups, err = l.groups.LookupGroups(ctx, account)

		var degraded *droppriv.DegradedError
		switch {
		case errors.As(err, &degraded) && len(degraded.Groups) > 0:
			// Some source was unavailable. `id` on this host would
			// return the same short list, so refusing here would deny
			// every login whenever a directory blinked -- while the rest
			// of the machine carried on. Proceed, loudly: the user may
			// see fewer permissions than usual, and an operator should
			// be able to find out why from the log rather than from a
			// support ticket.
			groups = degraded.Groups
			l.logger.Warn(logging.DestinationHTTP,
				"Group list is incomplete; this session may have fewer permissions than it should",
				"account", account, "unavailable_source", degraded.Source,
				"groups", groups, "error", degraded.Err)
		case degraded != nil:
			// Degraded AND empty is not a short answer, it is no answer:
			// every source that might have known this account was the one
			// that was unavailable. Proceeding would hand the session an
			// empty group list, which reads downstream as a real "belongs
			// to nothing" and is indistinguishable from a user who was
			// legitimately removed from everything.
			return "", nil, fmt.Errorf(
				"group lookup for %q learned nothing: %s was unavailable: %w",
				account, degraded.Source, degraded.Err)
		case err != nil:
			return "", nil, fmt.Errorf("reading groups for %q: %w", account, err)
		}
	}
	return account, groups, nil
}

// describeFailure turns a mapping error into something an operator can
// act on and a user can report, without telling the user which accounts
// exist.
func describeFailure(err error) string {
	switch {
	case errors.Is(err, idmap.ErrAmbiguous):
		return "Your identity matches more than one local account. This is a configuration " +
			"problem on the access point, not something you can fix; please report it."
	case errors.Is(err, idmap.ErrNoMatch):
		return "Your identity does not correspond to a local account on this access point."
	default:
		return "The account database could not be consulted. Please try again shortly."
	}
}

// mapAssertedIdentity applies local resolution to an identity asserted by
// something OTHER than the SSO callback.
//
// The callback is not the only way an outside party names a user. A
// trusted proxy can assert one in a header, and RFC 8693 token exchange
// accepts a JWT from a trusted external issuer. Both are assertions of
// the same kind as an OIDC subject, and both must therefore go through
// the same mapping: otherwise enabling identity mapping would leave a
// second, unmapped way to obtain a session, which is exactly the hole
// the feature exists to close.
//
// Returns ("", nil, err) when the identity cannot be resolved, and the
// caller must refuse. When no local identity is configured the inputs are
// returned unchanged, so this is safe to call unconditionally.
func (h *Handler) mapAssertedIdentity(ctx context.Context, subject string, assertedGroups []string) (string, []string, error) {
	if h.localIdentity == nil {
		return subject, assertedGroups, nil
	}
	return h.localIdentity.resolve(ctx, subject, assertedGroups)
}
