package httpserver

import (
	"context"
	"errors"
	"fmt"
	"time"

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

type localIdentity struct {
	// resolver maps the asserted subject to a local account. Nil leaves
	// the subject alone, which is right when it is already a login name.
	resolver *idmap.Resolver
	// groups reads membership from the system. Nil keeps the token's
	// groups claim, which is the default and the only thing that works
	// where there is no account database to read.
	groups idmap.GroupSource
	logger *logging.Logger
}

// mapsAccount reports whether the asserted subject is translated.
func (l *localIdentity) mapsAccount() bool { return l != nil && l.resolver != nil }

// sourcesGroups reports whether membership comes from the system rather
// than from the token.
func (l *localIdentity) sourcesGroups() bool { return l != nil && l.groups != nil }

// newLocalIdentity builds the mapper from operator configuration.
//
// passwdFile, when set, is read instead of asking NSS -- useful where
// accounts are local, and the only thing a test can point at. Otherwise
// enumeration goes through `getent passwd`, whose limits are documented
// on idmap.Getent: SSSD lists directory accounts there only when its
// domain has `enumerate = true`.
func newLocalIdentity(strategies []idmap.Strategy, systemGroups bool, passwdFile string, ttl time.Duration, logger *logging.Logger) *localIdentity {
	if len(strategies) == 0 && !systemGroups {
		return nil
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	l := &localIdentity{logger: logger}
	if systemGroups {
		// Order from nsswitch.conf, so this agrees with the rest of the
		// machine rather than preferring a source of its own.
		l.groups = idmap.NewCachedGroups(idmap.DefaultGroupSource(), ttl)
	}
	if len(strategies) == 0 {
		return l
	}

	var (
		enum idmap.Enumerator
		ver  idmap.Verifier
	)
	if passwdFile != "" {
		pf := idmap.NewPasswdFile(passwdFile)
		enum, ver = pf, &idmap.PasswdFileVerifier{File: pf}
	} else {
		// The index comes from whatever will enumerate; the re-check
		// goes to getent, which answers for a single account even when
		// the directory refuses to list them all.
		enum = &idmap.Chain{Sources: []idmap.Enumerator{
			&idmap.Getent{},
			idmap.NewPasswdFile(""),
		}}
		ver = &idmap.GetentUser{}
	}
	l.resolver = idmap.New(enum, ver, idmap.WithTTL(ttl), idmap.WithStrategies(strategies...))
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
		groups, err = l.groups.GroupsFor(ctx, account)
		if err != nil {
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
