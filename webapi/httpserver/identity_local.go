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
// Both halves are deliberately all-or-nothing. When this is configured,
// a caller who cannot be mapped does not get a session: falling back to
// the token's own claims would mean the weaker authorization basis
// engages exactly when the stronger one is broken, and the people most
// likely to trip it are the ones whose accounts are misconfigured.
type localIdentity struct {
	resolver *idmap.Resolver
	groups   idmap.GroupSource
	logger   *logging.Logger
}

// newLocalIdentity builds the mapper from operator configuration.
//
// passwdFile, when set, is read instead of asking NSS -- useful where
// accounts are local, and the only thing a test can point at. Otherwise
// enumeration goes through `getent passwd`, whose limits are documented
// on idmap.Getent: SSSD lists directory accounts there only when its
// domain has `enumerate = true`.
func newLocalIdentity(strategies []idmap.Strategy, passwdFile string, ttl time.Duration, logger *logging.Logger) *localIdentity {
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
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if len(strategies) == 0 {
		strategies = []idmap.Strategy{idmap.StrategyGecos}
	}
	return &localIdentity{
		resolver: idmap.New(enum, ver, idmap.WithTTL(ttl), idmap.WithStrategies(strategies...)),
		groups:   idmap.NewCachedGroups(&idmap.IDCommand{}, ttl),
		logger:   logger,
	}
}

// warmUp builds the index once at startup and says what it found.
//
// An operator should learn that the account database looks empty, or
// that two accounts claim the same identity, while reading the startup
// log -- not from one user's failed login weeks later.
func (l *localIdentity) warmUp(ctx context.Context) {
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

// resolve maps an asserted subject to a local account and its groups.
func (l *localIdentity) resolve(ctx context.Context, subject string) (account string, groups []string, err error) {
	account, err = l.resolver.Resolve(ctx, subject)
	if err != nil {
		return "", nil, err
	}
	groups, err = l.groups.GroupsFor(ctx, account)
	if err != nil {
		return "", nil, fmt.Errorf("reading groups for %q: %w", account, err)
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
