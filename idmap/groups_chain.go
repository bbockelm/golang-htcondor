package idmap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/bbockelm/golang-htcondor/droppriv"
)

// DegradedError reports a group list assembled while at least one
// configured source was unavailable.
//
// It carries the groups anyway, because that is what the rest of the
// system does: glibc's default action for UNAVAIL is `continue`, so `id`
// on a host whose SSSD is down returns the files-only list without
// complaint. Refusing outright would disagree with every other tool on
// the machine and would deny every login whenever a directory blinked.
//
// But a caller that is about to do something IRREVERSIBLE must not treat
// it as a complete answer. "Fewer groups than usual" and "this user was
// removed from a group" look identical in the list itself; only this
// error tells them apart. Login proceeds on a degraded list, with a
// warning; the refresh-time oracle refuses to revoke on one.
type DegradedError struct {
	Groups []string
	Source string
	Err    error
}

func (e *DegradedError) Error() string {
	return fmt.Sprintf("group list is incomplete: %s was unavailable: %v", e.Source, e.Err)
}

func (e *DegradedError) Unwrap() error { return e.Err }

// GroupChain consults every configured source and MERGES their answers,
// which is what nsswitch.conf means.
//
// glibc's `group:` line is union semantics: getgrouplist/initgroups asks
// each service and combines the supplementary groups it gets back. That
// is the whole point of writing "files sss" -- a user is meant to end up
// with their local groups AND their directory groups. An earlier version
// of this took the first source that answered, which on any files-first
// host silently dropped every directory group for every user who
// happened to have a local passwd entry.
//
// A source that does not know the account (ErrUnknownUser) contributes
// nothing and is not a failure; on a mixed host that is the normal case
// for most users at most sources.
//
// A source that is UNAVAILABLE does not fail the lookup either -- see
// DegradedError for why -- but the result is marked, so the one caller
// that must not act on a short list can decline.
type GroupChain struct{ Sources []GroupSource }

// Name lists the chained sources, so a log line says what was consulted.
func (c *GroupChain) Name() string {
	names := make([]string, 0, len(c.Sources))
	for _, s := range c.Sources {
		names = append(names, s.Name())
	}
	return "chain(" + strings.Join(names, ",") + ")"
}

// GroupsFor returns the union of every source's answer.
//
// The error is a *DegradedError when some sources answered and others
// were unavailable; the groups are still returned with it.
func (c *GroupChain) GroupsFor(ctx context.Context, username string) ([]string, error) {
	var (
		merged   []string
		known    bool
		degraded *DegradedError
	)
	for _, s := range c.Sources {
		groups, err := s.GroupsFor(ctx, username)
		if err != nil {
			if errors.Is(err, ErrUnknownUser) {
				// This service simply has no record of the account.
				continue
			}
			// Unavailable. Keep going, as glibc does, but remember.
			if degraded == nil {
				degraded = &DegradedError{Source: s.Name(), Err: err}
			}
			continue
		}
		known = true
		merged = append(merged, groups...)
	}

	if !known {
		if degraded != nil {
			// Nothing answered AND something was broken: this is an
			// outage, not an unknown account, and must not be mistaken
			// for "this user belongs to nothing".
			return nil, fmt.Errorf("no source could answer for %q: %w", username, degraded)
		}
		return nil, fmt.Errorf("%w: no configured source knows %q", ErrUnknownUser, username)
	}
	if len(merged) == 0 {
		// Every source that knew the account named no group. No real
		// account is in zero groups -- it is in at least its primary one.
		return nil, fmt.Errorf("sources knew %q but reported no groups at all", username)
	}

	merged = normalizeGroups(merged)
	if degraded != nil {
		degraded.Groups = merged
		return merged, degraded
	}
	return merged, nil
}

// NSSwitchGroupSource builds the chain from nsswitch.conf's `group:`
// line, so this code consults the same sources, in the same order, as
// everything else on the machine.
//
// That line is the system's own statement of where group membership
// comes from -- "files sss", "sss files", "files" alone. Hardcoding an
// order here would mean asking SSSD on a host whose administrator said
// not to, or preferring files on one that puts the directory first, and
// being confidently wrong in a way that is invisible until somebody's
// permissions differ from `id`'s answer.
//
// Methods this package cannot speak itself -- ldap, winbind, nis --
// are not skipped. They cause id(1) to be appended, which resolves
// through libc and therefore honours the whole line including them.
// Better to spawn a process than to silently answer from a subset of
// the sources the administrator configured.
func NSSwitchGroupSource(nsswitchPath string) GroupSource {
	if nsswitchPath == "" {
		nsswitchPath = "/etc/nsswitch.conf"
	}
	methods, err := droppriv.ParseNSSwitchDB(nsswitchPath, "group")
	if err != nil {
		// Unreadable: let libc decide, since it can read what we cannot.
		return &GroupChain{Sources: []GroupSource{&IDCommand{}}}
	}

	declared := countDeclaredMethods(nsswitchPath, "group")

	var sources []GroupSource
	for _, m := range methods {
		switch m {
		case droppriv.NSSSwitchMethodSSS:
			if s := sssdGroupSource(); s != nil {
				sources = append(sources, s)
			}
		case droppriv.NSSSwitchMethodFiles:
			sources = append(sources, &GroupFiles{})
		}
	}

	// The line named methods we do not implement, or none we recognised.
	// Ask libc, which implements all of them.
	if len(sources) == 0 || declared > len(methods) {
		sources = append(sources, &IDCommand{})
	}
	return &GroupChain{Sources: sources}
}

// countDeclaredMethods counts every method on a database's line,
// including the ones ParseNSSwitchDB drops. The difference between this
// and what came back is exactly "what the administrator configured that
// we cannot speak".
func countDeclaredMethods(path, database string) int {
	f, err := os.Open(path) //nolint:gosec // operator configuration
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, database+":") {
			continue
		}
		n := 0
		for _, part := range strings.Fields(line)[1:] {
			if strings.HasPrefix(part, "[") {
				continue // an action, not a source
			}
			n++
		}
		return n
	}
	return 0
}

// DefaultGroupSource reads nsswitch.conf. It is a function rather than a
// value so that a test, or a host whose configuration changes, is not
// stuck with whatever was true at init.
func DefaultGroupSource() GroupSource { return NSSwitchGroupSource("") }
