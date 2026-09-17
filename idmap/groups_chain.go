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

// GroupChain consults every configured source and MERGES their answers,
// which is what nsswitch.conf means.
//
// glibc's `group:` line is union semantics: getgrouplist/initgroups asks
// each service and combines the supplementary groups it gets back. That
// is the whole point of writing "files sss" -- a user is meant to end up
// with their local groups AND their directory groups. An earlier version
// of this took the first source that answered, which on any
// files-first host silently dropped every directory group for every user
// who happened to have a local passwd entry, and `id` would have
// disagreed with us about who could do what.
//
// A source that does not know the account (ErrUnknownUser) contributes
// nothing and is not a failure; on a mixed host that is the normal case
// for most users at most sources.
//
// A source that is BROKEN fails the whole lookup, even if another source
// answered. The partial list that would otherwise be returned is the
// dangerous case: it looks like a complete answer, so a caller cannot
// tell that a user's directory groups are missing because SSSD is down
// rather than because they were removed. Login then under-authorizes,
// and -- far worse -- the refresh-time oracle would read it as lost
// membership and REVOKE the grant. Refusing to answer at all keeps both
// callers honest: login fails closed, and the oracle treats an error as
// no opinion rather than as grounds to revoke.
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
func (c *GroupChain) GroupsFor(ctx context.Context, username string) ([]string, error) {
	var (
		merged []string
		known  bool
	)
	for _, s := range c.Sources {
		groups, err := s.GroupsFor(ctx, username)
		if err != nil {
			if errors.Is(err, ErrUnknownUser) {
				// This service simply has no record of the account.
				continue
			}
			return nil, fmt.Errorf("%s could not answer for %q, so the group list would be incomplete: %w",
				s.Name(), username, err)
		}
		known = true
		merged = append(merged, groups...)
	}
	if !known {
		return nil, fmt.Errorf("%w: no configured source knows %q", ErrUnknownUser, username)
	}
	if len(merged) == 0 {
		// Every source claimed to know the account and none named a
		// group. No real account is in zero groups -- it is in at least
		// its primary one -- so this is a malformed answer, not a
		// permissions decision.
		return nil, fmt.Errorf("sources knew %q but reported no groups at all", username)
	}
	return normalizeGroups(merged), nil
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
