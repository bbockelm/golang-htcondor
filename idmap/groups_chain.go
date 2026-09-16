package idmap

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/bbockelm/golang-htcondor/droppriv"
)

// GroupChain asks each source in turn and takes the first real answer.
//
// The order matters and is deliberate: a native SSSD query first where
// it is available, then `id -Gn`, which resolves through NSS and so
// covers /etc/group, systemd-userdbd and anything else nsswitch.conf
// names. os/user is last because, built without cgo, it reads
// /etc/group ALONE -- a directory-backed account would come back a
// member of nothing, which reads as "no permissions" rather than as the
// failure it is.
//
// A source that errors is passed over; a source that returns no groups
// at all is treated as not having answered, for the same reason.
type GroupChain struct{ Sources []GroupSource }

// Name lists the chained sources, so a log line says what was tried.
func (c *GroupChain) Name() string {
	names := make([]string, 0, len(c.Sources))
	for _, s := range c.Sources {
		names = append(names, s.Name())
	}
	return "chain(" + strings.Join(names, ",") + ")"
}

// GroupsFor returns the first non-empty membership any source reports.
func (c *GroupChain) GroupsFor(ctx context.Context, username string) ([]string, error) {
	var firstErr error
	for _, s := range c.Sources {
		groups, err := s.GroupsFor(ctx, username)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", s.Name(), err)
			}
			continue
		}
		if len(groups) == 0 {
			// Not an answer: every account is in at least its primary
			// group. Treat it as this source not knowing the user.
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: no groups for %q", s.Name(), username)
			}
			continue
		}
		return groups, nil
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no group source could answer for %q", username)
	}
	return nil, firstErr
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
