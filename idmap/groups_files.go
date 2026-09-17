package idmap

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// GroupFiles is the "files" method of nsswitch.conf: membership from
// /etc/group, and the primary group from the account's own passwd entry.
//
// Both halves are required and neither is sufficient. /etc/group lists
// only SUPPLEMENTARY members -- an account's primary group usually names
// nobody, because the gid in its passwd entry is what puts it there. A
// reader that consulted /etc/group alone would report most users as
// missing the very group their files are created in.
type GroupFiles struct {
	// PasswdPath defaults to /etc/passwd, GroupPath to /etc/group.
	PasswdPath string
	GroupPath  string
}

// Name identifies this source in logs.
func (g *GroupFiles) Name() string { return "files" }

func (g *GroupFiles) passwdPath() string {
	if g.PasswdPath == "" {
		return "/etc/passwd"
	}
	return g.PasswdPath
}

func (g *GroupFiles) groupPath() string {
	if g.GroupPath == "" {
		return "/etc/group"
	}
	return g.GroupPath
}

// GroupsFor returns the account's groups by name.
func (g *GroupFiles) GroupsFor(ctx context.Context, username string) ([]string, error) {
	if username == "" {
		return nil, fmt.Errorf("no username to look up groups for")
	}

	accounts, err := NewPasswdFile(g.passwdPath()).Enumerate(ctx)
	if err != nil {
		return nil, err
	}
	var (
		primaryGID uint32
		found      bool
	)
	for _, a := range accounts {
		if a.Username == username {
			primaryGID, found = a.primaryGID, true
			break
		}
	}
	if !found {
		// Not a failure: on a host whose accounts live in a directory,
		// every one of them is absent from this file. The chain treats
		// this as "nothing to contribute" and consults the next source.
		return nil, fmt.Errorf("%w: no account %q in %s", ErrUnknownUser, username, g.passwdPath())
	}

	entries, err := parseGroupFile(g.groupPath())
	if err != nil {
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if e.gid == primaryGID {
			names = append(names, e.name)
			continue
		}
		for _, m := range e.members {
			if m == username {
				names = append(names, e.name)
				break
			}
		}
	}
	if len(names) == 0 {
		// The account exists but names no group at all, which means its
		// primary gid has no entry here. Report the number rather than
		// an empty list, so a caller cannot read this as "no groups".
		names = append(names, strconv.FormatUint(uint64(primaryGID), 10))
	}
	return normalizeGroups(names), nil
}

type groupEntryFile struct {
	name    string
	gid     uint32
	members []string
}

// parseGroupFile reads group(5): name:passwd:gid:member,member,...
func parseGroupFile(path string) ([]groupEntryFile, error) {
	f, err := os.Open(path) //nolint:gosec // the path is operator configuration, not user input
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []groupEntryFile
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		gid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		e := groupEntryFile{name: fields[0], gid: uint32(gid)}
		if len(fields) > 3 && fields[3] != "" {
			for _, m := range strings.Split(fields[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					e.members = append(e.members, m)
				}
			}
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
