package idmap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// PasswdFile enumerates /etc/passwd. It sees local accounts only, which
// is the whole database on a machine that has no directory and a small
// part of it on a machine that does.
type PasswdFile struct{ Path string }

// NewPasswdFile reads the given file, or /etc/passwd when path is empty.
func NewPasswdFile(path string) *PasswdFile {
	if path == "" {
		path = "/etc/passwd"
	}
	return &PasswdFile{Path: path}
}

// Name identifies this source in logs.
func (p *PasswdFile) Name() string { return "passwd:" + p.Path }

// Enumerate reads every account in the file.
func (p *PasswdFile) Enumerate(_ context.Context) ([]Account, error) {
	f, err := os.Open(p.Path) //nolint:gosec // the path is operator configuration, not user input
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parsePasswd(f)
}

// The account index is built from /etc/passwd alone, deliberately.
//
// There is no `getent passwd` here and there must not be: this package
// runs inside a daemon that manipulates its own privileges, and forking
// from such a process is hazardous in ways that have nothing to do with
// whether the command itself is correct.
//
// Little is lost. SSSD answers `getent passwd` with directory accounts
// only when its domain sets `enumerate = true`, which is off by default
// and discouraged for large directories -- so on the deployments this
// targets, shelling out never listed directory accounts either. A site
// whose accounts are NOT materialised locally cannot build a GECOS index
// at all, by any means available here, because the SSSD client protocol
// has no enumeration primitive. Such a site needs its accounts in
// /etc/passwd, or an explicit map.

// Chain enumerates several sources and merges them. The FIRST source to
// claim a username wins, so a local override shadows a directory entry
// the same way nsswitch.conf makes it.
type Chain struct{ Sources []Enumerator }

// Name lists the chained sources, so a log line says which were tried.
func (c *Chain) Name() string {
	names := make([]string, 0, len(c.Sources))
	for _, s := range c.Sources {
		names = append(names, s.Name())
	}
	return "chain(" + strings.Join(names, ",") + ")"
}

// Enumerate merges every source, first claim to a username winning.
func (c *Chain) Enumerate(ctx context.Context) ([]Account, error) {
	var out []Account
	seen := make(map[string]bool)
	var firstErr error
	for _, s := range c.Sources {
		accounts, err := s.Enumerate(ctx)
		if err != nil {
			// One unavailable source must not blind the others: a
			// machine with no getent still has /etc/passwd.
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", s.Name(), err)
			}
			continue
		}
		for _, a := range accounts {
			if seen[a.Username] {
				continue
			}
			seen[a.Username] = true
			out = append(out, a)
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// parsePasswd reads passwd-format lines. Malformed lines are skipped
// rather than failing the whole enumeration: one unreadable entry in a
// thousand should not lock every user out.
func parsePasswd(r io.Reader) ([]Account, error) {
	var out []Account
	sc := bufio.NewScanner(r)
	// Directory entries can carry long GECOS values; the default 64KiB
	// token limit is generous but the line limit is what bites first.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell
		f := strings.Split(line, ":")
		if len(f) < 5 {
			continue
		}
		uid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		gid, err := strconv.ParseUint(f[3], 10, 32)
		if err != nil {
			continue
		}
		out = append(out, Account{
			Username: f[0], Gecos: f[4],
			UID: uint32(uid), primaryGID: uint32(gid),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
