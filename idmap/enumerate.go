package idmap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
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

// Getent enumerates through NSS by running `getent passwd`, so it sees
// whatever the system sees -- local files plus SSSD, LDAP, and anything
// else in nsswitch.conf.
//
// The catch is real and worth stating: SSSD answers `getent passwd` with
// directory entries only when its domain has `enumerate = true`, which
// is off by default and discouraged for large directories. A site whose
// accounts live in LDAP and whose SSSD does not enumerate will get a
// short list here and users will fail to resolve -- which is why
// Resolver logs the count, and why that count is worth an operator's
// attention on startup rather than at the first failed login.
type Getent struct {
	// Path to getent. Empty means look it up on PATH.
	Path string
}

// Name identifies this source in logs.
func (g *Getent) Name() string { return "getent passwd" }

// Enumerate lists every account NSS will hand over.
func (g *Getent) Enumerate(ctx context.Context) ([]Account, error) {
	bin := g.Path
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("getent"); err != nil {
			return nil, fmt.Errorf("getent is not available: %w", err)
		}
	}
	cmd := exec.CommandContext(ctx, bin, "passwd") //nolint:gosec // bin is resolved from PATH or operator config
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// getent exits 2 when the database is empty, which for our
		// purposes is a legitimate (if alarming) answer, not a failure.
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("running %s passwd: %w: %s", bin, err, strings.TrimSpace(stderr.String()))
		}
	}
	return parsePasswd(&stdout)
}

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
		out = append(out, Account{Username: f[0], Gecos: f[4], UID: uint32(uid)})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
