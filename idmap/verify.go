package idmap

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// GetentUser answers the forward question -- what is this account's
// GECOS -- by running `getent passwd <username>`.
//
// This is the lookup every user database supports, including the ones
// that will not enumerate: SSSD answers a single-name query for a
// directory account whether or not `enumerate` is on. So a site whose
// index is necessarily incomplete still gets its index hits confirmed,
// and Resolver's re-check is not merely a formality.
type GetentUser struct {
	// Path to getent. Empty means look it up on PATH.
	Path string
}

// Name identifies this verifier in logs.
func (g *GetentUser) Name() string { return "getent passwd <user>" }

// GecosOf returns the account's GECOS field. A missing account is an
// error, never an empty GECOS: "deleted" and "no real name set" must not
// look alike to a caller deciding who somebody is.
func (g *GetentUser) GecosOf(ctx context.Context, username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("no username to look up")
	}
	bin := g.Path
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("getent"); err != nil {
			return "", fmt.Errorf("getent is not available: %w", err)
		}
	}
	cmd := exec.CommandContext(ctx, bin, "passwd", username) //nolint:gosec // bin is from PATH or operator config; username is an argv element
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// getent exits 2 for "not found", which is the common case and
		// deserves the clearer message.
		if stdout.Len() == 0 {
			return "", fmt.Errorf("no account %q: %w: %s", username, err, strings.TrimSpace(stderr.String()))
		}
	}
	accounts, err := parsePasswd(&stdout)
	if err != nil {
		return "", err
	}
	for _, a := range accounts {
		if a.Username == username {
			return a.Gecos, nil
		}
	}
	return "", fmt.Errorf("no account %q", username)
}

// PasswdFileVerifier answers the same question from a passwd file. Useful
// where the accounts are local, and in tests.
type PasswdFileVerifier struct{ File *PasswdFile }

// Name identifies this verifier in logs.
func (p *PasswdFileVerifier) Name() string { return "verify:" + p.File.Name() }

// GecosOf returns the account's GECOS field, or an error if it is absent.
func (p *PasswdFileVerifier) GecosOf(ctx context.Context, username string) (string, error) {
	accounts, err := p.File.Enumerate(ctx)
	if err != nil {
		return "", err
	}
	for _, a := range accounts {
		if a.Username == username {
			return a.Gecos, nil
		}
	}
	return "", fmt.Errorf("no account %q in %s", username, p.File.Path)
}
