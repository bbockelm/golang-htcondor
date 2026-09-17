package idmap

import (
	"context"
	"fmt"
)

// SSSDUser answers the forward question -- what is this account's GECOS
// -- over the SSSD socket protocol.
//
// This is the lookup every directory supports for a single name, whether
// or not it will enumerate, which is what makes the index's re-check
// meaningful on a host whose index is necessarily incomplete.
//
// It speaks to SSSD directly rather than running `getent`: a daemon that
// manipulates its own privileges should not be forking, and a library at
// this level has no business doing so regardless.
type SSSDUser struct {
	// SocketPath overrides the SSSD NSS socket. Empty uses the default.
	SocketPath string

	groups SSSDGroups // reuses the lazily-connected client
}

// Name identifies this verifier in logs.
func (s *SSSDUser) Name() string { return "sssd" }

// GecosOf returns the account's GECOS field.
//
// A missing account is ErrUnknownUser, never an empty GECOS: "deleted"
// and "no real name set" must not look alike to a caller deciding who
// somebody is.
func (s *SSSDUser) GecosOf(ctx context.Context, username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("no username to look up")
	}
	s.groups.SocketPath = s.SocketPath
	client, err := s.groups.connect(ctx)
	if err != nil {
		return "", err
	}
	u, err := client.GetUserByName(username)
	if err != nil {
		// SSSD does not distinguish "no such user" from a transport
		// failure in its error text reliably, so this is reported as a
		// lookup failure and the chain decides.
		return "", fmt.Errorf("SSSD lookup for %q: %w", username, err)
	}
	if u == nil || u.Name != username {
		return "", fmt.Errorf("%w: SSSD has no account %q", ErrUnknownUser, username)
	}
	return u.Gecos, nil
}

// PasswdFileVerifier answers the same question from a passwd file.
type PasswdFileVerifier struct{ File *PasswdFile }

// Name identifies this verifier in logs.
func (p *PasswdFileVerifier) Name() string { return "verify:" + p.File.Name() }

// GecosOf returns the account's GECOS field, or ErrUnknownUser.
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
	return "", fmt.Errorf("%w: no account %q in %s", ErrUnknownUser, username, p.File.Path)
}

// VerifierChain tries each verifier until one answers, so a host with
// local AND directory accounts can confirm either.
type VerifierChain struct{ Verifiers []Verifier }

// GecosOf returns the first definitive answer.
func (c *VerifierChain) GecosOf(ctx context.Context, username string) (string, error) {
	var firstErr error
	for _, v := range c.Verifiers {
		gecos, err := v.GecosOf(ctx, username)
		if err == nil {
			return gecos, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("%w: no verifier knows %q", ErrUnknownUser, username)
	}
	return "", firstErr
}
