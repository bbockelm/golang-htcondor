package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// This file holds the admin-editable, non-provenance client policy: the set of
// grant types a client may use, and the service identity a client_credentials
// token asserts. Unlike the provenance columns (origin, last_used, ...), these
// ARE things an operator legitimately sets after registration.

// supportedGrantTypes is the closed set the admin UI/PATCH may assign -- the
// grants this server actually implements.
var supportedGrantTypes = map[string]bool{
	"authorization_code":   true,
	"refresh_token":        true,
	"client_credentials":   true,
	tokenExchangeGrantType: true,
}

// confidentialOnlyGrants may not be assigned to a public client: they either
// authenticate the client with a secret (client_credentials) or act on another
// principal's behalf and so must be a trusted, authenticated client (token
// exchange).
var confidentialOnlyGrants = map[string]bool{
	"client_credentials":   true,
	tokenExchangeGrantType: true,
}

// validateGrantTypes checks a requested grant set against what the server
// supports and what makes sense for the client. A public client may not hold
// client_credentials (it has no secret to authenticate the grant).
func validateGrantTypes(grants []string, public bool) error {
	if len(grants) == 0 {
		return fmt.Errorf("at least one grant type is required")
	}
	seen := make(map[string]bool, len(grants))
	for _, g := range grants {
		if !supportedGrantTypes[g] {
			return fmt.Errorf("unsupported grant type %q", g)
		}
		if seen[g] {
			return fmt.Errorf("duplicate grant type %q", g)
		}
		seen[g] = true
		if public && confidentialOnlyGrants[g] {
			return fmt.Errorf("%s cannot be granted to a public client", g)
		}
	}
	return nil
}

// updateClientGrants sets a client's grant_types (and, when non-nil, its
// service_subject) in one statement. Reports whether the client existed.
func updateClientGrants(ctx context.Context, db *sql.DB, clientID string, grants []string, serviceSubject *string) (bool, error) {
	grantsJSON, err := json.Marshal(grants)
	if err != nil {
		return false, err
	}
	var res sql.Result
	if serviceSubject != nil {
		res, err = db.ExecContext(ctx,
			`UPDATE oauth2_clients SET grant_types = ?, service_subject = ? WHERE id = ?`,
			string(grantsJSON), *serviceSubject, clientID)
	} else {
		res, err = db.ExecContext(ctx,
			`UPDATE oauth2_clients SET grant_types = ? WHERE id = ?`,
			string(grantsJSON), clientID)
	}
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// clientServiceSubject reads a client's configured service identity. Empty means
// none configured (client_credentials must then be refused).
func (s *OAuth2Storage) clientServiceSubject(ctx context.Context, clientID string) (string, error) {
	var subject string
	err := s.db.QueryRowContext(ctx,
		`SELECT service_subject FROM oauth2_clients WHERE id = ?`, clientID).Scan(&subject)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return subject, err
}
