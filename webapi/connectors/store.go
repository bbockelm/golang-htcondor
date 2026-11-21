package connectors

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb/seal"
)

// Storage for connectors this server declares and for what users have
// granted them. See migration 0038 for the schema and why it is two
// tables.

// ErrNoKEK is returned when a sealed value is read by a server that has
// no key to open it.
//
// Refusing beats guessing, the same choice upstreamRefreshStore makes:
// the row was written by a server with a KEK and this one has none, so
// the bytes are unreadable, and treating them as plaintext would send
// ciphertext to a provider as if it were a secret.
var ErrNoKEK = errors.New("the stored value is sealed but no KEK is configured (HTTP_API_KEK_FILE)")

// Stored is a connector this server declares, as it comes back from the
// database.
//
// It carries NO client secret. That is not an oversight and not a
// convenience: a struct with a secret field is a struct that ends up in
// a JSON response the first time somebody adds an endpoint. The secret
// is reachable only through ClientSecret, which is a different call with
// a name that says what it does.
type Stored struct {
	ID   ID
	Kind Kind

	ClientID string
	// SecretSet reports whether a secret is stored, without being one.
	SecretSet       bool
	SecretUpdatedAt time.Time

	AuthorizationURL string
	TokenURL         string
	Scopes           []string
	Groups           []string
	Transfer         Transfer
	Enabled          bool

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Credential is one user's grant. It carries no refresh token for the
// same reason Stored carries no secret; see RefreshToken.
type Credential struct {
	Subject         string
	Connector       ID
	ProviderSubject string
	GrantedScopes   []string
	ObtainedAt      time.Time
	LastRefreshedAt time.Time
	LastUsedAt      time.Time
}

// Store reads and writes both tables.
type Store struct {
	db     *sql.DB
	sealer *seal.Sealer
	now    func() time.Time
}

// NewStore builds a store. A nil sealer means values are stored in the
// clear, which is what a server with no HTTP_API_KEK_FILE does.
func NewStore(db *sql.DB, sealer *seal.Sealer) *Store {
	return &Store{db: db, sealer: sealer, now: time.Now}
}

func (s *Store) clock() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

func (s *Store) ready() bool { return s != nil && s.db != nil }

// seal wraps a secret for storage. Without a sealer the bytes are
// stored as they are and the wrapped-key column stays NULL, which is
// how a later read knows which it is looking at.
func (s *Store) seal(plain []byte) (data, dek []byte, err error) {
	if len(plain) == 0 {
		return nil, nil, nil
	}
	if s.sealer == nil {
		return plain, nil, nil
	}
	return s.sealer.Seal(plain)
}

func (s *Store) open(data, dek []byte) ([]byte, error) {
	if len(dek) == 0 {
		return data, nil
	}
	if s.sealer == nil {
		return nil, ErrNoKEK
	}
	return s.sealer.Open(data, dek)
}

// --- connectors -------------------------------------------------------

// PutConnector creates or updates a stored connector.
//
// secret is the client secret to store: nil leaves whatever is there
// alone, and a non-nil empty slice clears it. The distinction matters --
// a form that round-trips an absent field as "" would wipe a working
// connector's secret on an unrelated edit, which is a failure nobody
// would attribute to the edit that caused it.
func (s *Store) PutConnector(ctx context.Context, c Stored, secret []byte) error {
	if !s.ready() {
		return errors.New("no database")
	}
	if err := c.ID.Validate(); err != nil {
		return err
	}
	if !c.Kind.Valid() {
		return fmt.Errorf("connector %s: kind %q is not one of credd, vault, oauth2", c.ID, c.Kind)
	}
	if c.Transfer == "" {
		c.Transfer = TransferSpool
	}
	if !c.Transfer.Valid() {
		return fmt.Errorf("connector %s: transfer %q is not spool or direct", c.ID, c.Transfer)
	}

	now := s.clock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// created_at is passed for the INSERT and is deliberately absent
	// from the DO UPDATE SET list below, which is what preserves it on
	// an edit. An earlier version read the existing row first to carry
	// the value forward; that was dead code, since the upsert never
	// touches the column. See TestUpdateKeepsCreatedAt.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO connectors (id, kind, client_id, authorization_url, token_url,
		                        scopes, groups, transfer, enabled, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			kind = excluded.kind,
			client_id = excluded.client_id,
			authorization_url = excluded.authorization_url,
			token_url = excluded.token_url,
			scopes = excluded.scopes,
			groups = excluded.groups,
			transfer = excluded.transfer,
			enabled = excluded.enabled,
			updated_at = excluded.updated_at`,
		c.ID.String(), string(c.Kind), c.ClientID, c.AuthorizationURL, c.TokenURL,
		strings.Join(c.Scopes, ","), strings.Join(c.Groups, ","), string(c.Transfer),
		c.Enabled, now, now); err != nil {
		return err
	}

	if secret != nil {
		data, dek, err := s.seal(secret)
		if err != nil {
			return fmt.Errorf("seal the client secret: %w", err)
		}
		var updatedAt any
		if len(secret) > 0 {
			updatedAt = now
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE connectors SET client_secret = ?, client_secret_dek = ?, secret_updated_at = ?
			WHERE id = ?`, data, dek, updatedAt, c.ID.String()); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Connector reads one stored connector. Found is false when the
// configuration declares it instead, or when nothing does.
func (s *Store) Connector(ctx context.Context, id ID) (Stored, bool, error) {
	if !s.ready() {
		return Stored{}, false, nil
	}
	rows, err := s.db.QueryContext(ctx, connectorSelect+` WHERE id = ?`, id.String())
	if err != nil {
		return Stored{}, false, err
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		return Stored{}, false, rows.Err()
	}
	c, err := scanConnector(rows)
	if err != nil {
		return Stored{}, false, err
	}
	return c, true, rows.Err()
}

// Connectors lists every stored connector, by id.
func (s *Store) Connectors(ctx context.Context) ([]Stored, error) {
	if !s.ready() {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, connectorSelect+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Stored
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// client_secret is deliberately absent from this list. A SELECT * here
// would put the secret in every struct that any caller ever renders.
const connectorSelect = `
	SELECT id, kind, client_id,
	       CASE WHEN client_secret IS NULL THEN 0 ELSE 1 END AS secret_set,
	       secret_updated_at, authorization_url, token_url, scopes, groups,
	       transfer, enabled, created_at, updated_at
	FROM connectors`

func scanConnector(rows *sql.Rows) (Stored, error) {
	var (
		c            Stored
		idStr, kind  string
		scopes       string
		groups       string
		transfer     string
		secretSet    int
		secretUpdate sql.NullTime
	)
	if err := rows.Scan(&idStr, &kind, &c.ClientID, &secretSet, &secretUpdate,
		&c.AuthorizationURL, &c.TokenURL, &scopes, &groups, &transfer,
		&c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return Stored{}, err
	}
	id, err := ParseID(idStr)
	if err != nil {
		return Stored{}, fmt.Errorf("stored connector id %q: %w", idStr, err)
	}
	c.ID = id
	c.Kind = Kind(kind)
	c.Scopes = splitList(scopes)
	c.Groups = splitList(groups)
	c.Transfer = Transfer(transfer)
	c.SecretSet = secretSet != 0
	if secretUpdate.Valid {
		c.SecretUpdatedAt = secretUpdate.Time
	}
	return c, nil
}

// ClientSecret reads a stored connector's client secret.
//
// A call of its own, named for what it does, because this is the one
// path by which a secret leaves the database. Every other read returns
// Stored, which cannot carry one.
func (s *Store) ClientSecret(ctx context.Context, id ID) ([]byte, error) {
	if !s.ready() {
		return nil, sql.ErrNoRows
	}
	var data, dek []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT client_secret, client_secret_dek FROM connectors WHERE id = ?`,
		id.String()).Scan(&data, &dek)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("connector %s has no stored client secret", id)
	}
	return s.open(data, dek)
}

// DeleteConnector removes a stored connector AND the credentials users
// granted it, reporting how many went with it.
//
// They go together because a credential whose connector is gone is
// unreachable: no page lists it, nothing refreshes it, and nobody can
// revoke it. The count is returned so a confirmation can say what is
// about to be destroyed rather than asking in the abstract.
func (s *Store) DeleteConnector(ctx context.Context, id ID) (credentials int64, err error) {
	if !s.ready() {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`DELETE FROM connector_credentials WHERE connector = ?`, id.String())
	if err != nil {
		return 0, err
	}
	credentials, _ = res.RowsAffected()

	if _, err := tx.ExecContext(ctx, `DELETE FROM connectors WHERE id = ?`, id.String()); err != nil {
		return 0, err
	}
	return credentials, tx.Commit()
}

// --- credentials ------------------------------------------------------

// PutCredential records what a user granted.
func (s *Store) PutCredential(ctx context.Context, c Credential, refreshToken []byte) error {
	if !s.ready() {
		return errors.New("no database")
	}
	if c.Subject == "" {
		return errors.New("a credential needs a subject")
	}
	if len(refreshToken) == 0 {
		return fmt.Errorf("connector %s: refusing to store an empty refresh token for %s",
			c.Connector, c.Subject)
	}
	data, dek, err := s.seal(refreshToken)
	if err != nil {
		return fmt.Errorf("seal the refresh token: %w", err)
	}
	now := s.clock()
	if c.ObtainedAt.IsZero() {
		c.ObtainedAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO connector_credentials
		    (subject, connector, provider_subject, refresh_token, refresh_token_dek,
		     granted_scopes, obtained_at, last_refreshed_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(subject, connector) DO UPDATE SET
			provider_subject = excluded.provider_subject,
			refresh_token = excluded.refresh_token,
			refresh_token_dek = excluded.refresh_token_dek,
			granted_scopes = excluded.granted_scopes,
			obtained_at = excluded.obtained_at,
			last_refreshed_at = excluded.last_refreshed_at`,
		c.Subject, c.Connector.String(), c.ProviderSubject, data, dek,
		strings.Join(c.GrantedScopes, " "), c.ObtainedAt, now)
	return err
}

// Credential reads one user's grant, without its refresh token.
func (s *Store) Credential(ctx context.Context, subject string, id ID) (Credential, bool, error) {
	if !s.ready() {
		return Credential{}, false, nil
	}
	var (
		c                       Credential
		scopes                  string
		refreshed, used         sql.NullTime
		providerSubject, connID string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT connector, provider_subject, granted_scopes, obtained_at,
		       last_refreshed_at, last_used_at
		FROM connector_credentials WHERE subject = ? AND connector = ?`,
		subject, id.String()).Scan(&connID, &providerSubject, &scopes,
		&c.ObtainedAt, &refreshed, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, err
	}
	c.Subject = subject
	c.Connector = id
	c.ProviderSubject = providerSubject
	c.GrantedScopes = strings.Fields(scopes)
	if refreshed.Valid {
		c.LastRefreshedAt = refreshed.Time
	}
	if used.Valid {
		c.LastUsedAt = used.Time
	}
	return c, true, nil
}

// RefreshToken reads one grant's refresh token.
//
// A call of its own, for the same reason ClientSecret is: this is the
// only path by which a user's refresh token leaves the database.
func (s *Store) RefreshToken(ctx context.Context, subject string, id ID) ([]byte, error) {
	if !s.ready() {
		return nil, sql.ErrNoRows
	}
	var data, dek []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT refresh_token, refresh_token_dek FROM connector_credentials
		 WHERE subject = ? AND connector = ?`, subject, id.String()).Scan(&data, &dek)
	if err != nil {
		return nil, err
	}
	return s.open(data, dek)
}

// MarkUsed records that a credential was handed to a job or the Picker.
//
// What makes it possible to tell a user their connection needs renewing
// before a job holds, and to answer whether anyone uses a connector at
// all. The credd sweeps by last use and cannot report.
func (s *Store) MarkUsed(ctx context.Context, subject string, id ID) error {
	if !s.ready() {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE connector_credentials SET last_used_at = ? WHERE subject = ? AND connector = ?`,
		s.clock(), subject, id.String())
	return err
}

// DeleteCredential forgets one user's grant, which is what a provider
// refusing to renew it means.
func (s *Store) DeleteCredential(ctx context.Context, subject string, id ID) error {
	if !s.ready() {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM connector_credentials WHERE subject = ? AND connector = ?`,
		subject, id.String())
	return err
}

// RevokeConnector forgets every grant for one connector, leaving the
// connector itself in place.
//
// This is what to do when a client secret has leaked or rotated: the
// stored refresh tokens were issued to the old registration and users
// have to consent again. It is a different verb from DeleteConnector on
// purpose, and it stays available on a connector the CONFIGURATION
// declares -- the configuration owns the definition, but these
// credentials are this server's own state, and an operator who cannot
// revoke them here has to go and delete database rows by hand.
func (s *Store) RevokeConnector(ctx context.Context, id ID) (int64, error) {
	if !s.ready() {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM connector_credentials WHERE connector = ?`, id.String())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CountCredentials reports how many users have connected one connector,
// and when it was last used by any of them.
func (s *Store) CountCredentials(ctx context.Context, id ID) (users int, lastUsed time.Time, err error) {
	if !s.ready() {
		return 0, time.Time{}, nil
	}
	if err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM connector_credentials WHERE connector = ?`,
		id.String()).Scan(&users); err != nil {
		return 0, time.Time{}, err
	}

	// ORDER BY ... LIMIT 1 rather than MAX(last_used_at), which looks
	// like the same question and is not. The SQLite driver converts a
	// value to time.Time from the DECLARED COLUMN TYPE, and an aggregate
	// expression has no declared type -- so MAX() comes back as a string
	// and scans into a NullTime as invalid. Reading the column itself
	// keeps its type.
	var last sql.NullTime
	err = s.db.QueryRowContext(ctx,
		`SELECT last_used_at FROM connector_credentials
		 WHERE connector = ? AND last_used_at IS NOT NULL
		 ORDER BY last_used_at DESC LIMIT 1`, id.String()).Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		return users, time.Time{}, nil
	}
	if err != nil {
		return 0, time.Time{}, err
	}
	if last.Valid {
		lastUsed = last.Time
	}
	return users, lastUsed, nil
}
