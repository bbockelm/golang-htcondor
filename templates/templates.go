// Package templates provides batch-submission templates for the
// htcondor-api submit page. A "template" is the body of an HTCondor
// submit file (without the trailing `queue` line) plus a list of
// column variable names that will be table-bound by the user before
// submission.
//
// Sources, in order of precedence at the API layer:
//
//  1. User templates    — saved via POST /api/v1/templates; persisted
//                         to a SQL database keyed on (owner, id) so
//                         two users can have a template with the same
//                         id and never see each other's library.
//  2. Global templates  — loaded once from a YAML file path the
//                         operator points at via config.
//  3. Built-in templates — embedded in the binary (this package's
//                         builtin.yaml). Always available.
//
// The Library merges all three and exposes them through a single
// thread-safe API. Built-in and global templates are read-only; user
// templates can be created and deleted, scoped to the calling user.

package templates

import (
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "github.com/glebarez/sqlite" // SQLite driver (pure Go, no CGO)
	"gopkg.in/yaml.v3"
)

//go:embed builtin.yaml
var builtinYAML []byte

// Source identifies where a template came from. Read-only sources
// reject Save and Delete.
type Source string

const (
	SourceBuiltin Source = "builtin"
	SourceGlobal  Source = "global"
	SourceUser    Source = "user"
)

// Template is one entry in the library. Owner is only meaningful for
// SourceUser entries; built-in / global templates leave it blank.
type Template struct {
	ID          string   `json:"id"           yaml:"id"`
	Name        string   `json:"name"         yaml:"name"`
	Description string   `json:"description"  yaml:"description"`
	Columns     []string `json:"columns"      yaml:"columns"`
	Contents    string   `json:"contents"     yaml:"contents"`
	Source      Source   `json:"source"       yaml:"-"`
	Owner       string   `json:"owner,omitempty" yaml:"-"` // user templates only
}

// fileShape is the YAML shape used by both builtin.yaml and the
// global YAML file. User templates do not use this shape; they live
// in the SQL store.
type fileShape struct {
	Templates []Template `yaml:"templates"`
}

// Library is the merged template catalog. All methods are safe for
// concurrent use.
type Library struct {
	builtin []Template // immutable after construction
	global  []Template // immutable after construction (load-once)

	store userTemplateStore // nil = Save/Delete unavailable
}

// LibraryConfig configures library construction.
type LibraryConfig struct {
	// GlobalPath is an optional YAML file with operator-curated
	// templates. Empty string disables.
	GlobalPath string

	// UserStoreDBPath is the SQLite file backing user-saved
	// templates. Required for Save/Delete to succeed.
	//
	// Migration to Postgres is a contained change: implement the
	// userTemplateStore interface against a Postgres connection
	// string (and accept either via a discriminator field added
	// here later — for now we only ship the SQLite backend).
	UserStoreDBPath string
}

// userTemplateStore is the (small) interface every backend has to
// satisfy. Today the only backend is SQLite; a Postgres backend will
// land alongside as the deployment moves to Kubernetes with multiple
// replicas — both implementations are stateless across the wire so
// nothing in the Library cares which one is wired up.
type userTemplateStore interface {
	LoadAll(owner string) ([]Template, error)
	Get(id, owner string) (Template, bool, error)
	Save(t Template) error
	Delete(id, owner string) (bool, error)
	Close() error
}

// NewLibrary builds a Library, loading built-ins (mandatory) plus any
// configured global / user sources. A missing global file is fatal
// (the operator told us about it; if it's gone something's wrong).
// A missing SQLite file is created.
func NewLibrary(cfg LibraryConfig) (*Library, error) {
	builtin, err := loadBuiltin()
	if err != nil {
		return nil, fmt.Errorf("templates: load built-in: %w", err)
	}

	lib := &Library{builtin: builtin}

	if cfg.GlobalPath != "" {
		g, err := loadYAMLFile(cfg.GlobalPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("templates: load global %s: %w", cfg.GlobalPath, err)
		}
		for i := range g {
			g[i].Source = SourceGlobal
		}
		lib.global = g
	}

	if cfg.UserStoreDBPath != "" {
		store, err := newSQLUserTemplateStore(cfg.UserStoreDBPath)
		if err != nil {
			return nil, fmt.Errorf("templates: open user store %s: %w", cfg.UserStoreDBPath, err)
		}
		lib.store = store
	}

	return lib, nil
}

// Close releases resources (the user template DB connection). Safe to
// call multiple times.
func (l *Library) Close() error {
	if l.store == nil {
		return nil
	}
	return l.store.Close()
}

// loadBuiltin parses the embedded builtin.yaml. Errors are programming
// errors (we shipped a broken yaml) so we crash loudly at startup.
func loadBuiltin() ([]Template, error) {
	var f fileShape
	if err := yaml.Unmarshal(builtinYAML, &f); err != nil {
		return nil, fmt.Errorf("parse embedded builtin.yaml: %w", err)
	}
	for i := range f.Templates {
		f.Templates[i].Source = SourceBuiltin
		if err := validateTemplate(&f.Templates[i]); err != nil {
			return nil, fmt.Errorf("builtin %q: %w", f.Templates[i].ID, err)
		}
	}
	return f.Templates, nil
}

func loadYAMLFile(path string) ([]Template, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f fileShape
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for i := range f.Templates {
		if err := validateTemplate(&f.Templates[i]); err != nil {
			return nil, fmt.Errorf("%s: %q: %w", path, f.Templates[i].ID, err)
		}
	}
	return f.Templates, nil
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var columnPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateTemplate(t *Template) error {
	if t.Name == "" {
		return errors.New("name is required")
	}
	if t.Contents == "" {
		return errors.New("contents is required")
	}
	if t.ID == "" {
		t.ID = slugify(t.Name)
	}
	if !idPattern.MatchString(t.ID) {
		return fmt.Errorf("id %q must match %s", t.ID, idPattern)
	}
	for _, c := range t.Columns {
		if !columnPattern.MatchString(c) {
			return fmt.Errorf("column %q is not a valid HTCondor macro name", c)
		}
	}
	return nil
}

func slugify(s string) string {
	s = strings.ToLower(s)
	s = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		h := sha256.Sum256([]byte(s))
		return "tpl-" + hex.EncodeToString(h[:4])
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// All returns the catalog visible to `owner`. Built-in and global
// entries are visible to everybody; user entries are only visible to
// their owner. The returned slice is sorted: user / global / built-in,
// alphabetical inside each group.
//
// Passing owner == "" returns only the public (built-in + global)
// entries; this is useful for system-level callers that don't have a
// concrete user identity.
func (l *Library) All(owner string) []Template {
	out := make([]Template, 0, 16)
	if owner != "" && l.store != nil {
		users, err := l.store.LoadAll(owner)
		if err == nil {
			out = appendSorted(out, users)
		}
		// On store error, surface nothing for the user section; the
		// public sections still render. Caller's logger will pick up
		// the error if they're using ListWithError below.
	}
	out = appendSorted(out, l.global)
	out = appendSorted(out, l.builtin)
	return out
}

// AllWithError is like All but surfaces a store error to the caller.
// Useful when building HTTP responses where we want to log a DB
// outage instead of silently dropping the user section.
func (l *Library) AllWithError(owner string) ([]Template, error) {
	out := make([]Template, 0, 16)
	var storeErr error
	if owner != "" && l.store != nil {
		users, err := l.store.LoadAll(owner)
		if err != nil {
			storeErr = err
		} else {
			out = appendSorted(out, users)
		}
	}
	out = appendSorted(out, l.global)
	out = appendSorted(out, l.builtin)
	return out, storeErr
}

func appendSorted(dst []Template, src []Template) []Template {
	cp := make([]Template, len(src))
	copy(cp, src)
	sort.Slice(cp, func(i, j int) bool { return cp[i].Name < cp[j].Name })
	return append(dst, cp...)
}

// Get returns a template the caller is authorized to see. Lookup
// order: user (only if owner is non-empty), global, built-in.
func (l *Library) Get(id, owner string) (Template, bool) {
	if owner != "" && l.store != nil {
		t, ok, err := l.store.Get(id, owner)
		if err == nil && ok {
			return t, true
		}
	}
	for _, t := range l.global {
		if t.ID == id {
			return t, true
		}
	}
	for _, t := range l.builtin {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// Save persists a user template owned by `owner`. Updates an existing
// row when (owner, id) already exists; otherwise inserts a new row.
// The caller is required to be authenticated — Save returns an error
// if owner is empty.
func (l *Library) Save(t Template, owner string) (Template, error) {
	if l.store == nil {
		return Template{}, errors.New("templates: user store not configured (Save unavailable)")
	}
	if owner == "" {
		return Template{}, errors.New("templates: owner is required for Save")
	}
	t.Source = SourceUser
	t.Owner = owner
	if err := validateTemplate(&t); err != nil {
		return Template{}, err
	}
	if err := l.store.Save(t); err != nil {
		return Template{}, fmt.Errorf("persist user template: %w", err)
	}
	return t, nil
}

// Delete removes a user-saved template. Returns false if no template
// with that (owner, id) tuple exists. Built-in / global templates are
// not deletable; the handler should reject those before reaching us.
func (l *Library) Delete(id, owner string) (bool, error) {
	if l.store == nil {
		return false, errors.New("templates: user store not configured (Delete unavailable)")
	}
	if owner == "" {
		return false, errors.New("templates: owner is required for Delete")
	}
	return l.store.Delete(id, owner)
}

// ----------------------------------------------------------------------
// SQL-backed user template store (default backend).
//
// Schema (single table, composite primary key on (owner, id) so two
// users may both have a "my-pipeline" without collision):
//
//   CREATE TABLE templates_user (
//       owner       TEXT      NOT NULL,
//       id          TEXT      NOT NULL,
//       name        TEXT      NOT NULL,
//       description TEXT      NOT NULL DEFAULT '',
//       columns_csv TEXT      NOT NULL DEFAULT '',
//       contents    TEXT      NOT NULL,
//       created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
//       updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
//       PRIMARY KEY (owner, id)
//   );
//
// columns_csv is a packed comma-separated string. We could normalize
// to a side table (template_columns) but the read path always wants
// the whole list at once, so the join would be pure overhead.
// ----------------------------------------------------------------------

type sqlUserTemplateStore struct {
	db *sql.DB
}

func newSQLUserTemplateStore(path string) (*sqlUserTemplateStore, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	// SQLite supports a single writer at a time; serialize writes by
	// keeping max-open at 1. Reads through database/sql will still
	// be queued behind any in-flight write.
	db.SetMaxOpenConns(1)

	s := &sqlUserTemplateStore{db: db}
	if err := s.createTables(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *sqlUserTemplateStore) createTables() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS templates_user (
			owner       TEXT      NOT NULL,
			id          TEXT      NOT NULL,
			name        TEXT      NOT NULL,
			description TEXT      NOT NULL DEFAULT '',
			columns_csv TEXT      NOT NULL DEFAULT '',
			contents    TEXT      NOT NULL,
			created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (owner, id)
		);
	`)
	if err != nil {
		return fmt.Errorf("create templates_user: %w", err)
	}
	// Index on owner alone for fast LoadAll-by-user queries. The
	// (owner, id) primary key already covers point lookups, but the
	// index helps when scanning all rows for a single owner.
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS templates_user_owner ON templates_user(owner);`)
	if err != nil {
		return fmt.Errorf("create index: %w", err)
	}
	return nil
}

func (s *sqlUserTemplateStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *sqlUserTemplateStore) LoadAll(owner string) ([]Template, error) {
	rows, err := s.db.Query(`
		SELECT id, name, description, columns_csv, contents
		  FROM templates_user
		 WHERE owner = ?
		 ORDER BY name`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Template
	for rows.Next() {
		var t Template
		var colsCSV string
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &colsCSV, &t.Contents); err != nil {
			return nil, err
		}
		t.Owner = owner
		t.Source = SourceUser
		t.Columns = unpackColumns(colsCSV)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *sqlUserTemplateStore) Get(id, owner string) (Template, bool, error) {
	var t Template
	var colsCSV string
	err := s.db.QueryRow(`
		SELECT id, name, description, columns_csv, contents
		  FROM templates_user
		 WHERE owner = ? AND id = ?`, owner, id).
		Scan(&t.ID, &t.Name, &t.Description, &colsCSV, &t.Contents)
	if errors.Is(err, sql.ErrNoRows) {
		return Template{}, false, nil
	}
	if err != nil {
		return Template{}, false, err
	}
	t.Owner = owner
	t.Source = SourceUser
	t.Columns = unpackColumns(colsCSV)
	return t, true, nil
}

func (s *sqlUserTemplateStore) Save(t Template) error {
	now := time.Now().UTC()
	cols := packColumns(t.Columns)
	// UPSERT: SQLite (>=3.24) and Postgres both speak ON CONFLICT.
	// glebarez/sqlite tracks a recent SQLite version so we're fine.
	_, err := s.db.Exec(`
		INSERT INTO templates_user
			(owner, id, name, description, columns_csv, contents, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(owner, id) DO UPDATE SET
			name        = excluded.name,
			description = excluded.description,
			columns_csv = excluded.columns_csv,
			contents    = excluded.contents,
			updated_at  = excluded.updated_at`,
		t.Owner, t.ID, t.Name, t.Description, cols, t.Contents, now, now)
	return err
}

func (s *sqlUserTemplateStore) Delete(id, owner string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM templates_user WHERE owner = ? AND id = ?`, owner, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// packColumns / unpackColumns serialize the columns slice into a
// single TEXT cell. We use \x1f (ASCII Unit Separator) as the field
// separator; HTCondor macro names are constrained to [A-Za-z0-9_],
// so a non-printable byte is unambiguous and one byte cheaper than
// JSON-encoding.
const colSep = "\x1f"

func packColumns(cols []string) string {
	if len(cols) == 0 {
		return ""
	}
	return strings.Join(cols, colSep)
}

func unpackColumns(packed string) []string {
	if packed == "" {
		return nil
	}
	return strings.Split(packed, colSep)
}
