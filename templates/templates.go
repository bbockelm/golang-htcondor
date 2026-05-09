// Package templates provides batch-submission templates for the
// htcondor-api submit page. A "template" is the body of an HTCondor
// submit file (without the trailing `queue` line) plus a list of
// column variable names that will be table-bound by the user before
// submission.
//
// Sources, in order of precedence at the API layer:
//
//  1. User templates    — saved via POST /api/v1/templates; persisted
//     to a SQL database keyed on (owner, id) so
//     two users can have a template with the same
//     id and never see each other's library.
//  2. Global templates  — loaded once from a YAML file path the
//     operator points at via config.
//  3. Built-in templates — embedded in the binary (this package's
//     builtin.yaml). Always available.
//
// The Library merges all three and exposes them through a single
// thread-safe API. Built-in and global templates are read-only; user
// templates can be created and deleted, scoped to the calling user.
package templates

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	_ "github.com/glebarez/sqlite" // SQLite driver (pure Go, no CGO)
	"gopkg.in/yaml.v3"
)

//go:embed builtin.yaml
var builtinYAML []byte

// Source identifies where a template came from. Read-only sources
// reject Save and Delete.
type Source string

// Source values: where a Template came from.
const (
	SourceBuiltin Source = "builtin"
	SourceGlobal  Source = "global"
	SourceUser    Source = "user"
)

// Template is one entry in the library. Owner is only meaningful for
// SourceUser entries; built-in / global templates leave it blank.
//
// Columns are HTCondor macro names (substituted via $(name) in the
// submit-file body); the optional Description on each one is shown
// as help text on the batch-table column header. InputFiles are an
// optional default attachment set — the submit page merges them with
// any per-batch files the user drops, capped at MaxInputFileBytes
// each (see validateTemplate).
type Template struct {
	ID          string      `json:"id"                   yaml:"id"`
	Name        string      `json:"name"                 yaml:"name"`
	Description string      `json:"description"          yaml:"description"`
	Columns     []Column    `json:"columns"              yaml:"columns"`
	Contents    string      `json:"contents"             yaml:"contents"`
	InputFiles  []InputFile `json:"input_files,omitempty" yaml:"input_files,omitempty"`
	Source      Source      `json:"source"               yaml:"-"`
	Owner       string      `json:"owner,omitempty"      yaml:"-"` // user templates only
	// Visibility controls who can see the template in the picker.
	// "private" (default): only Owner. "shared": every authenticated
	// user. The owner is always allowed to mutate; non-owners can
	// load a shared template as a starting point but cannot edit or
	// delete it. Built-in / global sources leave this blank — they
	// have their own discoverability story (catalog YAMLs).
	Visibility Visibility `json:"visibility,omitempty" yaml:"-"`
}

// Visibility is the access scope of a user-saved template.
type Visibility string

// Visibility values. The string forms are persisted in SQLite and
// returned over the wire — don't rename them without a migration.
//
//   - VisibilityPrivate: only the template's owner sees it in the
//     picker and can Load/Save it. The default for SaveTemplate
//     when the field is omitted.
//   - VisibilityShared: every authenticated user sees this template
//     in their picker. Useful for "team" templates an admin or a
//     trusted user wants to share, but note the social-engineering
//     pivot: the SPA must clearly attribute shared templates to
//     their author so users review them before submitting.
const (
	VisibilityPrivate Visibility = "private"
	VisibilityShared  Visibility = "shared"
)

// Column is one variable on a template. Description is optional and
// surfaces as the column header's help text in the batch table.
type Column struct {
	Name        string `json:"name"                  yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// UnmarshalYAML accepts either a bare string (legacy: "name") or a full
// {name, description} map. Built-in templates that don't need help
// text stay terse.
func (c *Column) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		c.Name = node.Value
		return nil
	}
	type rawColumn struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	var raw rawColumn
	if err := node.Decode(&raw); err != nil {
		return err
	}
	c.Name = raw.Name
	c.Description = raw.Description
	return nil
}

// UnmarshalJSON mirrors UnmarshalYAML for the API: accept either a
// bare string or a {name, description} object. Older clients that
// still POST `["foo", "bar"]` keep working.
func (c *Column) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &c.Name)
	}
	type rawColumn struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	var raw rawColumn
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	c.Name = raw.Name
	c.Description = raw.Description
	return nil
}

// ColumnNames returns just the macro names, in order. Useful for code
// paths that don't care about descriptions (e.g., the submit-file
// emitter, which only needs to write `queue a, b, c from ...`).
func ColumnNames(cols []Column) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.Name
	}
	return out
}

// MaxInputFileBytes caps a single InputFile's content size. Templates
// are stored verbatim (in YAML or in the user-store DB) so we want
// each file small — anything larger belongs in transfer_input_files
// pointing at object storage. The 1 MiB ceiling matches the per-file
// limit the operator agreed on; total-per-template is loosely capped
// in validateTemplate.
const MaxInputFileBytes = 1 << 20 // 1 MiB

// MaxTotalInputFileBytes caps the sum of all InputFile contents on a
// single template. Sized at 5× the per-file ceiling so a small set of
// scripts + a config blob fits comfortably while keeping each row in
// the user-store DB reasonable.
const MaxTotalInputFileBytes = 5 * MaxInputFileBytes

// InputFile is an optional default attachment that ships with the
// template. The submit page hands these to /api/v1/jobs/{id}/input
// alongside any per-batch files the user drops.
//
// JSON encoding: Content is base64 (Go's encoding/json default for
// []byte). YAML encoding uses two distinct keys (`content` for plain
// UTF-8 text — typical for scripts — or `content_b64` for opaque
// binary), see (un)marshal methods below.
type InputFile struct {
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

// UnmarshalYAML accepts either `content: "..."` (plain text — the
// common case for shell scripts) or `content_b64: "..."` (base64 for
// arbitrary bytes). Exactly one should be set.
func (f *InputFile) UnmarshalYAML(node *yaml.Node) error {
	type rawFile struct {
		Name          string `yaml:"name"`
		Content       string `yaml:"content"`
		ContentBase64 string `yaml:"content_b64"`
	}
	var raw rawFile
	if err := node.Decode(&raw); err != nil {
		return err
	}
	f.Name = raw.Name
	if raw.ContentBase64 != "" {
		b, err := base64.StdEncoding.DecodeString(raw.ContentBase64)
		if err != nil {
			return fmt.Errorf("input file %q: decode content_b64: %w", raw.Name, err)
		}
		f.Content = b
	} else {
		f.Content = []byte(raw.Content)
	}
	return nil
}

// MarshalYAML chooses `content:` for valid UTF-8 (so a built-in or
// operator-curated template stays human-readable) and falls back to
// `content_b64:` for opaque binary.
func (f InputFile) MarshalYAML() (any, error) {
	if utf8.Valid(f.Content) {
		return struct {
			Name    string `yaml:"name"`
			Content string `yaml:"content"`
		}{f.Name, string(f.Content)}, nil
	}
	return struct {
		Name          string `yaml:"name"`
		ContentBase64 string `yaml:"content_b64"`
	}{f.Name, base64.StdEncoding.EncodeToString(f.Content)}, nil
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

	// UserStoreDB is an externally-managed SQLite *sql.DB whose
	// templates_user table has been set up by the caller (typically
	// the unified appdb migrations on the htcondor-api side). When
	// non-nil, Save/Delete work against this DB and the library does
	// NOT take ownership — closing the Library is a no-op for the DB.
	//
	// Mutually exclusive with UserStoreDBPath. UserStoreDB wins.
	UserStoreDB *sql.DB

	// UserStoreDBPath is the legacy stand-alone-file path. Used by
	// tests and by older deployments that haven't migrated to the
	// unified app database. The library opens the file itself, runs
	// its own DDL on first use, and closes it on Close().
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

	switch {
	case cfg.UserStoreDB != nil:
		lib.store = newSQLUserTemplateStoreFromDB(cfg.UserStoreDB)
	case cfg.UserStoreDBPath != "":
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
	raw, err := os.ReadFile(path) //nolint:gosec // path is operator-controlled config
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
		if !columnPattern.MatchString(c.Name) {
			return fmt.Errorf("column %q is not a valid HTCondor macro name", c.Name)
		}
	}
	// Per-file and total caps on input files. We surface the offending
	// name so the operator can find it in a large template.
	var totalBytes int
	seenNames := make(map[string]bool, len(t.InputFiles))
	for i, f := range t.InputFiles {
		if f.Name == "" {
			return fmt.Errorf("input_files[%d]: name is required", i)
		}
		if seenNames[f.Name] {
			return fmt.Errorf("input_files: duplicate name %q", f.Name)
		}
		seenNames[f.Name] = true
		// Reject path components — these names are written into the
		// job sandbox by /input multipart, which already rejects path
		// traversal, but enforce it earlier so the template can't
		// even be saved with a bad name.
		if strings.ContainsAny(f.Name, "/\\") || f.Name == "." || f.Name == ".." {
			// Quote the literal "." and ".." so the message ends with a
			// closing-quote rather than punctuation — keeps revive's
			// error-strings rule happy without losing the specifics
			// the user needs to fix the bad name.
			return fmt.Errorf("input file %q: name must not contain path separators and must not be %q or %q", f.Name, ".", "..")
		}
		if len(f.Content) > MaxInputFileBytes {
			return fmt.Errorf("input file %q: %d bytes exceeds the %d-byte per-file cap",
				f.Name, len(f.Content), MaxInputFileBytes)
		}
		totalBytes += len(f.Content)
	}
	if totalBytes > MaxTotalInputFileBytes {
		return fmt.Errorf("input files: %d bytes total exceeds the %d-byte template cap",
			totalBytes, MaxTotalInputFileBytes)
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
	// Default to private when the caller didn't pick a visibility —
	// matches the historical (pre-feature) behavior. Reject anything
	// that's neither private nor shared so a future client typo
	// can't silently land an unrecognized value in the DB.
	switch t.Visibility {
	case "":
		t.Visibility = VisibilityPrivate
	case VisibilityPrivate, VisibilityShared:
		// valid
	default:
		return Template{}, fmt.Errorf("templates: invalid visibility %q (want %q or %q)",
			t.Visibility, VisibilityPrivate, VisibilityShared)
	}
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
//       owner        TEXT      NOT NULL,
//       id           TEXT      NOT NULL,
//       name         TEXT      NOT NULL,
//       description  TEXT      NOT NULL DEFAULT '',
//       columns_csv  TEXT      NOT NULL DEFAULT '',
//       columns_json TEXT      NOT NULL DEFAULT '',  -- {name, description}[]
//       contents     TEXT      NOT NULL,
//       input_files  BLOB      NOT NULL DEFAULT X'', -- gob/JSON of []InputFile
//       created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
//       updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
//       PRIMARY KEY (owner, id)
//   );
//
// columns_csv kept for back-compat with rows written before the
// schema grew the json column; new writes populate columns_json
// (which has descriptions) and leave columns_csv as the legacy
// names-only fallback. Reads prefer columns_json when present.
// input_files is a JSON-encoded array of {name, content} (with
// content base64-encoded by encoding/json's []byte default).
// ----------------------------------------------------------------------

// ownsDB tracks whether this store is responsible for closing the
// underlying *sql.DB. True when the store opened the file itself
// (legacy LibraryConfig.UserStoreDBPath path); false when an external
// caller injected an already-open DB (LibraryConfig.UserStoreDB).
type sqlUserTemplateStore struct {
	db     *sql.DB
	ownsDB bool
}

// newSQLUserTemplateStore opens its own SQLite file, creates the
// templates_user table if missing, and returns a store. Used by the
// stand-alone path (tests, the legacy UserStoreDBPath config field).
// Production wires the table through appdb migrations and uses
// newSQLUserTemplateStoreFromDB instead.
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

	s := &sqlUserTemplateStore{db: db, ownsDB: true}
	if err := s.createTables(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// newSQLUserTemplateStoreFromDB wraps an externally-managed DB whose
// templates_user schema is already set up (typically by appdb's goose
// migrations). The store will not close db on Close().
func newSQLUserTemplateStoreFromDB(db *sql.DB) *sqlUserTemplateStore {
	return &sqlUserTemplateStore{db: db, ownsDB: false}
}

func (s *sqlUserTemplateStore) createTables() error {
	ctx := context.Background()
	_, err := s.db.ExecContext(ctx, `
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
	// Lazy migration: add columns_json and input_files when missing.
	// SQLite's ALTER TABLE only supports ADD COLUMN; that's all we
	// need. Both columns default to empty so old rows read as a
	// template with no descriptions and no input files.
	if err := s.addColumnIfMissing(ctx, "templates_user", "columns_json", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing(ctx, "templates_user", "input_files", "BLOB NOT NULL DEFAULT X''"); err != nil {
		return err
	}
	// Templates default to private (matches pre-feature behavior).
	// Goose migration 0003_template_visibility.sql covers the
	// production-DB path; this addColumnIfMissing covers the
	// legacy stand-alone-file path used by tests + UserStoreDBPath.
	if err := s.addColumnIfMissing(ctx, "templates_user", "visibility", "TEXT NOT NULL DEFAULT 'private'"); err != nil {
		return err
	}
	// Index on owner alone for fast LoadAll-by-user queries. The
	// (owner, id) primary key already covers point lookups, but the
	// index helps when scanning all rows for a single owner.
	_, err = s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS templates_user_owner ON templates_user(owner);`)
	if err != nil {
		return fmt.Errorf("create index: %w", err)
	}
	return nil
}

// addColumnIfMissing is the manual migration helper. SQLite's PRAGMA
// table_info returns one row per column; we look for the target name
// and run ALTER TABLE only when it's not there. Idempotent — second
// startup is a no-op.
func (s *sqlUserTemplateStore) addColumnIfMissing(ctx context.Context, table, column, decl string) error {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s);", table))
	if err != nil {
		return fmt.Errorf("table_info(%s): %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("scan table_info: %w", err)
		}
		if name == column {
			return nil // already present
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("table_info(%s) iter: %w", table, err)
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s;", table, column, decl))
	if err != nil {
		return fmt.Errorf("alter %s add %s: %w", table, column, err)
	}
	return nil
}

func (s *sqlUserTemplateStore) Close() error {
	if s.db == nil || !s.ownsDB {
		return nil
	}
	return s.db.Close()
}

// LoadAll returns the templates the given user is allowed to see in
// the picker:
//   - every row owned by `owner` (their private + shared templates)
//   - every row from any OTHER owner whose visibility is "shared"
//
// Only the owner's rows expose mutation paths in the API layer; this
// function is read-only and returns the union ordered by name.
func (s *sqlUserTemplateStore) LoadAll(owner string) ([]Template, error) {
	rows, err := s.db.QueryContext(context.Background(), `
		SELECT owner, id, name, description, columns_csv, columns_json, contents, input_files, visibility
		  FROM templates_user
		 WHERE owner = ? OR visibility = 'shared'
		 ORDER BY name`, owner)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Template
	for rows.Next() {
		var t Template
		var colsCSV, colsJSON string
		var inputFilesBlob []byte
		var visibility string
		if err := rows.Scan(&t.Owner, &t.ID, &t.Name, &t.Description, &colsCSV, &colsJSON, &t.Contents, &inputFilesBlob, &visibility); err != nil {
			return nil, err
		}
		t.Source = SourceUser
		t.Visibility = Visibility(visibility)
		if t.Visibility == "" {
			t.Visibility = VisibilityPrivate
		}
		t.Columns = decodeColumns(colsJSON, colsCSV)
		files, ferr := decodeInputFiles(inputFilesBlob)
		if ferr != nil {
			return nil, fmt.Errorf("decode input_files for %s/%s: %w", t.Owner, t.ID, ferr)
		}
		t.InputFiles = files
		out = append(out, t)
	}
	return out, rows.Err()
}

// Get returns one template the user is allowed to see:
//   - their own template at (owner, id), regardless of visibility, OR
//   - any other user's template at id when its visibility is "shared".
//
// `owner` is the actor making the request; the returned Template's
// Owner field reflects the actual writer (which may differ when the
// user is loading a shared template).
func (s *sqlUserTemplateStore) Get(id, owner string) (Template, bool, error) {
	var t Template
	var colsCSV, colsJSON string
	var inputFilesBlob []byte
	var visibility string
	err := s.db.QueryRowContext(context.Background(), `
		SELECT owner, id, name, description, columns_csv, columns_json, contents, input_files, visibility
		  FROM templates_user
		 WHERE id = ? AND (owner = ? OR visibility = 'shared')
		 LIMIT 1`, id, owner).
		Scan(&t.Owner, &t.ID, &t.Name, &t.Description, &colsCSV, &colsJSON, &t.Contents, &inputFilesBlob, &visibility)
	if errors.Is(err, sql.ErrNoRows) {
		return Template{}, false, nil
	}
	if err != nil {
		return Template{}, false, err
	}
	t.Source = SourceUser
	t.Visibility = Visibility(visibility)
	if t.Visibility == "" {
		t.Visibility = VisibilityPrivate
	}
	t.Columns = decodeColumns(colsJSON, colsCSV)
	files, ferr := decodeInputFiles(inputFilesBlob)
	if ferr != nil {
		return Template{}, false, fmt.Errorf("decode input_files for %s/%s: %w", t.Owner, t.ID, ferr)
	}
	t.InputFiles = files
	return t, true, nil
}

func (s *sqlUserTemplateStore) Save(t Template) error {
	now := time.Now().UTC()
	colsCSV := packColumnNames(t.Columns) // legacy, names-only
	colsJSON, err := json.Marshal(t.Columns)
	if err != nil {
		return fmt.Errorf("marshal columns: %w", err)
	}
	inputFilesBlob, err := encodeInputFiles(t.InputFiles)
	if err != nil {
		return fmt.Errorf("encode input_files: %w", err)
	}
	visibility := string(t.Visibility)
	if visibility == "" {
		visibility = string(VisibilityPrivate)
	}
	// UPSERT: SQLite (>=3.24) and Postgres both speak ON CONFLICT.
	// glebarez/sqlite tracks a recent SQLite version so we're fine.
	_, err = s.db.ExecContext(context.Background(), `
		INSERT INTO templates_user
			(owner, id, name, description, columns_csv, columns_json, contents, input_files, visibility, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(owner, id) DO UPDATE SET
			name         = excluded.name,
			description  = excluded.description,
			columns_csv  = excluded.columns_csv,
			columns_json = excluded.columns_json,
			contents     = excluded.contents,
			input_files  = excluded.input_files,
			visibility   = excluded.visibility,
			updated_at   = excluded.updated_at`,
		t.Owner, t.ID, t.Name, t.Description, colsCSV, string(colsJSON), t.Contents, inputFilesBlob, visibility, now, now)
	return err
}

func (s *sqlUserTemplateStore) Delete(id, owner string) (bool, error) {
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM templates_user WHERE owner = ? AND id = ?`, owner, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// packColumnNames / unpackColumnNames serialize a list of column
// macro names (no descriptions) into the legacy `columns_csv` TEXT
// cell. We keep writing this column for back-compat with any reader
// that doesn't know about columns_json yet. \x1f (ASCII Unit
// Separator) is the field separator; HTCondor macro names are
// constrained to [A-Za-z0-9_], so a non-printable byte is
// unambiguous and one byte cheaper than JSON-encoding.
const colSep = "\x1f"

func packColumnNames(cols []Column) string {
	if len(cols) == 0 {
		return ""
	}
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name
	}
	return strings.Join(names, colSep)
}

func unpackColumnNames(packed string) []Column {
	if packed == "" {
		return nil
	}
	parts := strings.Split(packed, colSep)
	out := make([]Column, len(parts))
	for i, p := range parts {
		out[i] = Column{Name: p}
	}
	return out
}

// decodeColumns prefers the JSON-encoded columns_json cell (which
// preserves descriptions) and falls back to the legacy CSV when
// columns_json is empty (rows written before the schema migration).
func decodeColumns(jsonCell, csvCell string) []Column {
	if jsonCell != "" {
		var out []Column
		if err := json.Unmarshal([]byte(jsonCell), &out); err == nil {
			return out
		}
		// Malformed JSON shouldn't happen — we wrote it ourselves —
		// but if it does, fall through to the CSV fallback rather
		// than silently dropping the column list.
	}
	return unpackColumnNames(csvCell)
}

// encodeInputFiles / decodeInputFiles handle the BLOB column. We use
// JSON (with []byte → base64 via encoding/json's default) so the
// column stays human-debuggable with sqlite3 CLI. Empty slice is
// stored as a zero-length blob, not the string "[]" — saves a few
// bytes per row when no input files are attached (the common case).
func encodeInputFiles(files []InputFile) ([]byte, error) {
	if len(files) == 0 {
		// Return a zero-length, non-nil slice — the SQLite driver
		// otherwise sends NULL, which trips the NOT NULL constraint
		// on the column. Decode treats len==0 as "no files".
		return []byte{}, nil
	}
	return json.Marshal(files)
}

func decodeInputFiles(blob []byte) ([]InputFile, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	var out []InputFile
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, err
	}
	return out, nil
}
