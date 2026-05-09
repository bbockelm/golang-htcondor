package templates

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestBuiltinsLoad confirms the embedded builtin.yaml parses, populates
// the expected ids, and stamps Source=builtin. Built-ins are visible
// to anybody (including the empty-owner system caller).
func TestBuiltinsLoad(t *testing.T) {
	lib, err := NewLibrary(LibraryConfig{})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })

	all := lib.All("")
	if len(all) < 2 {
		t.Fatalf("expected at least 2 built-ins, got %d", len(all))
	}
	wantIDs := map[string]bool{"hello-world": false, "sleep": false}
	for _, tpl := range all {
		if _, ok := wantIDs[tpl.ID]; ok {
			wantIDs[tpl.ID] = true
		}
		if tpl.Source != SourceBuiltin {
			t.Errorf("template %q: source=%q, want builtin", tpl.ID, tpl.Source)
		}
		if tpl.Contents == "" {
			t.Errorf("template %q: empty contents", tpl.ID)
		}
		if tpl.Owner != "" {
			t.Errorf("template %q: built-in should have empty Owner, got %q", tpl.ID, tpl.Owner)
		}
	}
	for id, found := range wantIDs {
		if !found {
			t.Errorf("expected built-in %q not present", id)
		}
	}
}

// TestUserStoreSaveDelete exercises the SQLite-backed user store:
// save, reload (via a fresh Library pointing at the same DB), update,
// delete.
func TestUserStoreSaveDelete(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "user.db")

	lib, err := NewLibrary(LibraryConfig{UserStoreDBPath: store})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}

	saved, err := lib.Save(Template{
		Name:     "My Pipeline",
		Contents: "executable = ./run.sh\nqueue\n",
		Columns:  []Column{{Name: "sample_id"}},
	}, "alice")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if saved.ID != "my-pipeline" {
		t.Errorf("expected slug %q, got %q", "my-pipeline", saved.ID)
	}
	if saved.Source != SourceUser {
		t.Errorf("expected source=user, got %q", saved.Source)
	}
	if saved.Owner != "alice" {
		t.Errorf("expected Owner=alice, got %q", saved.Owner)
	}
	_ = lib.Close()

	// Reload from disk via a fresh Library — confirms persistence works.
	lib2, err := NewLibrary(LibraryConfig{UserStoreDBPath: store})
	if err != nil {
		t.Fatalf("NewLibrary reload: %v", err)
	}
	t.Cleanup(func() { _ = lib2.Close() })

	got, ok := lib2.Get("my-pipeline", "alice")
	if !ok {
		t.Fatalf("template not present after reload")
	}
	if got.Contents != saved.Contents {
		t.Errorf("contents drift: %q vs %q", got.Contents, saved.Contents)
	}
	if got.Owner != "alice" {
		t.Errorf("expected Owner=alice on reload, got %q", got.Owner)
	}

	// Update by saving with the same id.
	updated, err := lib2.Save(Template{
		ID:       "my-pipeline",
		Name:     "My Pipeline",
		Contents: "# updated\nqueue\n",
		Columns:  []Column{{Name: "sample_id"}},
	}, "alice")
	if err != nil {
		t.Fatalf("Save (update): %v", err)
	}
	if updated.Contents != "# updated\nqueue\n" {
		t.Errorf("expected updated contents")
	}

	// Make sure update didn't duplicate.
	all := lib2.All("alice")
	count := 0
	for _, t := range all {
		if t.ID == "my-pipeline" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected single my-pipeline entry, got %d", count)
	}

	// Delete.
	deleted, err := lib2.Delete("my-pipeline", "alice")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !deleted {
		t.Errorf("Delete returned false")
	}
	if _, ok := lib2.Get("my-pipeline", "alice"); ok {
		t.Errorf("template still findable after Delete")
	}
}

// TestPerUserIsolation is the centerpiece of the owner-scoping work:
// alice and bob can each save a template called "my-pipeline" with
// completely different contents, neither sees the other's, and Delete
// only affects the calling user's row.
func TestPerUserIsolation(t *testing.T) {
	store := filepath.Join(t.TempDir(), "user.db")
	lib, err := NewLibrary(LibraryConfig{UserStoreDBPath: store})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })

	if _, err := lib.Save(Template{
		Name: "My Pipeline", Contents: "echo alice\nqueue\n",
		Columns: []Column{{Name: "x"}},
	}, "alice"); err != nil {
		t.Fatalf("alice Save: %v", err)
	}
	if _, err := lib.Save(Template{
		Name: "My Pipeline", Contents: "echo bob\nqueue\n",
		Columns: []Column{{Name: "y"}},
	}, "bob"); err != nil {
		t.Fatalf("bob Save: %v", err)
	}

	// alice sees only her own template (plus public).
	allAlice := lib.All("alice")
	for _, tt := range allAlice {
		if tt.Source == SourceUser {
			if tt.Owner != "alice" {
				t.Errorf("alice's catalog leaks user template owned by %q", tt.Owner)
			}
			if tt.Contents != "echo alice\nqueue\n" {
				t.Errorf("alice's my-pipeline contents wrong: %q", tt.Contents)
			}
		}
	}

	// bob sees only his own.
	allBob := lib.All("bob")
	for _, tt := range allBob {
		if tt.Source == SourceUser && tt.Owner != "bob" {
			t.Errorf("bob's catalog leaks user template owned by %q", tt.Owner)
		}
	}

	// Get is owner-scoped.
	got, ok := lib.Get("my-pipeline", "alice")
	if !ok || got.Contents != "echo alice\nqueue\n" {
		t.Errorf("alice Get returned wrong template: %+v ok=%v", got, ok)
	}
	got, ok = lib.Get("my-pipeline", "bob")
	if !ok || got.Contents != "echo bob\nqueue\n" {
		t.Errorf("bob Get returned wrong template: %+v ok=%v", got, ok)
	}

	// Cross-owner delete is a no-op (not found from this caller's
	// perspective). bob deleting "my-pipeline" must not delete
	// alice's.
	deleted, err := lib.Delete("my-pipeline", "bob")
	if err != nil {
		t.Fatalf("bob Delete: %v", err)
	}
	if !deleted {
		t.Errorf("bob Delete returned false; expected true")
	}
	if _, ok := lib.Get("my-pipeline", "alice"); !ok {
		t.Errorf("alice's template was deleted when bob deleted his")
	}
}

// TestSaveValidation rejects invalid templates and bad column names.
// TestVisibilitySharedAcrossOwners pins the cross-user picker:
// templates owned by Bob with visibility="shared" must appear in
// Alice's LoadAll, and Alice can Get them as starting points; templates
// owned by Bob with visibility="private" stay invisible to Alice. The
// regression we're guarding against is a future Save path that
// accidentally widens private rows to shared (or a list query that
// silently surfaces every owner's rows regardless of visibility).
func TestVisibilitySharedAcrossOwners(t *testing.T) {
	dir := t.TempDir()
	lib, err := NewLibrary(LibraryConfig{UserStoreDBPath: filepath.Join(dir, "user.db")})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })

	// Bob saves both a private and a shared template.
	if _, err := lib.Save(Template{
		Name:       "Bob Private",
		Contents:   "# private\nqueue\n",
		Columns:    []Column{{Name: "x"}},
		Visibility: VisibilityPrivate,
	}, "bob"); err != nil {
		t.Fatalf("Save bob private: %v", err)
	}
	if _, err := lib.Save(Template{
		Name:       "Bob Shared",
		Contents:   "# shared\nqueue\n",
		Columns:    []Column{{Name: "x"}},
		Visibility: VisibilityShared,
	}, "bob"); err != nil {
		t.Fatalf("Save bob shared: %v", err)
	}

	// (a) Alice's LoadAll surfaces the shared row but not the private.
	all := lib.All("alice")
	var sawShared, sawPrivate bool
	for _, t2 := range all {
		if t2.Source != SourceUser {
			continue
		}
		if t2.Owner == "bob" && t2.ID == "bob-shared" {
			sawShared = true
		}
		if t2.Owner == "bob" && t2.ID == "bob-private" {
			sawPrivate = true
		}
	}
	if !sawShared {
		t.Errorf("alice's picker should include bob's shared template; got %+v", all)
	}
	if sawPrivate {
		t.Errorf("alice's picker must NOT leak bob's private template; got %+v", all)
	}

	// (b) Alice can Get bob's shared row (load as a starting point).
	got, ok := lib.Get("bob-shared", "alice")
	switch {
	case !ok:
		t.Errorf("alice should be able to Get bob-shared")
	case got.Owner != "bob":
		t.Errorf("expected Get to surface real owner=bob; got %q", got.Owner)
	case got.Visibility != VisibilityShared:
		t.Errorf("expected Visibility=shared on the loaded ad; got %q", got.Visibility)
	}

	// (c) Alice CANNOT Get bob's private row.
	if _, ok := lib.Get("bob-private", "alice"); ok {
		t.Errorf("alice should NOT be able to Get bob-private")
	}
}

func TestSaveValidation(t *testing.T) {
	store := filepath.Join(t.TempDir(), "user.db")
	lib, err := NewLibrary(LibraryConfig{UserStoreDBPath: store})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })

	cases := []struct {
		name string
		in   Template
	}{
		{"missing-name", Template{Contents: "queue"}},
		{"missing-contents", Template{Name: "x"}},
		{"bad-column", Template{Name: "x", Contents: "queue", Columns: []Column{{Name: "bad name"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := lib.Save(c.in, "alice"); err == nil {
				t.Errorf("expected validation error, got nil")
			}
		})
	}
}

// TestSaveRequiresOwner confirms the API enforces an owner on every
// Save; an empty-owner Save is a clear server bug, not a public
// catalog write.
func TestSaveRequiresOwner(t *testing.T) {
	store := filepath.Join(t.TempDir(), "user.db")
	lib, err := NewLibrary(LibraryConfig{UserStoreDBPath: store})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })

	if _, err := lib.Save(Template{Name: "x", Contents: "queue"}, ""); err == nil {
		t.Errorf("expected error when owner is empty")
	}
}

// TestColumnYAMLAcceptsBareString confirms the YAML loader accepts the
// legacy `- name` form alongside the new `- name: foo / description: bar`
// shape — built-in templates that don't need help text stay terse.
func TestColumnYAMLAcceptsBareString(t *testing.T) {
	const src = `
templates:
  - id: mixed
    name: Mixed
    description: ""
    columns:
      - bare_name
      - { name: with_desc, description: "Sample id (must be unique)" }
    contents: |
      executable = /bin/true
`
	var f fileShape
	if err := yaml.Unmarshal([]byte(src), &f); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(f.Templates) != 1 {
		t.Fatalf("got %d templates, want 1", len(f.Templates))
	}
	cols := f.Templates[0].Columns
	if len(cols) != 2 {
		t.Fatalf("got %d cols, want 2", len(cols))
	}
	if cols[0].Name != "bare_name" || cols[0].Description != "" {
		t.Errorf("bare col: %+v", cols[0])
	}
	if cols[1].Name != "with_desc" || !strings.HasPrefix(cols[1].Description, "Sample id") {
		t.Errorf("desc col: %+v", cols[1])
	}
}

// TestColumnJSONAcceptsBareString confirms the API also accepts a
// JSON list of bare strings — older clients that haven't been
// updated to the {name, description} shape stay compatible.
func TestColumnJSONAcceptsBareString(t *testing.T) {
	type wrapper struct {
		Columns []Column `json:"columns"`
	}
	var w wrapper
	if err := jsonUnmarshalForTest(`{"columns": ["a", {"name":"b","description":"hello"}]}`, &w); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(w.Columns) != 2 {
		t.Fatalf("got %d cols", len(w.Columns))
	}
	if w.Columns[0].Name != "a" || w.Columns[0].Description != "" {
		t.Errorf("bare col: %+v", w.Columns[0])
	}
	if w.Columns[1].Name != "b" || w.Columns[1].Description != "hello" {
		t.Errorf("desc col: %+v", w.Columns[1])
	}
}

// TestInputFilesRoundtripDB exercises the user-store save/load path
// for templates with default input files: bytes have to come back
// exactly, including non-UTF8 binary content.
func TestInputFilesRoundtripDB(t *testing.T) {
	store := filepath.Join(t.TempDir(), "user.db")
	lib, err := NewLibrary(LibraryConfig{UserStoreDBPath: store})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })

	textScript := []byte("#!/bin/sh\necho hello\n")
	binBlob := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}

	saved, err := lib.Save(Template{
		Name:     "with-files",
		Contents: "executable = ./run.sh\nqueue\n",
		Columns:  []Column{{Name: "n", Description: "Sample number"}},
		InputFiles: []InputFile{
			{Name: "run.sh", Content: textScript},
			{Name: "blob.bin", Content: binBlob},
		},
	}, "alice")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(saved.InputFiles) != 2 {
		t.Fatalf("Save returned %d files", len(saved.InputFiles))
	}

	got, ok := lib.Get("with-files", "alice")
	if !ok {
		t.Fatalf("template missing after Save")
	}
	if len(got.InputFiles) != 2 {
		t.Fatalf("Get returned %d files", len(got.InputFiles))
	}
	if got.InputFiles[0].Name != "run.sh" || !bytes.Equal(got.InputFiles[0].Content, textScript) {
		t.Errorf("text file roundtrip wrong: %+v", got.InputFiles[0])
	}
	if got.InputFiles[1].Name != "blob.bin" || !bytes.Equal(got.InputFiles[1].Content, binBlob) {
		t.Errorf("binary file roundtrip wrong: name=%s len=%d", got.InputFiles[1].Name, len(got.InputFiles[1].Content))
	}
	if len(got.Columns) != 1 || got.Columns[0].Description != "Sample number" {
		t.Errorf("column description didn't roundtrip: %+v", got.Columns)
	}
}

// TestInputFileSizeLimit asserts that exceeding the per-file 1 MiB
// cap fails Save with a clear error, and that a payload right at
// the cap is accepted.
func TestInputFileSizeLimit(t *testing.T) {
	store := filepath.Join(t.TempDir(), "user.db")
	lib, err := NewLibrary(LibraryConfig{UserStoreDBPath: store})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })

	// Right at the cap: should pass.
	atCap := bytes.Repeat([]byte{'x'}, MaxInputFileBytes)
	if _, err := lib.Save(Template{
		Name:     "ok",
		Contents: "queue\n",
		InputFiles: []InputFile{
			{Name: "fits.bin", Content: atCap},
		},
	}, "alice"); err != nil {
		t.Fatalf("Save at-cap should succeed: %v", err)
	}

	// One byte over: should fail.
	overCap := bytes.Repeat([]byte{'x'}, MaxInputFileBytes+1)
	if _, err := lib.Save(Template{
		Name:     "too-big",
		Contents: "queue\n",
		InputFiles: []InputFile{
			{Name: "huge.bin", Content: overCap},
		},
	}, "alice"); err == nil {
		t.Fatalf("Save over-cap should have failed")
	}
}

// TestInputFileNamesRejectPathSep guards against a saved template
// being usable as a path-traversal vector at submit time.
func TestInputFileNamesRejectPathSep(t *testing.T) {
	store := filepath.Join(t.TempDir(), "user.db")
	lib, err := NewLibrary(LibraryConfig{UserStoreDBPath: store})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })

	bad := []string{"../etc/passwd", "subdir/file", "..", ".", `\windows`}
	for _, name := range bad {
		_, err := lib.Save(Template{
			Name:       "x",
			Contents:   "queue\n",
			InputFiles: []InputFile{{Name: name, Content: []byte("x")}},
		}, "alice")
		if err == nil {
			t.Errorf("Save accepted bad name %q", name)
		}
	}
}

// jsonUnmarshalForTest wraps json.Unmarshal for terser test bodies.
func jsonUnmarshalForTest(src string, dst any) error {
	return json.Unmarshal([]byte(src), dst)
}

// TestSaveWithoutStoreFails confirms Save returns a clear error when
// UserStoreDBPath wasn't configured (rather than silently dropping).
func TestSaveWithoutStoreFails(t *testing.T) {
	lib, err := NewLibrary(LibraryConfig{})
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	t.Cleanup(func() { _ = lib.Close() })
	if _, err := lib.Save(Template{Name: "x", Contents: "queue"}, "alice"); err == nil {
		t.Errorf("expected error when no user store configured")
	}
}
