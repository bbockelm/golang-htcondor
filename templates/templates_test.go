package templates

import (
	"path/filepath"
	"testing"
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
		Columns:  []string{"sample_id"},
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
		Columns:  []string{"sample_id"},
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
		Columns: []string{"x"},
	}, "alice"); err != nil {
		t.Fatalf("alice Save: %v", err)
	}
	if _, err := lib.Save(Template{
		Name: "My Pipeline", Contents: "echo bob\nqueue\n",
		Columns: []string{"y"},
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
		{"bad-column", Template{Name: "x", Contents: "queue", Columns: []string{"bad name"}}},
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
