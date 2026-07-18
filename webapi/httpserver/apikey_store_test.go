package httpserver

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestAPIKeyStoreInsertLookup is the basic happy path: insert a row,
// look it up by key_id, see all the fields back. The store doesn't
// hash the secret — that's the apikey package's job — so we just
// stash a fixed string and confirm it round-trips.
func TestAPIKeyStoreInsertLookup(t *testing.T) {
	store := &apiKeyStore{db: newTestDB(t, filepath.Join(t.TempDir(), "ak.db"))}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	createdAt, err := store.Insert(context.Background(),
		"abcdefabcdef", "fakehash", "test-key", "alice",
		[]string{"metrics"}, &exp)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if createdAt.IsZero() {
		t.Errorf("Insert returned zero time")
	}

	row, err := store.LookupActive(context.Background(), "abcdefabcdef")
	if err != nil {
		t.Fatalf("LookupActive: %v", err)
	}
	if row.KeyID != "abcdefabcdef" {
		t.Errorf("KeyID = %q, want abcdefabcdef", row.KeyID)
	}
	if row.SecretHash != "fakehash" {
		t.Errorf("SecretHash = %q", row.SecretHash)
	}
	if row.Name != "test-key" {
		t.Errorf("Name = %q", row.Name)
	}
	if row.Creator != "alice" {
		t.Errorf("Creator = %q", row.Creator)
	}
	if len(row.Scopes) != 1 || row.Scopes[0] != "metrics" {
		t.Errorf("Scopes = %v, want [metrics]", row.Scopes)
	}
	if row.ExpiresAt == nil || !row.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", row.ExpiresAt, exp)
	}
	if row.DeletedAt != nil {
		t.Errorf("DeletedAt = %v, want nil for fresh row", row.DeletedAt)
	}
}

// TestAPIKeyStoreLookupExpired confirms an expired key is treated as
// not-found — the auth path uses errors.Is(err, errAPIKeyNotFound)
// and must NOT differentiate "expired" from "doesn't exist". A
// chatty error here would help an attacker enumerate revoked ids.
func TestAPIKeyStoreLookupExpired(t *testing.T) {
	store := &apiKeyStore{db: newTestDB(t, filepath.Join(t.TempDir(), "ak.db"))}
	past := time.Now().Add(-time.Hour).UTC()
	if _, err := store.Insert(context.Background(),
		"deadbeefdead", "h", "n", "alice", []string{"metrics"}, &past); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	_, err := store.LookupActive(context.Background(), "deadbeefdead")
	if !errors.Is(err, errAPIKeyNotFound) {
		t.Errorf("LookupActive on expired key: err=%v, want errAPIKeyNotFound", err)
	}
}

// TestAPIKeyStoreSoftDelete confirms a soft-deleted key:
//   - returns errAPIKeyNotFound from LookupActive
//   - still appears in ListByCreator with deleted_at populated
//   - cannot be soft-deleted twice (idempotency error)
func TestAPIKeyStoreSoftDelete(t *testing.T) {
	store := &apiKeyStore{db: newTestDB(t, filepath.Join(t.TempDir(), "ak.db"))}
	if _, err := store.Insert(context.Background(),
		"aaabbbcccddd", "h", "n", "alice", []string{"metrics"}, nil); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if err := store.SoftDelete(context.Background(), "aaabbbcccddd", "alice"); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if _, err := store.LookupActive(context.Background(), "aaabbbcccddd"); !errors.Is(err, errAPIKeyNotFound) {
		t.Errorf("LookupActive after soft-delete: err=%v, want errAPIKeyNotFound", err)
	}
	rows, err := store.ListByCreator(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ListByCreator: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ListByCreator: %d rows, want 1 (soft-deleted should still appear)", len(rows))
	}
	if rows[0].DeletedAt == nil {
		t.Errorf("ListByCreator: DeletedAt nil for soft-deleted row")
	}
	// Second delete is a 404 — the partial-update WHERE clause
	// excludes already-tombstoned rows.
	if err := store.SoftDelete(context.Background(), "aaabbbcccddd", "alice"); !errors.Is(err, errAPIKeyNotFound) {
		t.Errorf("Second SoftDelete: err=%v, want errAPIKeyNotFound", err)
	}
}

// TestAPIKeyStoreSoftDeleteCrossOwner pins the
// "admins-only-delete-their-own-keys" rule. alice can't delete
// bob's key, even if she knows the id. Returns errAPIKeyNotFound
// (not Forbidden) so admin-side enumeration of "is this id real?"
// against the delete endpoint is impossible.
func TestAPIKeyStoreSoftDeleteCrossOwner(t *testing.T) {
	store := &apiKeyStore{db: newTestDB(t, filepath.Join(t.TempDir(), "ak.db"))}
	if _, err := store.Insert(context.Background(),
		"bbbbbbbbbbbb", "h", "n", "bob", []string{"metrics"}, nil); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := store.SoftDelete(context.Background(), "bbbbbbbbbbbb", "alice"); !errors.Is(err, errAPIKeyNotFound) {
		t.Errorf("Cross-owner delete: err=%v, want errAPIKeyNotFound", err)
	}
	// Bob's row should still be active.
	if _, err := store.LookupActive(context.Background(), "bbbbbbbbbbbb"); err != nil {
		t.Errorf("Bob's key was tombstoned by Alice's delete attempt: %v", err)
	}
}
