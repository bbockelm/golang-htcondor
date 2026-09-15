package idmap

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

type fakeGroups struct {
	groups map[string][]string
	err    error
	calls  int
}

func (f *fakeGroups) Name() string { return "fake" }
func (f *fakeGroups) GroupsFor(_ context.Context, username string) ([]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return normalizeGroups(f.groups[username]), nil
}

func TestNormalizeGroupsSortsAndDeduplicates(t *testing.T) {
	got := normalizeGroups([]string{"osg", "condor", "osg", " staff ", "", "condor"})
	want := []string{"condor", "osg", "staff"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeGroups = %v, want %v", got, want)
	}
	if normalizeGroups(nil) != nil {
		t.Error("empty input should stay nil rather than becoming an empty slice")
	}
}

func TestCachedGroupsServesFromCacheWithinTTL(t *testing.T) {
	src := &fakeGroups{groups: map[string][]string{"tannenba": {"osg", "condor"}}}
	now := time.Unix(1_700_000_000, 0)
	c := NewCachedGroups(src, time.Minute)
	c.now = func() time.Time { return now }

	for i := 0; i < 4; i++ {
		got, err := c.GroupsFor(context.Background(), "tannenba")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, []string{"condor", "osg"}) {
			t.Fatalf("got %v", got)
		}
	}
	if src.calls != 1 {
		t.Errorf("hit the source %d times inside the TTL, want 1", src.calls)
	}

	now = now.Add(2 * time.Minute)
	if _, err := c.GroupsFor(context.Background(), "tannenba"); err != nil {
		t.Fatal(err)
	}
	if src.calls != 2 {
		t.Errorf("did not refresh after the TTL: %d calls", src.calls)
	}
}

// A returned slice must not alias the cache: a caller that sorts or
// appends to its answer would otherwise corrupt everyone else's.
func TestCachedGroupsReturnsACopy(t *testing.T) {
	src := &fakeGroups{groups: map[string][]string{"tannenba": {"osg", "condor"}}}
	c := NewCachedGroups(src, time.Minute)

	first, err := c.GroupsFor(context.Background(), "tannenba")
	if err != nil {
		t.Fatal(err)
	}
	first[0] = "wheel"

	second, err := c.GroupsFor(context.Background(), "tannenba")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, []string{"condor", "osg"}) {
		t.Errorf("cache was mutated through a returned slice: %v", second)
	}
}

// A failed lookup is not an answer. Caching it would turn a blip in the
// directory into minutes of "you are in no groups", which reads as a
// permissions decision rather than an outage.
func TestCachedGroupsDoesNotCacheFailures(t *testing.T) {
	src := &fakeGroups{err: errors.New("sssd timeout")}
	c := NewCachedGroups(src, time.Minute)

	for i := 0; i < 3; i++ {
		if _, err := c.GroupsFor(context.Background(), "tannenba"); err == nil {
			t.Fatal("expected the error to surface")
		}
	}
	if src.calls != 3 {
		t.Errorf("source called %d times; a failure must not be cached", src.calls)
	}

	src.err = nil
	src.groups = map[string][]string{"tannenba": {"osg"}}
	got, err := c.GroupsFor(context.Background(), "tannenba")
	if err != nil || !reflect.DeepEqual(got, []string{"osg"}) {
		t.Errorf("recovery after the outage failed: %v %v", got, err)
	}
}

func TestForgetDropsTheEntry(t *testing.T) {
	src := &fakeGroups{groups: map[string][]string{"tannenba": {"osg"}}}
	c := NewCachedGroups(src, time.Hour)

	if _, err := c.GroupsFor(context.Background(), "tannenba"); err != nil {
		t.Fatal(err)
	}
	c.Forget("tannenba")
	if _, err := c.GroupsFor(context.Background(), "tannenba"); err != nil {
		t.Fatal(err)
	}
	if src.calls != 2 {
		t.Errorf("Forget did not invalidate: %d calls", src.calls)
	}
}

func TestGroupsForRejectsAnEmptyUsername(t *testing.T) {
	if _, err := (&IDCommand{}).GroupsFor(context.Background(), ""); err == nil {
		t.Error("an empty username must not be handed to id(1)")
	}
}

// Exercises the real id(1) against this machine's own account, which is
// the only account a test can be sure exists.
func TestIDCommandAgainstThisAccount(t *testing.T) {
	if _, err := exec.LookPath("id"); err != nil {
		t.Skip("id(1) not available")
	}
	me, err := exec.CommandContext(t.Context(), "id", "-un").Output()
	if err != nil {
		t.Skipf("cannot determine the current user: %v", err)
	}
	username := string(bytes.TrimSpace(me))
	if username == "" {
		t.Skip("current user has no name")
	}

	groups, err := (&IDCommand{}).GroupsFor(context.Background(), username)
	if err != nil {
		t.Fatalf("GroupsFor(%q): %v", username, err)
	}
	if len(groups) == 0 {
		t.Errorf("%q resolved to no groups at all, which no real account has", username)
	}
	// Sorted and unique, per normalizeGroups.
	for i := 1; i < len(groups); i++ {
		if groups[i-1] >= groups[i] {
			t.Errorf("groups are not sorted and unique: %v", groups)
			break
		}
	}
	t.Logf("%s is in %d groups", username, len(groups))
}
