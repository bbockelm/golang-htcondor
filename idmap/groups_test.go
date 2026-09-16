package idmap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
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

func TestGroupChainTakesTheFirstRealAnswer(t *testing.T) {
	empty := &fakeGroups{groups: map[string][]string{}}
	broken := &fakeGroups{err: errors.New("sssd socket missing")}
	good := &fakeGroups{groups: map[string][]string{"tannenba": {"osg", "condor"}}}

	c := &GroupChain{Sources: []GroupSource{broken, empty, good}}
	got, err := c.GroupsFor(context.Background(), "tannenba")
	if err != nil {
		t.Fatalf("GroupsFor: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"condor", "osg"}) {
		t.Errorf("got %v, want [condor osg]", got)
	}
	if broken.calls != 1 || empty.calls != 1 || good.calls != 1 {
		t.Errorf("each source should be tried once: %d %d %d", broken.calls, empty.calls, good.calls)
	}
}

// An empty list is not an answer. Every account is in at least its
// primary group, so "no groups" means the source does not know the user
// -- and accepting it would silently narrow what that user may do.
func TestGroupChainTreatsEmptyAsNoAnswer(t *testing.T) {
	empty := &fakeGroups{groups: map[string][]string{}}
	c := &GroupChain{Sources: []GroupSource{empty}}

	if got, err := c.GroupsFor(context.Background(), "tannenba"); err == nil {
		t.Fatalf("an empty membership was returned as an answer: %v", got)
	}
}

func writeNSSwitch(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nsswitch.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The chain must be the machine's own declared order, not one this
// package prefers.
func TestNSSwitchGroupSourceFollowsTheDeclaredOrder(t *testing.T) {
	filesFirst := NSSwitchGroupSource(writeNSSwitch(t,
		"passwd: files sss\ngroup:  files sss\n")).Name()
	sssFirst := NSSwitchGroupSource(writeNSSwitch(t,
		"passwd: sss files\ngroup:  sss files\n")).Name()

	if runtime.GOOS == "linux" {
		if !strings.HasPrefix(filesFirst, "chain(files,sssd") {
			t.Errorf("files-first gave %q", filesFirst)
		}
		if !strings.HasPrefix(sssFirst, "chain(sssd,files") {
			t.Errorf("sss-first gave %q", sssFirst)
		}
	} else if !strings.Contains(filesFirst, "files") || strings.Contains(filesFirst, "sssd") {
		// SSSD's socket protocol is Linux-only; the rest of the order
		// still has to be respected.
		t.Errorf("off Linux, expected files without sssd: %q", filesFirst)
	}
}

// The group database is routinely configured differently from passwd.
// Reading the wrong line would consult the wrong sources.
func TestNSSwitchGroupSourceReadsTheGroupLineNotPasswd(t *testing.T) {
	path := writeNSSwitch(t, "passwd: sss\ngroup:  files\n")
	name := NSSwitchGroupSource(path).Name()

	if strings.Contains(name, "sssd") {
		t.Errorf("chain %q used the passwd line; group says files only", name)
	}
	if !strings.Contains(name, "files") {
		t.Errorf("chain %q does not consult files", name)
	}
}

// A method this package cannot speak must not be silently dropped: libc
// can speak it, so id(1) is appended and the whole line is honoured.
func TestNSSwitchGroupSourceDefersToLibcForUnknownMethods(t *testing.T) {
	for _, line := range []string{
		"group: files ldap\n",
		"group: winbind files\n",
		"group: nis\n",
	} {
		name := NSSwitchGroupSource(writeNSSwitch(t, line)).Name()
		if !strings.Contains(name, "id -Gn") {
			t.Errorf("for %q the chain was %q; expected id(1) so libc handles the unknown method",
				strings.TrimSpace(line), name)
		}
	}
}

// An unreadable nsswitch.conf is not a licence to guess.
func TestNSSwitchGroupSourceFallsBackToLibc(t *testing.T) {
	name := NSSwitchGroupSource(filepath.Join(t.TempDir(), "absent")).Name()
	if name != "chain(id -Gn)" {
		t.Errorf("chain = %q, want libc alone when the config cannot be read", name)
	}
}

// Actions like [NOTFOUND=return] are not sources and must not be counted
// as methods we cannot speak.
func TestNSSwitchGroupSourceIgnoresActions(t *testing.T) {
	name := NSSwitchGroupSource(writeNSSwitch(t,
		"group: files [NOTFOUND=return] sss\n")).Name()
	if strings.Contains(name, "id -Gn") {
		t.Errorf("chain %q treated an action as an unsupported method", name)
	}
}

// The files source must combine BOTH halves: /etc/group lists only
// supplementary members, so an account's primary group is knowable only
// from its passwd gid.
func TestGroupFilesIncludesThePrimaryGroup(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(passwd, []byte(
		"tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// tannenba's primary group (20013) names no members, as is normal.
	if err := os.WriteFile(group, []byte(
		"tannenba:x:20013:\nosg:x:5000:tannenba,someone\ncondor:x:5001:someone\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := (&GroupFiles{PasswdPath: passwd, GroupPath: group}).
		GroupsFor(context.Background(), "tannenba")
	if err != nil {
		t.Fatalf("GroupsFor: %v", err)
	}
	want := []string{"osg", "tannenba"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (primary group plus supplementary, not condor)", got, want)
	}
}

// An account with no group entry at all still has its primary gid, and
// reporting nothing would read as "no permissions".
func TestGroupFilesReportsABareGIDRatherThanNothing(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(passwd, []byte("orphan:x:20099:20099::/home/orphan:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, []byte("other:x:5000:someone\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := (&GroupFiles{PasswdPath: passwd, GroupPath: group}).
		GroupsFor(context.Background(), "orphan")
	if err != nil {
		t.Fatalf("GroupsFor: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"20099"}) {
		t.Errorf("got %v, want the bare gid rather than an empty list", got)
	}
}

func TestGroupFilesRejectsAnUnknownAccount(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	_ = os.WriteFile(passwd, []byte("someone:x:1:1::/:/bin/sh\n"), 0o600)
	_ = os.WriteFile(group, []byte("someone:x:1:\n"), 0o600)

	if got, err := (&GroupFiles{PasswdPath: passwd, GroupPath: group}).
		GroupsFor(context.Background(), "ghost"); err == nil {
		t.Errorf("an unknown account resolved to %v", got)
	}
}
