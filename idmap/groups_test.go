package idmap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

// unknownGroups reports ErrUnknownUser, the way a source behaves for an
// account that lives in some other service.
type unknownGroups struct{ calls int }

func (u *unknownGroups) Name() string { return "unknown" }
func (u *unknownGroups) GroupsFor(context.Context, string) ([]string, error) {
	u.calls++
	return nil, fmt.Errorf("%w: not here", ErrUnknownUser)
}

// nsswitch's `group:` line is UNION semantics: a user on a "files sss"
// host is meant to end up with their local groups AND their directory
// groups. Taking the first source that answered silently dropped the
// rest, and `id` would then disagree with us about what the user may do.
func TestGroupChainMergesEverySource(t *testing.T) {
	local := &fakeGroups{groups: map[string][]string{"tannenba": {"staff", "shared"}}}
	directory := &fakeGroups{groups: map[string][]string{"tannenba": {"osg", "shared"}}}

	got, err := (&GroupChain{Sources: []GroupSource{local, directory}}).
		GroupsFor(context.Background(), "tannenba")
	if err != nil {
		t.Fatalf("GroupsFor: %v", err)
	}
	want := []string{"osg", "shared", "staff"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v -- the union of both sources, de-duplicated", got, want)
	}
	if local.calls != 1 || directory.calls != 1 {
		t.Errorf("both sources must be consulted: local=%d directory=%d", local.calls, directory.calls)
	}
}

// A source that has never heard of the account is the NORMAL case on a
// mixed host, not a failure.
func TestGroupChainSkipsSourcesThatDoNotKnowTheUser(t *testing.T) {
	unknown := &unknownGroups{}
	directory := &fakeGroups{groups: map[string][]string{"tannenba": {"osg"}}}

	got, err := (&GroupChain{Sources: []GroupSource{unknown, directory}}).
		GroupsFor(context.Background(), "tannenba")
	if err != nil {
		t.Fatalf("an unknown-to-one-source account must still resolve: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"osg"}) {
		t.Errorf("got %v, want [osg]", got)
	}
	if unknown.calls != 1 {
		t.Error("the unknown source should still have been asked")
	}

	// Unknown everywhere is ErrUnknownUser, so a caller can tell "no such
	// account" from "the directory is down".
	if _, err := (&GroupChain{Sources: []GroupSource{unknown, &unknownGroups{}}}).
		GroupsFor(context.Background(), "ghost"); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("want ErrUnknownUser when nobody knows the account, got %v", err)
	}
}

// An unavailable source does NOT fail the lookup -- glibc's default
// action for UNAVAIL is `continue`, so `id` on this host would return
// the same shortened list, and refusing would deny every login whenever
// a directory blinked while the rest of the machine carried on.
//
// But the result is MARKED, because a short list and a list that shrank
// because the user lost a group are identical in the list itself. Only
// the marker tells them apart, and one caller -- the refresh-time
// oracle, which revokes -- must be able to.
func TestGroupChainMarksADegradedAnswer(t *testing.T) {
	broken := &fakeGroups{err: errors.New("sssd socket timeout")}
	local := &fakeGroups{groups: map[string][]string{"tannenba": {"staff"}}}

	got, err := (&GroupChain{Sources: []GroupSource{local, broken}}).
		GroupsFor(context.Background(), "tannenba")

	if !reflect.DeepEqual(got, []string{"staff"}) {
		t.Errorf("got %v; the sources that DID answer must still be used, as id(1) would", got)
	}
	var degraded *DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("err = %v, want a *DegradedError so a caller can tell this is incomplete", err)
	}
	if degraded.Source != "fake" {
		t.Errorf("degraded.Source = %q, want the unavailable source named", degraded.Source)
	}
	if !reflect.DeepEqual(degraded.Groups, []string{"staff"}) {
		t.Errorf("degraded.Groups = %v, want the partial list carried with the error", degraded.Groups)
	}
	if errors.Is(err, ErrUnknownUser) {
		t.Error("an unavailable source must not read as an unknown account")
	}
}

// Nothing answered AND something was broken is an outage, not an unknown
// account -- and must never read as "this user belongs to nothing".
func TestGroupChainDistinguishesOutageFromUnknownAccount(t *testing.T) {
	broken := &fakeGroups{err: errors.New("sssd down")}
	unknown := &unknownGroups{}

	_, err := (&GroupChain{Sources: []GroupSource{unknown, broken}}).
		GroupsFor(context.Background(), "tannenba")
	if err == nil {
		t.Fatal("an outage produced no error")
	}
	if errors.Is(err, ErrUnknownUser) {
		t.Error("an outage was reported as an unknown account; the caller would deny rather than retry")
	}
	var degraded *DegradedError
	if !errors.As(err, &degraded) {
		t.Errorf("err = %v, want the outage identified as degraded", err)
	}

	// With no broken source, the same shape really is an unknown account.
	if _, err := (&GroupChain{Sources: []GroupSource{unknown}}).
		GroupsFor(context.Background(), "ghost"); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("err = %v, want ErrUnknownUser", err)
	}
}

// Every account is in at least its primary group, so an all-empty answer
// is a malformed read rather than a permissions decision.
func TestGroupChainRejectsAnAllEmptyAnswer(t *testing.T) {
	empty := &fakeGroups{groups: map[string][]string{"tannenba": {}}}

	if got, err := (&GroupChain{Sources: []GroupSource{empty}}).
		GroupsFor(context.Background(), "tannenba"); err == nil {
		t.Fatalf("an empty membership was accepted as an answer: %v", got)
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
//
// This is platform-independent by design: the SSSD reader is ordinary Go
// and is selected by what nsswitch.conf says, not by GOOS. A host
// without SSSD simply never names sss on its group line -- and a host
// without nsswitch.conf at all falls back to libc, which is covered
// separately.
func TestNSSwitchGroupSourceFollowsTheDeclaredOrder(t *testing.T) {
	filesFirst := NSSwitchGroupSource(writeNSSwitch(t,
		"passwd: files sss\ngroup:  files sss\n")).Name()
	sssFirst := NSSwitchGroupSource(writeNSSwitch(t,
		"passwd: sss files\ngroup:  sss files\n")).Name()

	if filesFirst != "chain(files,sssd)" {
		t.Errorf("files-first gave %q, want chain(files,sssd)", filesFirst)
	}
	if sssFirst != "chain(sssd,files)" {
		t.Errorf("sss-first gave %q, want chain(sssd,files)", sssFirst)
	}
	// The order is the only difference, and it is the whole point.
	if filesFirst == sssFirst {
		t.Error("the declared order made no difference to the chain")
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

// Membership in /etc/group is matched EXACTLY. Prefix matching survived
// the old fixture because its names were prefix-unrelated -- and would
// have given "bob" every group that lists "bobby".
func TestGroupFilesMatchesMembersExactly(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(passwd,
		[]byte("bob:x:20050:20050::/home/bob:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// "bobby" and "bobsleigh" both begin with "bob"; "bob" is a member of
	// neither.
	if err := os.WriteFile(group, []byte(
		"bob:x:20050:\nbobby-only:x:5000:bobby\nbobsleigh-team:x:5001:bobsleigh,alice\nshared:x:5002:bob,bobby\n"),
		0o600); err != nil {
		t.Fatal(err)
	}

	got, err := (&GroupFiles{PasswdPath: passwd, GroupPath: group}).
		GroupsFor(context.Background(), "bob")
	if err != nil {
		t.Fatalf("GroupsFor: %v", err)
	}
	want := []string{"bob", "shared"} // primary group, plus the one that really lists bob
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v -- a prefix of a member name is not membership", got, want)
	}
}
