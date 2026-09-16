package idmap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A real line from the access point this was written for. The account is
// "tannenba" and the token calls the same person "tatannen"; nothing
// derives either name from the other.
// second field is the conventional "x" placeholder meaning "see shadow(5)".
//
//nolint:gosec // G101: a passwd(5) line from a real host, not a credential -- the
const realPasswdLine = "tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/bash"

type fakeEnum struct {
	accounts []Account
	err      error
	calls    int
}

func (f *fakeEnum) Name() string { return "fake" }
func (f *fakeEnum) Enumerate(context.Context) ([]Account, error) {
	f.calls++
	return f.accounts, f.err
}

type fakeVerifier struct {
	gecos map[string]string
	err   error
}

func (v *fakeVerifier) GecosOf(_ context.Context, username string) (string, error) {
	if v.err != nil {
		return "", v.err
	}
	g, ok := v.gecos[username]
	if !ok {
		return "", fmt.Errorf("no such user %q", username)
	}
	return g, nil
}

func TestResolveMapsSubjectToTheAccountThatCarriesIt(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{
		{Username: "root", Gecos: "root", UID: 0},
		{Username: "tannenba", Gecos: "tatannen", UID: 20013},
		{Username: "bbockelm", Gecos: "brian.bockelman.1", UID: 20014},
	}}
	ver := &fakeVerifier{gecos: map[string]string{
		"root": "root", "tannenba": "tatannen", "bbockelm": "brian.bockelman.1",
	}}
	r := New(enum, ver)

	for subject, want := range map[string]string{
		"tatannen":          "tannenba",
		"brian.bockelman.1": "bbockelm",
	} {
		got, err := r.Resolve(context.Background(), subject)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", subject, err)
		}
		if got != want {
			t.Errorf("Resolve(%q) = %q, want %q", subject, got, want)
		}
	}
}

// The username is NOT a subject. Someone whose token says "tannenba"
// must not be handed the tannenba account just because the string looks
// like a login name -- the account's GECOS says its subject is
// "tatannen", and that is the only thing that maps.
func TestResolveDoesNotMatchOnUsername(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}}}
	r := New(enum, &fakeVerifier{gecos: map[string]string{"tannenba": "tatannen"}})

	if got, err := r.Resolve(context.Background(), "tannenba"); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("Resolve(%q) = %q, %v; want ErrNoMatch", "tannenba", got, err)
	}
}

// Two accounts with the same GECOS is a directory mistake or an attempt
// to become someone else. Either way, resolving to one of them picks a
// victim, so it resolves to neither.
func TestResolveRefusesADuplicatedGecos(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{
		{Username: "tannenba", Gecos: "tatannen", UID: 20013},
		{Username: "impostor", Gecos: "tatannen", UID: 20099},
	}}
	r := New(enum, &fakeVerifier{gecos: map[string]string{
		"tannenba": "tatannen", "impostor": "tatannen",
	}})

	got, err := r.Resolve(context.Background(), "tatannen")
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("Resolve = %q, %v; want ErrAmbiguous", got, err)
	}
	if got != "" {
		t.Errorf("returned %q alongside the error; must resolve to nobody", got)
	}
	if amb := r.AmbiguousGecos(); len(amb) != 1 || amb[0] != "tatannen" {
		t.Errorf("AmbiguousGecos() = %v, want [tatannen] so an operator can fix it", amb)
	}
}

// Most accounts on any system have no GECOS. They must not all collide
// with each other, nor answer a caller whose subject is empty.
func TestResolveIgnoresEmptyGecos(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{
		{Username: "daemon", Gecos: "", UID: 2},
		{Username: "bin", Gecos: "", UID: 1},
		{Username: "spaces", Gecos: "   ", UID: 3},
	}}
	r := New(enum, &fakeVerifier{})

	if _, err := r.Resolve(context.Background(), ""); !errors.Is(err, ErrNoMatch) {
		t.Errorf("an empty subject must not resolve: %v", err)
	}
	if _, err := r.Resolve(context.Background(), "   "); !errors.Is(err, ErrNoMatch) {
		t.Errorf("a whitespace subject must not resolve: %v", err)
	}
	if _, amb, _ := r.Stats(); amb != 0 {
		t.Errorf("empty GECOS values were counted as ambiguous (%d)", amb)
	}
}

// The index can be minutes old. The forward lookup is the direction the
// system actually supports, so it gets the last word.
func TestResolveRechecksTheIndexAgainstTheDirectory(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}}}
	// The account has since been re-pointed at somebody else.
	ver := &fakeVerifier{gecos: map[string]string{"tannenba": "someone.else"}}
	r := New(enum, ver)

	got, err := r.Resolve(context.Background(), "tatannen")
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("stale index was trusted: got %q, err %v", got, err)
	}
	if !strings.Contains(err.Error(), "someone.else") {
		t.Errorf("the error should name what the GECOS is now: %v", err)
	}
}

// A deleted account must read as absent, never as "GECOS cleared".
func TestResolveFailsWhenTheAccountIsGone(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}}}
	r := New(enum, &fakeVerifier{gecos: map[string]string{}})

	if got, err := r.Resolve(context.Background(), "tatannen"); err == nil {
		t.Fatalf("resolved %q against an account that no longer exists", got)
	}
}

func TestIndexIsRebuiltOnlyAfterTTL(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}}}
	now := time.Unix(1_700_000_000, 0)
	r := New(enum, nil, WithTTL(time.Minute), WithClock(func() time.Time { return now }))

	for i := 0; i < 5; i++ {
		if _, err := r.Resolve(context.Background(), "tatannen"); err != nil {
			t.Fatal(err)
		}
	}
	if enum.calls != 1 {
		t.Errorf("enumerated %d times within the TTL, want 1", enum.calls)
	}

	now = now.Add(2 * time.Minute)
	if _, err := r.Resolve(context.Background(), "tatannen"); err != nil {
		t.Fatal(err)
	}
	if enum.calls != 2 {
		t.Errorf("enumerated %d times after the TTL expired, want 2", enum.calls)
	}
}

// An enumeration that fails must not resolve anybody. Returning stale or
// empty results here would silently change who the caller is.
func TestResolveFailsClosedWhenEnumerationFails(t *testing.T) {
	enum := &fakeEnum{err: errors.New("sssd is down")}
	r := New(enum, nil)

	if _, err := r.Resolve(context.Background(), "tatannen"); err == nil {
		t.Fatal("resolved a subject while the account database was unreadable")
	}
}

func TestPasswdFileParsesTheRealLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	body := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"# a comment",
		"",
		realPasswdLine,
		"malformed-line-without-enough-fields",
		"nouid:x:notanumber:0:x:/:/bin/sh",
		"gecos:x:20015:20015:has:colons?no,but,commas:/home/g:/bin/sh",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	accounts, err := NewPasswdFile(path).Enumerate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Account{}
	for _, a := range accounts {
		byName[a.Username] = a
	}
	if len(accounts) != 3 {
		t.Errorf("parsed %d accounts (%v), want 3 with the bad lines skipped", len(accounts), byName)
	}
	// A non-numeric uid makes the line malformed, and it is dropped
	// rather than recorded with a defaulted uid -- a silent 0 there would
	// be root's.
	if _, ok := byName["nouid"]; ok {
		t.Error("kept an entry whose uid did not parse")
	}
	got := byName["tannenba"]
	if got.Gecos != "tatannen" || got.UID != 20013 {
		t.Errorf("parsed %+v, want GECOS tatannen uid 20013", got)
	}
	// Commas are part of the string, not a split point.
	if g := byName["gecos"].Gecos; g != "has" {
		t.Errorf("GECOS field = %q; passwd is colon-separated, so the field stops at the next colon", g)
	}
}

func TestChainPrefersTheEarlierSource(t *testing.T) {
	local := &fakeEnum{accounts: []Account{{Username: "tannenba", Gecos: "local-wins", UID: 20013}}}
	dir := &fakeEnum{accounts: []Account{
		{Username: "tannenba", Gecos: "tatannen", UID: 20013},
		{Username: "only-in-dir", Gecos: "dir-subject", UID: 30000},
	}}
	c := &Chain{Sources: []Enumerator{local, dir}}

	accounts, err := c.Enumerate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 {
		t.Fatalf("merged to %d accounts, want 2", len(accounts))
	}
	for _, a := range accounts {
		if a.Username == "tannenba" && a.Gecos != "local-wins" {
			t.Errorf("directory shadowed the local entry: %+v", a)
		}
	}
}

// One broken source must not blind the others.
func TestChainSurvivesAFailingSource(t *testing.T) {
	broken := &fakeEnum{err: errors.New("getent: not found")}
	local := &fakeEnum{accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}}}

	accounts, err := (&Chain{Sources: []Enumerator{broken, local}}).Enumerate(context.Background())
	if err != nil {
		t.Fatalf("a working source was discarded because another failed: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("got %d accounts, want the one the working source knew", len(accounts))
	}

	// But if EVERY source fails, that is an error, not an empty database.
	if _, err := (&Chain{Sources: []Enumerator{broken}}).Enumerate(context.Background()); err == nil {
		t.Error("an all-failed chain reported an empty account list instead of an error")
	}
}

// An end-to-end pass over a passwd file: index it, resolve a subject,
// and confirm the answer against the same file.
func TestResolverOverAPasswdFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	body := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1::/usr/sbin:/usr/sbin/nologin",
		realPasswdLine,
		"bbockelm:x:20014:20014:brian.bockelman.1:/home/bbockelm:/bin/bash",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	pf := NewPasswdFile(path)
	r := New(pf, &PasswdFileVerifier{File: pf})

	got, err := r.Resolve(context.Background(), "tatannen")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "tannenba" {
		t.Errorf("Resolve(tatannen) = %q, want tannenba", got)
	}

	if _, err := r.Resolve(context.Background(), "nobody.at.all"); !errors.Is(err, ErrNoMatch) {
		t.Errorf("an unknown subject must not resolve: %v", err)
	}

	accounts, amb, built := r.Stats()
	if accounts != 4 || amb != 0 || built.IsZero() {
		t.Errorf("Stats() = %d accounts, %d ambiguous, built %v", accounts, amb, built)
	}
}
