// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idmap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	r := New(&SystemAccounts{Path: path}, FileGecos{Path: path})

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

func TestParseStrategies(t *testing.T) {
	got, err := ParseStrategies(" GECOS , username ")
	if err != nil {
		t.Fatalf("ParseStrategies: %v", err)
	}
	if len(got) != 2 || got[0] != StrategyGecos || got[1] != StrategyUsername {
		t.Errorf("parsed %v, want [gecos username]", got)
	}
	// A typo here decides who may log in, so it must not be skipped.
	if _, err := ParseStrategies("gecos,uid"); err == nil {
		t.Error("an unknown strategy was accepted")
	}
	if _, err := ParseStrategies("  "); err == nil {
		t.Error("an empty strategy list was accepted")
	}
}

// The common shape at a site where most accounts carry their own name in
// GECOS: "gecos,username" resolves the ones that do by GECOS, and the
// ones whose GECOS is blank by login name.
func TestStrategyChainCoversBothShapes(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{
		{Username: "tannenba", Gecos: "tatannen", UID: 20013}, // differs
		{Username: "matyas", Gecos: "matyas", UID: 20020},     // same
		{Username: "blank", Gecos: "", UID: 20021},            // no GECOS
	}}
	ver := &fakeVerifier{gecos: map[string]string{
		"tannenba": "tatannen", "matyas": "matyas", "blank": "",
	}}
	r := New(enum, ver, WithStrategies(StrategyGecos, StrategyUsername))

	for subject, want := range map[string]string{
		"tatannen": "tannenba", // by GECOS
		"matyas":   "matyas",   // by GECOS, which happens to equal the name
		"blank":    "blank",    // by login name, GECOS being empty
	} {
		got, err := r.Resolve(context.Background(), subject)
		if err != nil {
			t.Errorf("Resolve(%q): %v", subject, err)
			continue
		}
		if got != want {
			t.Errorf("Resolve(%q) = %q, want %q", subject, got, want)
		}
	}

	// Still nobody: no GECOS and no such login.
	if _, err := r.Resolve(context.Background(), "ghost"); !errors.Is(err, ErrNoMatch) {
		t.Errorf("an unknown subject resolved: %v", err)
	}
}

// With gecos first, a subject that is one account's login name and
// another's GECOS resolves to the GECOS owner. That is the configured
// order doing its job -- and it is why ShadowedUsernames exists.
func TestGecosWinsOverALoginNameAndIsReported(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{
		{Username: "carol", Gecos: "", UID: 20030},
		{Username: "impersonator", Gecos: "carol", UID: 20031},
	}}
	ver := &fakeVerifier{gecos: map[string]string{"carol": "", "impersonator": "carol"}}
	r := New(enum, ver, WithStrategies(StrategyGecos, StrategyUsername))

	got, err := r.Resolve(context.Background(), "carol")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "impersonator" {
		t.Errorf("Resolve(carol) = %q; with gecos first the GECOS owner wins", got)
	}

	shadow := r.ShadowedUsernames()
	if len(shadow) != 1 || !strings.Contains(shadow[0], "carol") {
		t.Errorf("ShadowedUsernames() = %v, want carol reported", shadow)
	}

	// Reversed, the login name wins -- the operator's ordering decides.
	r2 := New(enum, ver, WithStrategies(StrategyUsername, StrategyGecos))
	if got, err := r2.Resolve(context.Background(), "carol"); err != nil || got != "carol" {
		t.Errorf("username-first resolved to %q (%v), want carol", got, err)
	}
}

// Ambiguity must stop the chain. A later strategy answering for a subject
// two accounts already claim would resolve exactly the case that most
// needs refusing.
func TestAmbiguityStopsTheChain(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{
		{Username: "dave", Gecos: "contested", UID: 20040},
		{Username: "erin", Gecos: "contested", UID: 20041},
		{Username: "contested", Gecos: "", UID: 20042},
	}}
	ver := &fakeVerifier{gecos: map[string]string{
		"dave": "contested", "erin": "contested", "contested": "",
	}}
	r := New(enum, ver, WithStrategies(StrategyGecos, StrategyUsername))

	if got, err := r.Resolve(context.Background(), "contested"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("Resolve = %q, %v; ambiguity must not fall through to the login name", got, err)
	}
}

// acceptAnything says every account exists, so the ONLY thing that can
// reject a malformed login name is the syntax filter itself.
//
// The previous version of this test used a verifier that knew one
// account, so every bad input failed with "no such user" whether the
// filter existed or not -- deleting the filter entirely left the test
// green.
type acceptAnything struct{ asked []string }

func (a *acceptAnything) GecosOf(_ context.Context, username string) (string, error) {
	a.asked = append(a.asked, username)
	return "whatever", nil
}

func TestUsernameStrategyRejectsNonNames(t *testing.T) {
	ver := &acceptAnything{}
	enum := &fakeEnum{accounts: []Account{{Username: "ok", Gecos: "", UID: 1}}}
	r := New(enum, ver, WithStrategies(StrategyUsername))

	for _, bad := range []string{"../etc/shadow", "a:b", "has space", "two\nlines", "tab\there"} {
		if got, err := r.Resolve(context.Background(), bad); err == nil {
			t.Errorf("accepted %q as a login name, resolving to %q", bad, got)
		}
	}
	// The filter must reject these BEFORE they reach a lookup, so a
	// malformed string never becomes an argv element.
	if len(ver.asked) != 0 {
		t.Errorf("malformed names reached the verifier: %v", ver.asked)
	}

	// A well-formed name still resolves, so the filter is not simply
	// rejecting everything.
	if got, err := r.Resolve(context.Background(), "ok"); err != nil || got != "ok" {
		t.Errorf("a valid login name was rejected: %q %v", got, err)
	}
}

// An empty subject must never resolve. build() skips accounts with a
// blank GECOS, but the username strategy has no such protection: without
// the guard an empty subject is handed straight to the verifier, and a
// verifier that answers for "" would hand back an account.
func TestEmptySubjectNeverReachesALookup(t *testing.T) {
	ver := &acceptAnything{}
	enum := &fakeEnum{accounts: []Account{{Username: "ok", Gecos: "", UID: 1}}}
	r := New(enum, ver, WithStrategies(StrategyUsername, StrategyGecos))

	for _, empty := range []string{"", "   ", "\t"} {
		if got, err := r.Resolve(context.Background(), empty); err == nil {
			t.Errorf("empty subject %q resolved to %q", empty, got)
		}
	}
	if len(ver.asked) != 0 {
		t.Errorf("an empty subject reached the verifier: %v", ver.asked)
	}
}

// Subject matching is case-SENSITIVE, at the index AND at the re-check,
// and the two must agree.
//
// The index is a plain map lookup, so it is exact by construction and a
// differently-cased subject never even reaches the verifier. The
// interesting case is the other side: an index hit whose LIVE GECOS now
// differs only in case. A case-insensitive re-check would accept that,
// making the verifier more permissive than the index it is supposed to
// be confirming -- so the pair is pinned here rather than just the half
// that is exact for free.
func TestSubjectMatchingIsCaseSensitive(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}}}

	// Index side: a differently-cased subject is not a hit.
	exact := New(enum, &fakeVerifier{gecos: map[string]string{"tannenba": "tatannen"}})
	if got, err := exact.Resolve(context.Background(), "tatannen"); err != nil || got != "tannenba" {
		t.Fatalf("exact match failed: %q %v", got, err)
	}
	for _, variant := range []string{"TATANNEN", "Tatannen", "tATANNEN"} {
		if got, err := exact.Resolve(context.Background(), variant); err == nil {
			t.Errorf("%q matched an account whose GECOS is %q, resolving to %q", variant, "tatannen", got)
		}
	}

	// Re-check side: the index still says "tatannen", but the account's
	// GECOS now differs in case. That is a different string, so it is a
	// different identity, and the hit must be refused.
	drifted := New(enum, &fakeVerifier{gecos: map[string]string{"tannenba": "TATANNEN"}})
	if got, err := drifted.Resolve(context.Background(), "tatannen"); err == nil {
		t.Errorf("the re-check accepted GECOS %q for subject %q, resolving to %q; "+
			"it must compare exactly, like the index does", "TATANNEN", "tatannen", got)
	}
}

// slowEnum counts concurrent enumerations, so a stampede is observable
// rather than merely suspected.
type slowEnum struct {
	mu       sync.Mutex
	calls    int
	inFlight int
	maxSeen  int
	accounts []Account
	delay    time.Duration
	// errDuring records ctx.Err() observed WHILE enumerating. Checking
	// the context after the call is meaningless: build() cancels its own
	// derived context on return, which is cleanup, not interference.
	errDuring []error
}

func (e *slowEnum) Name() string { return "slow" }
func (e *slowEnum) Enumerate(ctx context.Context) ([]Account, error) {
	e.mu.Lock()
	e.calls++
	e.inFlight++
	if e.inFlight > e.maxSeen {
		e.maxSeen = e.inFlight
	}
	e.mu.Unlock()

	time.Sleep(e.delay)

	e.mu.Lock()
	e.inFlight--
	e.errDuring = append(e.errDuring, ctx.Err())
	e.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return e.accounts, nil
}

// N logins arriving at TTL expiry must cause ONE enumeration, not N. The
// account database is read in full each time; on a 1500-account host
// that is 1500 records per concurrent request.
func TestConcurrentResolvesRebuildOnce(t *testing.T) {
	enum := &slowEnum{
		accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}},
		delay:    50 * time.Millisecond,
	}
	r := New(enum, nil, WithTTL(time.Hour))

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Resolve(context.Background(), "tatannen"); err != nil {
				t.Errorf("Resolve: %v", err)
			}
		}()
	}
	wg.Wait()

	enum.mu.Lock()
	calls, maxConcurrent := enum.calls, enum.maxSeen
	enum.mu.Unlock()
	if calls != 1 {
		t.Errorf("enumerated %d times for 25 concurrent logins, want 1", calls)
	}
	if maxConcurrent > 1 {
		t.Errorf("%d enumerations ran at once; rebuilds must be serialised", maxConcurrent)
	}
}

// The index is process-wide; the context that happens to trigger a
// rebuild belongs to one request. A client that disconnects mid-rebuild
// must not cancel the shared enumeration -- that is how a truncated
// account list used to get installed and served for the whole TTL.
func TestRebuildSurvivesTheTriggeringRequestBeingCancelled(t *testing.T) {
	enum := &slowEnum{
		accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}},
		delay:    80 * time.Millisecond,
	}
	r := New(enum, nil, WithTTL(time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.Resolve(ctx, "tatannen") // may fail; the caller gave up
	}()
	time.Sleep(20 * time.Millisecond)
	cancel() // the login is abandoned mid-enumeration
	<-done

	// While it was running, the enumeration's context must have been
	// unaffected by the caller giving up.
	enum.mu.Lock()
	during := append([]error(nil), enum.errDuring...)
	enum.mu.Unlock()
	if len(during) == 0 {
		t.Fatal("no enumeration was attempted")
	}
	for i, err := range during {
		if err != nil {
			t.Errorf("enumeration %d was cancelled mid-flight by the abandoned request (%v); "+
				"a partial account list could be installed this way", i, err)
		}
	}

	// And a later login sees a complete index.
	if got, err := r.Resolve(context.Background(), "tatannen"); err != nil || got != "tannenba" {
		t.Errorf("after the abandoned login: got %q, %v; want tannenba", got, err)
	}
}

// flakyEnum answers, then starts failing.
type flakyEnum struct {
	accounts []Account
	failing  bool
	calls    int
}

func (f *flakyEnum) Name() string { return "flaky" }
func (f *flakyEnum) Enumerate(context.Context) ([]Account, error) {
	f.calls++
	if f.failing {
		return nil, errors.New("directory unreachable")
	}
	return f.accounts, nil
}

// The index is refreshed on a TTL, so a process running for weeks keeps
// up with the account database. When a refresh FAILS, the index we
// already hold is still used -- which is safe here specifically because
// every hit is confirmed against the live database before it is
// returned, so staleness delays new accounts rather than producing wrong
// ones.
func TestAFailedRefreshKeepsServingTheVerifiedIndex(t *testing.T) {
	enum := &flakyEnum{accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}}}
	ver := &fakeVerifier{gecos: map[string]string{"tannenba": "tatannen"}}
	now := time.Unix(1_700_000_000, 0)
	r := New(enum, ver, WithTTL(time.Minute), WithClock(func() time.Time { return now }))

	if got, err := r.Resolve(context.Background(), "tatannen"); err != nil || got != "tannenba" {
		t.Fatalf("first resolve: %q %v", got, err)
	}

	// The directory goes away, and the TTL expires.
	enum.failing = true
	now = now.Add(2 * time.Minute)

	got, err := r.Resolve(context.Background(), "tatannen")
	if err != nil {
		t.Fatalf("a transient enumeration failure denied a login that the existing index could answer: %v", err)
	}
	if got != "tannenba" {
		t.Errorf("got %q, want tannenba from the retained index", got)
	}
	if enum.calls < 2 {
		t.Error("no refresh was attempted")
	}

	// It is not papered over forever: past the staleness bound, resolution
	// fails rather than answering from an index nobody can refresh.
	now = now.Add(20 * time.Minute)
	if got, err := r.Resolve(context.Background(), "tatannen"); err == nil {
		t.Errorf("resolved %q from an index stale beyond the bound", got)
	}

	// And when the directory returns, so does normal service.
	enum.failing = false
	if got, err := r.Resolve(context.Background(), "tatannen"); err != nil || got != "tannenba" {
		t.Errorf("after recovery: %q %v", got, err)
	}
}

// A stale index must still not return an account whose GECOS has since
// changed -- that is the property that makes serving stale safe at all.
func TestAStaleIndexStillCannotPromoteAChangedAccount(t *testing.T) {
	enum := &flakyEnum{accounts: []Account{{Username: "tannenba", Gecos: "tatannen", UID: 20013}}}
	ver := &fakeVerifier{gecos: map[string]string{"tannenba": "tatannen"}}
	now := time.Unix(1_700_000_000, 0)
	r := New(enum, ver, WithTTL(time.Minute), WithClock(func() time.Time { return now }))

	if _, err := r.Resolve(context.Background(), "tatannen"); err != nil {
		t.Fatal(err)
	}

	// Refreshes fail, AND the account is re-pointed at somebody else.
	enum.failing = true
	ver.gecos["tannenba"] = "someone.else"
	now = now.Add(2 * time.Minute)

	if got, err := r.Resolve(context.Background(), "tatannen"); err == nil {
		t.Errorf("the stale index promoted %q whose GECOS is now %q", got, "someone.else")
	}
}
