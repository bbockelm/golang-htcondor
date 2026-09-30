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

package sshgateway

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeClock is a clock the test moves by hand, because every rule here
// is about elapsed time and none of it should be waited for.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func addr(t *testing.T, s string) net.Addr {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return net.TCPAddrFromAddrPort(ap)
}

func testBanlist(clock *fakeClock) *Banlist {
	return NewBanlist(BanlistOptions{
		HostThreshold: 4,
		NetThreshold:  10,
		Window:        10 * time.Minute,
		BanTime:       15 * time.Minute,
		MaxBanTime:    2 * time.Hour,
		MaxTracked:    64,
		Now:           clock.Now,
	})
}

func mustAllow(t *testing.T, b *Banlist, a net.Addr) {
	t.Helper()
	if ok, until := b.Allow(a); !ok {
		t.Fatalf("%s should still be allowed, locked out until %s", a, until)
	}
}

func mustRefuse(t *testing.T, b *Banlist, a net.Addr) time.Time {
	t.Helper()
	ok, until := b.Allow(a)
	if ok {
		t.Fatalf("%s should be locked out", a)
	}
	return until
}

func TestLockoutOnlyAfterTheThresholdIsReached(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")

	for i := 0; i < 3; i++ {
		b.Fail(client, WeightAbandoned, "test")
		mustAllow(t, b, client)
	}
	b.Fail(client, WeightAbandoned, "test")
	until := mustRefuse(t, b, client)

	if want := clock.Now().Add(15 * time.Minute); !until.Equal(want) {
		t.Fatalf("lockout until %s, want %s", until, want)
	}
}

func TestLockoutLiftsWhenItExpires(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")

	b.Fail(client, 4, "test")
	mustRefuse(t, b, client)

	clock.advance(15*time.Minute - time.Second)
	mustRefuse(t, b, client)

	clock.advance(2 * time.Second)
	mustAllow(t, b, client)
}

func TestEachLockoutLastsTwiceAsLong(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")

	want := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 2 * time.Hour}
	for i, d := range want {
		b.Fail(client, 4, "test")
		until := mustRefuse(t, b, client)
		if got := until.Sub(clock.Now()); got != d {
			t.Fatalf("lockout %d lasted %s, want %s", i+1, got, d)
		}
		clock.advance(d + time.Second)
		mustAllow(t, b, client)
	}
}

func TestKnockingWhileLockedOutDoesNotExtendIt(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")

	b.Fail(client, 4, "test")
	first := mustRefuse(t, b, client)

	// A scanner that keeps trying must not ratchet its own sentence
	// up, or the exponential backoff stops meaning "came back after
	// serving it" and starts meaning "kept the socket open".
	for i := 0; i < 50; i++ {
		clock.advance(time.Second)
		b.Fail(client, 4, "test")
	}
	if until := mustRefuse(t, b, client); !until.Equal(first) {
		t.Fatalf("lockout moved to %s, want it unchanged at %s", until, first)
	}

	clock.advance(15 * time.Minute)
	mustAllow(t, b, client)
}

func TestScoreIsForgottenAfterTheWindow(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")

	for i := 0; i < 3; i++ {
		b.Fail(client, WeightAbandoned, "test")
	}
	clock.advance(11 * time.Minute)
	for i := 0; i < 3; i++ {
		b.Fail(client, WeightAbandoned, "test")
		mustAllow(t, b, client)
	}
}

func TestASprayAcrossOneNetworkIsLockedOut(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)

	// Ten addresses, each in its own /64, all inside one /48. Per host
	// none of them comes close to the threshold of four; this is the
	// evasion the network tier exists for.
	for i := 0; i < 10; i++ {
		b.Fail(addr(t, fmt.Sprintf("[2001:db8:1:%x::1]:4000", i)), WeightAbandoned, "test")
	}

	fresh := addr(t, "[2001:db8:1:ffff::9]:4000")
	if ok, _ := b.Allow(fresh); ok {
		t.Fatal("an unused address in the sprayed /48 should be locked out with it")
	}
	// A different /48 is untouched.
	mustAllow(t, b, addr(t, "[2001:db8:2::1]:4000"))
}

func TestOneBadHostDoesNotLockOutItsNeighbours(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)

	bad := addr(t, "192.0.2.10:4000")
	// Well past the /24's own budget of ten. Once the host is locked
	// out its failures stop counting anywhere, or one noisy machine
	// on a campus would lock out the campus.
	for i := 0; i < 100; i++ {
		clock.advance(time.Second)
		b.Fail(bad, WeightAbandoned, "test")
	}
	mustRefuse(t, b, bad)
	mustAllow(t, b, addr(t, "192.0.2.11:4000"))
}

func TestSuccessClearsWhatAHostAccumulated(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")

	for i := 0; i < 3; i++ {
		b.Fail(client, WeightAbandoned, "test")
	}
	b.Succeed(client)
	for i := 0; i < 3; i++ {
		b.Fail(client, WeightAbandoned, "test")
		mustAllow(t, b, client)
	}
}

func TestSuccessDoesNotLaunderANetworkSpray(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)

	// Nine failures across the /48, then a success, then one more.
	// Crediting the network a whole host's worth for one login would
	// let a compromised machine log in between sprays forever.
	for i := 0; i < 9; i++ {
		b.Fail(addr(t, fmt.Sprintf("[2001:db8:1:%x::1]:4000", i)), WeightAbandoned, "test")
	}
	b.Succeed(addr(t, "[2001:db8:1:aa::1]:4000"))
	b.Fail(addr(t, "[2001:db8:1:bb::1]:4000"), WeightAbandoned, "test")
	b.Fail(addr(t, "[2001:db8:1:cc::1]:4000"), WeightAbandoned, "test")

	if ok, _ := b.Allow(addr(t, "[2001:db8:1:dd::1]:4000")); ok {
		t.Fatal("the /48 should be locked out; one success credits one point, not the whole score")
	}
}

func TestTrustedSourcesAreNeverLockedOut(t *testing.T) {
	clock := newClock()
	trusted, err := ParseTrustedNetworks([]string{"192.0.2.0/24", "198.51.100.7"})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	b := NewBanlist(BanlistOptions{
		HostThreshold: 2, NetThreshold: 4, Window: time.Minute,
		BanTime: time.Minute, MaxTracked: 16, Trusted: trusted, Now: clock.Now,
	})

	for _, s := range []string{"192.0.2.10:1", "198.51.100.7:1"} {
		a := addr(t, s)
		for i := 0; i < 20; i++ {
			b.Ban(a, "test")
		}
		mustAllow(t, b, a)
	}

	// The host next door to the single trusted address is not trusted.
	other := addr(t, "198.51.100.8:1")
	b.Ban(other, "test")
	mustRefuse(t, b, other)
}

func TestTheTableIsBoundedAndKeepsLiveLockouts(t *testing.T) {
	clock := newClock()
	b := NewBanlist(BanlistOptions{
		HostThreshold: 1, NetThreshold: 1000000, Window: time.Minute,
		BanTime: time.Hour, MaxTracked: 8, Now: clock.Now,
	})

	// Lock out eight hosts, filling the table with live lockouts.
	banned := make([]net.Addr, 0, 8)
	for i := 0; i < 8; i++ {
		a := addr(t, fmt.Sprintf("192.0.2.%d:1", i))
		b.Fail(a, 1, "test")
		mustRefuse(t, b, a)
		banned = append(banned, a)
	}

	// Now a flood of new sources. The table must not grow, and must
	// not release anybody to make room -- evicting a live lockout is
	// indistinguishable from lifting it.
	for i := 0; i < 500; i++ {
		b.Fail(addr(t, fmt.Sprintf("203.0.113.%d:1", i%256)), 1, "test")
	}

	if got := b.Stats().TrackedHosts; got > 8 {
		t.Fatalf("tracking %d hosts, bound is 8", got)
	}
	for _, a := range banned {
		mustRefuse(t, b, a)
	}
	if b.Stats().FailuresUntracked == 0 {
		t.Fatal("a failure that could not be tracked should be counted as such")
	}
}

func TestAnIdleEntryIsEvictedBeforeALiveOne(t *testing.T) {
	clock := newClock()
	b := NewBanlist(BanlistOptions{
		HostThreshold: 10, NetThreshold: 1000000, Window: time.Minute,
		BanTime: time.Hour, MaxTracked: 4, Now: clock.Now,
	})
	for i := 0; i < 4; i++ {
		b.Fail(addr(t, fmt.Sprintf("192.0.2.%d:1", i)), 1, "test")
	}
	clock.advance(2 * time.Minute)

	// Everything tracked is now stale; a new source gets a slot and
	// the table stays at its bound.
	b.Fail(addr(t, "203.0.113.1:1"), 1, "test")
	if got := b.Stats().TrackedHosts; got > 4 {
		t.Fatalf("tracking %d hosts, bound is 4", got)
	}
	if b.Stats().FailuresUntracked != 0 {
		t.Fatal("there was room once the stale entries were swept; nothing should have gone untracked")
	}
}

func TestNilBanlistPermitsEverything(t *testing.T) {
	var b *Banlist
	a := addr(t, "192.0.2.10:1")
	b.Fail(a, 100, "test")
	b.Ban(a, "test")
	b.Succeed(a)
	if ok, _ := b.Allow(a); !ok {
		t.Fatal("a nil Banlist must permit everything")
	}
	if b.AuthLogCallback() != nil {
		t.Fatal("a nil Banlist must not install an ssh hook")
	}
	if (b.Stats() != BanlistStats{}) {
		t.Fatal("a nil Banlist has no statistics")
	}
}

// fakeConnMetadata is the little of ssh.ConnMetadata the callback reads.
type fakeConnMetadata struct {
	ssh.ConnMetadata
	user   string
	remote net.Addr
}

func (f fakeConnMetadata) User() string         { return f.user }
func (f fakeConnMetadata) RemoteAddr() net.Addr { return f.remote }

func TestAuthLogWeighsMethodsDifferently(t *testing.T) {
	refused := errors.New("refused")
	cases := []struct {
		name      string
		method    string
		attempts  int
		lockedOut bool
	}{
		// "none" is how every client asks what the server offers.
		{"none is never counted", "none", 50, false},
		// An agent offers every key it holds before the certificate.
		{"publickey is never counted", "publickey", 50, false},
		// A person who walks away from the browser. Four is the
		// threshold here; three must not lock them out.
		{"three abandoned logins are tolerated", "keyboard-interactive", 3, false},
		{"four abandoned logins are not", "keyboard-interactive", 4, true},
		// Nothing legitimate asks for a method the server never
		// advertised.
		{"password is locked out at once", "password", 1, true},
		{"gssapi is locked out at once", "gssapi-with-mic", 1, true},
		{"a made-up method is locked out at once", "banana", 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newClock()
			b := testBanlist(clock)
			client := addr(t, "192.0.2.10:4000")
			log := b.AuthLogCallback()

			for i := 0; i < tc.attempts; i++ {
				// An ordinary username, so this measures the method
				// and nothing else; the scanner-name rule has its
				// own test.
				log(fakeConnMetadata{user: "bbockelm", remote: client}, tc.method, refused)
			}
			ok, _ := b.Allow(client)
			if ok == tc.lockedOut {
				t.Fatalf("after %d %q failures: allowed=%v, want allowed=%v",
					tc.attempts, tc.method, ok, !tc.lockedOut)
			}
		})
	}
}

func TestAuthLogTreatsSuccessAsAClearance(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")
	log := b.AuthLogCallback()

	for i := 0; i < 3; i++ {
		log(fakeConnMetadata{remote: client}, "keyboard-interactive", errors.New("refused"))
	}
	log(fakeConnMetadata{remote: client}, "keyboard-interactive", nil)
	for i := 0; i < 3; i++ {
		log(fakeConnMetadata{remote: client}, "keyboard-interactive", errors.New("refused"))
		mustAllow(t, b, client)
	}
}

func TestBanKeysGranularity(t *testing.T) {
	cases := []struct {
		in            string
		host, network string
	}{
		{"192.0.2.10:1", "192.0.2.10/32", "192.0.2.0/24"},
		{"[2001:db8:1:2:3:4:5:6]:1", "2001:db8:1:2::/64", "2001:db8:1::/48"},
		// An IPv4 address in v6 form is IPv4, or a client connecting
		// over a dual-stack socket would be counted separately from
		// itself.
		{"[::ffff:192.0.2.10]:1", "192.0.2.10/32", "192.0.2.0/24"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			h, n, ok := banKeys(addr(t, tc.in))
			if !ok {
				t.Fatalf("%s produced no keys", tc.in)
			}
			if h.String() != tc.host || n.String() != tc.network {
				t.Fatalf("keys for %s are %s and %s, want %s and %s", tc.in, h, n, tc.host, tc.network)
			}
		})
	}
}

func TestParseTrustedNetworks(t *testing.T) {
	got, err := ParseTrustedNetworks([]string{"10.0.0.0/8", "192.0.2.1", "2001:db8::/32", ""})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.1/32", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("parsed %v, want %v", got, want)
		}
	}
	if _, err := ParseTrustedNetworks([]string{"not-an-address"}); err == nil {
		t.Fatal("a bad entry should be an error, not a silently empty list")
	}
}

func TestStatsReportWhatAnOperatorNeeds(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")

	b.Fail(client, 4, "test")
	b.Allow(client)
	b.Allow(client)

	s := b.Stats()
	if s.BansIssued != 1 {
		t.Fatalf("issued %d lockouts, want 1", s.BansIssued)
	}
	if s.ActiveHostBans != 1 {
		t.Fatalf("%d active host lockouts, want 1", s.ActiveHostBans)
	}
	if s.ConnectionsRefused != 2 {
		t.Fatalf("%d refused connections, want 2", s.ConnectionsRefused)
	}
}

// A refusal that is the gateway's own doing must not count. An issuer
// outage or a busy afternoon would otherwise lock out every user who
// tried to get in during it -- turning a degraded service into an
// unreachable one, which is the failure mode this whole mechanism is
// supposed to prevent someone else from causing.
func TestTheGatewaysOwnRefusalsAreNotCounted(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")
	log := b.AuthLogCallback()

	busy := fmt.Errorf("sshgateway: too many concurrent logins: %w", ErrServerSide)
	for i := 0; i < 50; i++ {
		log(fakeConnMetadata{remote: client}, "keyboard-interactive", busy)
	}
	mustAllow(t, b, client)

	// And a wrapped one, since that is how the real ones arrive.
	outage := fmt.Errorf("starting the device authorization: %w: %w", ErrServerSide, errors.New("connection refused"))
	for i := 0; i < 50; i++ {
		log(fakeConnMetadata{remote: client}, "keyboard-interactive", outage)
	}
	mustAllow(t, b, client)
}

// A username no user would type on purpose makes a FAILED login count
// for more -- and does nothing on its own.
//
// It cannot do anything on its own here, because an unprefixed
// username means "my default session": `ssh root@gateway` is what a
// real person gets from a container, and they finish the login.
func TestAScannersUsernameMakesAFailureCountForMore(t *testing.T) {
	refused := errors.New("refused")
	cases := []struct {
		user      string
		attempts  int
		lockedOut bool
	}{
		// Threshold is four. An ordinary name is worth one a time.
		{"bbockelm", 3, false},
		{"bbockelm", 4, true},
		// A scanner's name is worth its own weight on top, which
		// reaches the threshold on the first try.
		{"root", 1, true},
		{"Ubuntu", 1, true},
		{"ec2-user", 1, true},
		// A job id is a perfectly ordinary thing to ask for.
		{"12345.0", 3, false},
		// And so is a session somebody deliberately named "root".
		{"+root", 3, false},
	}
	for _, tc := range cases {
		t.Run(tc.user, func(t *testing.T) {
			clock := newClock()
			b := testBanlist(clock)
			client := addr(t, "192.0.2.10:4000")
			log := b.AuthLogCallback()
			for i := 0; i < tc.attempts; i++ {
				log(fakeConnMetadata{user: tc.user, remote: client}, "keyboard-interactive", refused)
			}
			if ok, _ := b.Allow(client); ok == tc.lockedOut {
				t.Fatalf("%q after %d failures: allowed=%v", tc.user, tc.attempts, ok)
			}
		})
	}
}

// Succeeding as root is not a failure at all, so it costs nothing.
func TestConnectingAsRootAndSucceedingCostsNothing(t *testing.T) {
	clock := newClock()
	b := testBanlist(clock)
	client := addr(t, "192.0.2.10:4000")
	log := b.AuthLogCallback()

	for i := 0; i < 20; i++ {
		log(fakeConnMetadata{user: "root", remote: client}, "keyboard-interactive", nil)
	}
	mustAllow(t, b, client)
}
