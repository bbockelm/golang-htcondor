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
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Banlist locks out a source that fails to authenticate too often, in
// the manner of fail2ban: count failures in a window, refuse new
// connections for a while once the count is high enough, and refuse
// for longer each time the same source comes back.
//
// It counts at two granularities because one is not enough. Per host
// alone is free to evade over IPv6, where a single allocation holds
// more addresses than there are seconds in the universe; per network
// alone would let one abusive host at a university lock out the
// campus. So a host has its own budget and the network it sits in has
// a larger shared one, and tripping either refuses the connection.
//
// A nil *Banlist is a working, disabled Banlist: every method is safe
// to call on it and permits everything. That is what makes the
// gateway's wiring unconditional.
type Banlist struct {
	opts BanlistOptions

	mu    sync.Mutex
	hosts map[netip.Prefix]*banEntry
	nets  map[netip.Prefix]*banEntry

	issued    uint64
	refused   uint64
	untracked uint64
}

// BanlistOptions configures a Banlist. The zero value is usable and
// every field has a default.
type BanlistOptions struct {
	// HostThreshold is the failure score one host may accumulate
	// within Window before it is locked out.
	//
	// Scored rather than counted because the failures are not alike: a
	// person who walks away from a browser prompt and a scanner asking
	// for password authentication both "failed", and only one of them
	// should be shown the door on the first try. See the Weight
	// constants.
	HostThreshold int

	// NetThreshold is the same budget for the surrounding network,
	// shared by every host in it. Zero means DefaultNetThresholdRatio
	// times HostThreshold.
	NetThreshold int

	// Window is how long failures are remembered. A source that stops
	// failing for this long starts over with a clean score.
	Window time.Duration

	// BanTime is how long the first lockout lasts. Each subsequent
	// lockout of the same source doubles it, up to MaxBanTime -- so a
	// fumbled login costs a coffee break and a scanner that keeps
	// coming back costs a day.
	BanTime    time.Duration
	MaxBanTime time.Duration

	// MaxTracked bounds each of the two tables.
	//
	// Required, not a nicety: the whole point of the network tier is
	// that an IPv6 attacker has an unlimited supply of distinct source
	// addresses, and an unbounded map keyed by them is a memory
	// exhaustion bug wearing a security feature's clothes.
	MaxTracked int

	// Trusted sources are never counted and never locked out. For the
	// monitoring host and the office, so an operator cannot lock
	// themselves out of the gateway by testing it.
	Trusted []netip.Prefix

	Logger *logging.Logger

	// Now is the clock, for tests.
	Now func() time.Time
}

// Defaults applied to a zero BanlistOptions.
const (
	DefaultBanHostThreshold = 10
	DefaultBanWindow        = 10 * time.Minute
	DefaultBanTime          = 15 * time.Minute
	DefaultMaxBanTime       = 24 * time.Hour
	DefaultMaxTrackedBan    = 4096

	// DefaultNetThresholdRatio makes a network's budget this many
	// times a host's. Large enough that a site's ordinary share of
	// fumbled logins never reaches it, small enough that a spray
	// across a handful of addresses does.
	DefaultNetThresholdRatio = 4
)

// Failure weights. Fail takes one of these.
const (
	// WeightAbandoned is a login that began and did not finish: the
	// code expired, the browser said no, or the person closed the tab.
	//
	// Deliberately the lightest thing there is. It is what a real user
	// does when they are interrupted, and it is also the least useful
	// thing an attacker can do -- they cannot approve the grant, so
	// repeating it gains them nothing but noise.
	WeightAbandoned = 1

	// WeightUnlikelyUser is added to a failed login that asked for a
	// username no user of this gateway would type on purpose: root,
	// admin, ubuntu and the rest of what a scanner works through.
	//
	// Additive rather than an immediate lockout, because `ssh
	// root@gateway` is NOT by itself evidence of anything here. An
	// unprefixed username means "my default session", so that is
	// exactly what a real person gets when they connect from a
	// container or a machine they are root on -- and a real person
	// finishes the login. Only the failure counts, and this only
	// makes it count for more.
	WeightUnlikelyUser = 3

	// WeightForged is a certificate this deployment's CA did not sign,
	// or one whose signature does not check out.
	//
	// Heavy, because no client produces it by accident. An expired
	// certificate or one for the wrong principal is NOT this: those
	// are what a legitimate user hits the morning after, and they
	// score nothing.
	WeightForged = 5
)

type banEntry struct {
	score       int
	windowStart time.Time
	lastSeen    time.Time
	until       time.Time
	// strikes counts lockouts so far, which is what makes the next one
	// longer. Kept across the score resetting, since the score is
	// about recent behaviour and this is about history.
	strikes int
	why     string
}

// NewBanlist returns a Banlist with opts' defaults filled in.
func NewBanlist(opts BanlistOptions) *Banlist {
	if opts.HostThreshold <= 0 {
		opts.HostThreshold = DefaultBanHostThreshold
	}
	if opts.NetThreshold <= 0 {
		opts.NetThreshold = DefaultNetThresholdRatio * opts.HostThreshold
	}
	if opts.Window <= 0 {
		opts.Window = DefaultBanWindow
	}
	if opts.BanTime <= 0 {
		opts.BanTime = DefaultBanTime
	}
	if opts.MaxBanTime < opts.BanTime {
		opts.MaxBanTime = DefaultMaxBanTime
	}
	if opts.MaxBanTime < opts.BanTime {
		opts.MaxBanTime = opts.BanTime
	}
	if opts.MaxTracked <= 0 {
		opts.MaxTracked = DefaultMaxTrackedBan
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Banlist{
		opts:  opts,
		hosts: make(map[netip.Prefix]*banEntry),
		nets:  make(map[netip.Prefix]*banEntry),
	}
}

// Allow reports whether a new connection from addr may proceed, and
// when the lockout ends if it may not.
func (b *Banlist) Allow(addr net.Addr) (bool, time.Time) {
	if b == nil {
		return true, time.Time{}
	}
	host, network, ok := banKeys(addr)
	if !ok || b.trusted(host.Addr()) {
		return true, time.Time{}
	}

	now := b.opts.Now()
	b.mu.Lock()
	defer b.mu.Unlock()

	until := time.Time{}
	for _, e := range []*banEntry{b.hosts[host], b.nets[network]} {
		if e == nil || !e.until.After(now) {
			continue
		}
		if e.until.After(until) {
			until = e.until
		}
	}
	if until.IsZero() {
		return true, time.Time{}
	}
	b.refused++
	return false, until
}

// Fail records a failed login from addr, worth weight.
//
// Fail never blocks and never reports anything: the caller is on an
// error path and has its own answer to give.
func (b *Banlist) Fail(addr net.Addr, weight int, why string) {
	if b == nil || weight <= 0 {
		return
	}
	host, network, ok := banKeys(addr)
	if !ok || b.trusted(host.Addr()) {
		return
	}

	now := b.opts.Now()
	b.mu.Lock()
	defer b.mu.Unlock()

	// A host already locked out costs nothing further -- not even
	// against its network.
	//
	// It is the difference between the network tier catching a spray
	// and the network tier being a weapon: one noisy machine that
	// keeps knocking would otherwise spend the whole /24's budget by
	// itself and take its neighbours down with it. Its failures are
	// already being refused at the door; counting them twice buys
	// nothing.
	if e := b.hosts[host]; e != nil && e.until.After(now) {
		return
	}

	if e := b.charge(b.hosts, host, weight, why, now, b.opts.HostThreshold); e != nil {
		b.logBan("SSH gateway locked out a host", host, e)
	}
	if e := b.charge(b.nets, network, weight, why, now, b.opts.NetThreshold); e != nil {
		b.logBan("SSH gateway locked out a network", network, e)
	}
}

// Ban locks addr out now, without waiting for a score to build up.
//
// For a failure that only an attacker produces, where counting to ten
// first would be a courtesy nobody asked for. It charges a host's
// whole budget at once, so the surrounding network still sees it and a
// spray across addresses still adds up.
func (b *Banlist) Ban(addr net.Addr, why string) {
	if b == nil {
		return
	}
	b.Fail(addr, b.opts.HostThreshold, why)
}

// Succeed clears what a host has accumulated, because it has just
// proved there is a real user behind it. Its history of past lockouts
// goes with it, so somebody who was locked out once and has since been
// fine is not still serving a longer sentence a week later.
//
// The surrounding network is credited too, but only by one: a site
// with a genuine user in it should not be locked out for its
// neighbour's behaviour, and equally one compromised host should not
// be able to launder a spray by logging in successfully between
// attempts.
func (b *Banlist) Succeed(addr net.Addr) {
	if b == nil {
		return
	}
	host, network, ok := banKeys(addr)
	if !ok {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.hosts, host)
	if e := b.nets[network]; e != nil && e.until.IsZero() {
		if e.score <= 1 {
			delete(b.nets, network)
		} else {
			e.score--
		}
	}
}

// charge adds weight to one table's entry and returns it if this was
// the charge that locked it out.
func (b *Banlist) charge(table map[netip.Prefix]*banEntry, key netip.Prefix, weight int, why string, now time.Time, threshold int) *banEntry {
	e := table[key]
	if e == nil {
		if !b.makeRoom(table, now) {
			b.untracked++
			return nil
		}
		e = &banEntry{windowStart: now}
		table[key] = e
	}
	if now.Sub(e.windowStart) > b.opts.Window {
		e.score = 0
		e.windowStart = now
	}
	e.lastSeen = now
	e.why = why

	// Already locked out: extend nothing and count nothing. Otherwise
	// a source that keeps knocking while banned ratchets its own
	// sentence up forever, and the doubling below stops meaning
	// "came back after serving it".
	if e.until.After(now) {
		return nil
	}

	e.score += weight
	if e.score < threshold {
		return nil
	}

	ban := b.opts.BanTime
	for i := 0; i < e.strikes && ban < b.opts.MaxBanTime; i++ {
		ban *= 2
	}
	if ban > b.opts.MaxBanTime {
		ban = b.opts.MaxBanTime
	}
	e.until = now.Add(ban)
	e.strikes++
	e.score = 0
	e.windowStart = now
	b.issued++
	return e
}

// makeRoom keeps a table under MaxTracked, and reports whether there
// is space for one more.
//
// Expired entries go first. If that is not enough, the least recently
// seen entry that is NOT locked out is evicted -- never a live
// lockout, because evicting one is indistinguishable from lifting it,
// and an attacker who can pick which entry we forget would pick their
// own.
//
// When everything is a live lockout, the answer is no and the failure
// goes uncounted. That is the honest behaviour: the table is full of
// attackers, they are all still blocked, and the new arrival is
// refused a slot rather than one of them being released to make room.
func (b *Banlist) makeRoom(table map[netip.Prefix]*banEntry, now time.Time) bool {
	if len(table) < b.opts.MaxTracked {
		return true
	}
	for k, e := range table {
		if e.until.After(now) {
			continue
		}
		if now.Sub(e.lastSeen) > b.opts.Window {
			delete(table, k)
		}
	}
	if len(table) < b.opts.MaxTracked {
		return true
	}

	var oldestKey netip.Prefix
	var oldest time.Time
	found := false
	for k, e := range table {
		if e.until.After(now) {
			continue
		}
		if !found || e.lastSeen.Before(oldest) {
			oldestKey, oldest, found = k, e.lastSeen, true
		}
	}
	if !found {
		return false
	}
	delete(table, oldestKey)
	return true
}

func (b *Banlist) trusted(addr netip.Addr) bool {
	for _, p := range b.opts.Trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (b *Banlist) logBan(msg string, key netip.Prefix, e *banEntry) {
	if b.opts.Logger == nil {
		return
	}
	b.opts.Logger.Warn(logging.DestinationHTTP, msg,
		"source", key.String(),
		"until", e.until.Format(time.RFC3339),
		"strike", e.strikes,
		"reason", e.why)
}

// BanlistStats is a snapshot, for metrics and for tests.
type BanlistStats struct {
	// TrackedHosts and TrackedNetworks are table sizes, so an
	// operator can see the bound being approached before it bites.
	TrackedHosts    int
	TrackedNetworks int
	// ActiveHostBans and ActiveNetworkBans are lockouts in force.
	ActiveHostBans    int
	ActiveNetworkBans int
	// BansIssued, ConnectionsRefused and FailuresUntracked are
	// cumulative.
	BansIssued         uint64
	ConnectionsRefused uint64
	FailuresUntracked  uint64
}

// Stats returns a snapshot. Safe on a nil Banlist, where it is zero.
func (b *Banlist) Stats() BanlistStats {
	if b == nil {
		return BanlistStats{}
	}
	now := b.opts.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	s := BanlistStats{
		TrackedHosts:       len(b.hosts),
		TrackedNetworks:    len(b.nets),
		BansIssued:         b.issued,
		ConnectionsRefused: b.refused,
		FailuresUntracked:  b.untracked,
	}
	for _, e := range b.hosts {
		if e.until.After(now) {
			s.ActiveHostBans++
		}
	}
	for _, e := range b.nets {
		if e.until.After(now) {
			s.ActiveNetworkBans++
		}
	}
	return s
}

// AuthLogCallback is the ssh.ServerConfig hook that feeds the list.
//
// Every refused authentication arrives here, which is the right place
// to judge them: it is the only point that knows WHICH method was
// tried, and the method is the strongest signal available about who is
// on the other end.
//
// Returns nil for a nil Banlist, which is what ssh.ServerConfig wants
// for "no hook".
func (b *Banlist) AuthLogCallback() func(ssh.ConnMetadata, string, error) {
	if b == nil {
		return nil
	}
	return func(conn ssh.ConnMetadata, method string, err error) {
		addr := conn.RemoteAddr()
		if err == nil {
			b.Succeed(addr)
			return
		}
		if errors.Is(err, ErrServerSide) {
			// Our fault, not theirs. See ErrServerSide.
			return
		}
		switch method {
		case "none":
			// Every client opens with "none" to find out what the
			// server offers, and is refused. Counting it would lock
			// out everybody who has ever connected.
		case "publickey":
			// An agent offers every key it holds and each rejection
			// lands here, so a developer with a full keyring would
			// otherwise ban themselves before reaching the prompt. A
			// FORGED certificate is charged by CertAuth instead,
			// which is the only place that can tell the difference.
		case "keyboard-interactive":
			weight, why := WeightAbandoned, "login was not completed"
			if unlikelyUsername(conn.User()) {
				weight += WeightUnlikelyUser
				why += " for " + conn.User()
			}
			b.Fail(addr, weight, why)
		default:
			// A method this server never advertised: password,
			// gssapi-with-mic, hostbased, or something made up. A
			// real client asks for what it was offered in the
			// failure list, so nothing legitimate arrives here.
			//
			// This, and not the username, is what catches the
			// scanners. `root@` is no evidence at all -- an
			// unprefixed username means "my default session", so
			// `ssh root@gateway` is what a real user gets from a
			// container, while the scanner banging on port 22 is
			// asking for a password.
			b.Ban(addr, "attempted "+method+" authentication")
		}
	}
}

// unlikelyUsernames are the names a scanner works through. Only
// consulted for a login that already failed.
var unlikelyUsernames = map[string]bool{
	"root": true, "admin": true, "administrator": true, "sysadmin": true,
	"operator": true, "guest": true, "user": true, "test": true,
	"oracle": true, "postgres": true, "mysql": true, "ftp": true,
	"ubuntu": true, "centos": true, "debian": true, "ec2-user": true,
	"pi": true, "jenkins": true, "nagios": true, "backup": true,
	"support": true, "www-data": true, "deploy": true,
}

// unlikelyUsername reports whether a username is one of those.
//
// Matched on the RAW username, which is what excludes the two things
// that must not be caught by it. "+root" is somebody naming a session
// deliberately, and they may call it what they like; a job id is an
// ordinary request. Neither is in the list, because the list holds
// bare names -- and a bare name is the one thing this gateway ignores
// entirely, reading every one of them as "my default session". That
// is what makes drawing an inference from it safe: nothing else does.
func unlikelyUsername(user string) bool {
	return unlikelyUsernames[strings.ToLower(strings.TrimSpace(user))]
}

// banKeys splits an address into the host key and the network key.
//
// IPv6 counts a /64 as one host and a /48 as one network, because a
// single machine there routinely has several addresses and a single
// site has several /64s -- keying on the full address would count one
// laptop as thousands of strangers. IPv4 has no such slack, so a host
// is a /32 and a network is a /24.
func banKeys(addr net.Addr) (host, network netip.Prefix, ok bool) {
	ip, ok := banAddr(addr)
	if !ok {
		return host, network, false
	}
	hostBits, netBits := 32, 24
	if ip.Is6() {
		hostBits, netBits = 64, 48
	}
	h, err := ip.Prefix(hostBits)
	if err != nil {
		return host, network, false
	}
	n, err := ip.Prefix(netBits)
	if err != nil {
		return host, network, false
	}
	return h, n, true
}

func banAddr(addr net.Addr) (netip.Addr, bool) {
	if addr == nil {
		return netip.Addr{}, false
	}
	if ta, isTCP := addr.(*net.TCPAddr); isTCP {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok {
			return ip.Unmap(), true
		}
	}
	s := addr.String()
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Unmap(), true
	}
	return netip.Addr{}, false
}

// ParseTrustedNetworks reads a list of addresses and CIDR blocks.
//
// A bare address is taken as itself alone, so an operator can list a
// monitoring host without knowing to write /32 after it.
func ParseTrustedNetworks(items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, raw := range items {
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, p.Masked())
			continue
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
	}
	return out, nil
}
