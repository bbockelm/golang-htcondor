package authz

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// ConfigGetter is the slice of the HTCondor config the authorization policy
// needs: a raw key lookup. *config.Config satisfies it.
type ConfigGetter interface {
	Get(key string) (string, bool)
}

// behavior mirrors the C++ PermType behavior enum (condor_ipverify.h).
type behavior int

const (
	useTable   behavior = iota // consult allow/deny tables (default)
	allowAll                   // grant everyone
	denyAll                    // deny everyone
	onlyDenies                 // deny only those matching the deny table, allow the rest
)

// permEntry is the resolved policy for a single permission level: the parsed
// allow/deny tables (host pattern -> user patterns) and the optimized behavior.
type permEntry struct {
	behavior   behavior
	allowUsers map[string][]string // host key -> user patterns
	denyUsers  map[string][]string

	// allowKnob and denyKnob name the settings that supplied the tables
	// (e.g. "ALLOW_READ_SCHEDD", "DENY_DEFAULT"), "" if none is set.
	allowKnob, denyKnob string
}

// Policy is a port of HTCondor's IpVerify: it answers per-command authorization
// questions (Verify) using the ALLOW_<perm>/DENY_<perm> configuration, with the
// same permission hierarchy, glob/network matching, and parent implication as
// the C++ daemons, and the authorization holes (PunchHole) C++ daemons open for
// the sessions they trust whatever the configuration says.
//
// Not safe for concurrent Init; Verify is read-only after Init (the holes are
// safe to change concurrently).
type Policy struct {
	subsys  string
	entries map[Perm]*permEntry
	holes   *Holes

	usePoolUsernameEquiv bool

	// forwardResolve maps a hostname to its IP-string addresses (ExpandHostAddresses);
	// reverseResolve maps a peer IP to its hostnames (get_hostname_with_alias).
	// Both default to the net package and are overridable for tests.
	forwardResolve func(host string) []string
	reverseResolve func(ip net.IP) []string
}

const (
	condorAt     = "condor@"
	condorPoolAt = "condor_pool@"
)

// NewPolicy builds a Policy from cfg for the given subsystem (e.g. "CCB"),
// resolving every permission's ALLOW_/DENY_ tables up front (mirrors
// IpVerify::Init). subsys may be "" to skip the per-subsystem config variants.
func NewPolicy(cfg ConfigGetter, subsys string) (*Policy, error) {
	p := &Policy{
		subsys:               subsys,
		entries:              make(map[Perm]*permEntry),
		holes:                NewHoles(),
		usePoolUsernameEquiv: configBool(cfg, "USE_POOL_USERNAME_EQUIVALENT", true),
		forwardResolve:       defaultForwardResolve,
		reverseResolve:       defaultReverseResolve,
	}
	for _, perm := range allPerms {
		p.entries[perm] = p.buildEntry(cfg, perm)
	}
	return p, nil
}

var allPerms = []Perm{
	PermRead, PermWrite, PermNegotiator, PermAdministrator, PermConfig,
	PermDaemon, PermAdvertiseStartd, PermAdvertiseSchedd, PermAdvertiseMaster,
	PermDefault,
}

// buildEntry resolves ALLOW_<perm>/DENY_<perm> (through the config-fallback
// chain and per-subsystem variants) and computes the optimized behavior exactly
// as IpVerify::Init does.
func (p *Policy) buildEntry(cfg ConfigGetter, perm Perm) *permEntry {
	e := &permEntry{
		behavior:   useTable,
		allowUsers: make(map[string][]string),
		denyUsers:  make(map[string][]string),
	}
	pAllow, allowKnob, hasAllow := p.getSecSetting(cfg, "ALLOW_%s", perm)
	pDeny, denyKnob, hasDeny := p.getSecSetting(cfg, "DENY_%s", perm)
	e.allowKnob, e.denyKnob = allowKnob, denyKnob

	allowAllv := hasAllow && (pAllow == "*" || pAllow == "*/*")
	denyAllv := hasDeny && (pDeny == "*" || pDeny == "*/*")

	switch {
	case denyAllv || (!hasAllow && perm != PermRead && perm != PermWrite):
		// READ or WRITE may be implicitly allowed by other permissions.
		e.behavior = denyAll
	case allowAllv:
		if !hasDeny {
			e.behavior = allowAll
		} else {
			e.behavior = onlyDenies
			p.fillTable(e, pDeny, false)
		}
	}

	if e.behavior == useTable {
		if hasAllow {
			p.fillTable(e, pAllow, true)
		}
		if hasDeny {
			p.fillTable(e, pDeny, false)
		}
	}
	return e
}

// getSecSetting walks the config-fallback chain (perm, configNext..., DEFAULT),
// trying "<key>_<subsys>" before "<key>" at each level, returning the first set
// value and the knob that set it (mirrors SecMan::getSecSetting). fmt is
// "ALLOW_%s" / "DENY_%s".
func (p *Policy) getSecSetting(cfg ConfigGetter, format string, perm Perm) (value, knob string, ok bool) {
	for _, pp := range configChain(perm) {
		base := fmt.Sprintf(format, string(pp))
		if p.subsys != "" {
			k := base + "_" + strings.ToUpper(p.subsys)
			if v, ok := cfg.Get(k); ok {
				return v, k, true
			}
		}
		if v, ok := cfg.Get(base); ok {
			return v, base, true
		}
	}
	return "", "", false
}

// Knobs returns the settings that decide perm: the ALLOW_ and DENY_ knobs
// (with any _<SUBSYS> suffix, or those of the level perm falls back to) that
// are set, "" for one that is not.
func (p *Policy) Knobs(perm Perm) (allow, deny string) {
	if e := p.entries[perm]; e != nil {
		return e.allowKnob, e.denyKnob
	}
	return "", ""
}

// PunchHole opens perm, and every level it implies, to id whatever the
// ALLOW_/DENY_ settings say, as IpVerify::PunchHole does. id is a full
// user@domain, "user@domain/ip" or a bare IP address, matched exactly.
func (p *Policy) PunchHole(perm Perm, id string) { p.holes.Punch(perm, id) }

// FillHole closes one opening PunchHole made, as IpVerify::FillHole does. It
// reports whether perm was open to id.
func (p *Policy) FillHole(perm Perm, id string) bool { return p.holes.Fill(perm, id) }

// Holes returns the holes p consults.
func (p *Policy) Holes() *Holes { return p.holes }

// SetHoles makes p consult h, so holes punched before a reconfig still apply
// to the Policy rebuilt by it.
func (p *Policy) SetHoles(h *Holes) { p.holes = h }

// fillTable parses a comma/space-separated ALLOW/DENY list into e's host->user
// table, expanding hostnames to their IPs and adding condor@/condor_pool@
// reciprocal users (mirrors IpVerify::fill_table). Netgroups (+name) are not
// supported and are skipped.
func (p *Policy) fillTable(e *permEntry, list string, allow bool) {
	table := e.allowUsers
	if !allow {
		table = e.denyUsers
	}
	for _, entry := range tokenize(list) {
		if entry == "" {
			continue
		}
		host, user := splitEntry(entry)
		if user == netgroupSentinel {
			continue // netgroups unsupported
		}

		var altUser string
		if p.usePoolUsernameEquiv {
			if strings.HasPrefix(strings.ToLower(user), condorAt) {
				altUser = condorPoolAt + user[len(condorAt):]
			} else if strings.HasPrefix(strings.ToLower(user), condorPoolAt) {
				altUser = condorAt + user[len(condorPoolAt):]
			}
		}

		for _, hostKey := range p.expandHostAddresses(host) {
			table[hostKey] = append(table[hostKey], user)
			if altUser != "" {
				table[hostKey] = append(table[hostKey], altUser)
			}
		}
	}
}

const netgroupSentinel = "\x00netgroup\x00"

// splitEntry splits a security-list entry into a host pattern and a user
// pattern, a faithful port of IpVerify::split_entry.
func splitEntry(entry string) (host, user string) {
	if entry == "" {
		return "*", "*"
	}
	if entry[0] == '+' {
		// netgroup entry; we flag it for the caller to skip.
		return entry[1:], netgroupSentinel
	}

	slash0 := strings.IndexByte(entry, '/')
	if slash0 < 0 {
		if strings.IndexByte(entry, '@') >= 0 {
			return "*", entry // user with no host -> any host
		}
		return entry, "*" // bare host (or wildcard) with no user
	}

	// One or more slashes present.
	rest := entry[slash0+1:]
	if strings.IndexByte(rest, '/') >= 0 {
		// form is user/net/mask
		return entry[slash0+1:], entry[:slash0]
	}
	// One slash: user/host or net/mask. Resolve the ambiguity exactly as C++:
	// an '@' before the slash, or a leading '*', means user/host.
	at := strings.IndexByte(entry, '@')
	if (at >= 0 && at < slash0) || entry[0] == '*' {
		return entry[slash0+1:], entry[:slash0]
	}
	// Otherwise, if the left side parses as a network, it's net/mask.
	if looksLikeNetwork(entry) {
		return entry, "*"
	}
	// Strange entry: fall back to user/host.
	return entry[slash0+1:], entry[:slash0]
}

// expandHostAddresses returns the host keys an entry contributes: always the
// literal entry, plus (for a plain hostname) its resolved IP addresses. Mirrors
// IpVerify::ExpandHostAddresses.
func (p *Policy) expandHostAddresses(host string) []string {
	keys := []string{host}
	// Wildcards and FQUN slashes are left literal.
	if strings.ContainsAny(host, "*/") {
		return keys
	}
	// A network literal (IPv4/IPv6/CIDR) is left literal.
	if net.ParseIP(host) != nil {
		return keys
	}
	// Sinful-ish strings are not resolved.
	if strings.ContainsAny(host, "<>?:") {
		return keys
	}
	keys = append(keys, p.forwardResolve(host)...)
	return keys
}

// Authorize adapts Verify to the string-based callback a CEDAR command server
// uses (server.Server.Authorizer): it reports whether user, connecting from
// peerAddr ("host:port"), is allowed at the named authorization level (an
// HTCondor DCpermission name such as "READ" or "DAEMON"). An unparseable
// peerAddr yields a nil IP, which Verify treats as matching no host rule.
func (p *Policy) Authorize(perm, peerAddr, user string) bool {
	host, _, err := net.SplitHostPort(peerAddr)
	if err != nil {
		host = peerAddr
	}
	return p.Verify(Perm(perm), net.ParseIP(host), user)
}

// Verify reports whether the user connecting from addr is allowed at the given
// permission level. user is the peer's fully-qualified user ("user@domain"), the
// string ALLOW_*/DENY_* entries are matched against; a cedar server passes that
// for an authenticated peer and "unauthenticated@unmapped" for one that did not
// authenticate, as C++ DaemonCore does, so only an entry matching that string
// (e.g. "*", "*@unmapped") admits an unauthenticated peer. "" is treated as the
// totally-wild "*", as in C++. A hole open to the peer (PunchHole) grants perm
// before the tables are consulted, so DENY_<perm> does not close it. This is a
// port of IpVerify::Verify (without the result cache, which is a performance
// detail).
func (p *Policy) Verify(perm Perm, addr net.IP, user string) bool {
	if perm == PermAllow {
		return true
	}
	if p.holes.Allows(perm, addr, user) {
		return true
	}
	if user == "" {
		user = "*"
	}
	e := p.entries[perm]
	if e == nil {
		// Unknown perm: deny (C++ EXCEPTs; we fail closed).
		return false
	}

	switch e.behavior {
	case allowAll:
		return true
	case denyAll:
		return false
	}

	// USE_TABLE or ONLY_DENIES: match deny first, then allow, by IP then by
	// resolved hostname.
	allowed, denied := false, false

	if lookupUser(e.denyUsers, user, addr, "") {
		denied = true
	}
	if !denied && lookupUser(e.allowUsers, user, addr, "") {
		allowed = true
	}

	if !allowed && !denied {
		for _, host := range p.reverseResolve(addr) {
			if lookupUser(e.denyUsers, user, nil, host) {
				denied = true
				break
			}
			if lookupUser(e.allowUsers, user, nil, host) {
				allowed = true
				break
			}
		}
	}

	if denied {
		return false
	}
	if allowed {
		return true
	}

	// No match. ONLY_DENIES allows anything not denied.
	if e.behavior == onlyDenies {
		return true
	}

	// USE_TABLE with no match: a parent permission may imply this one.
	for _, parent := range directlyImpliedBy(perm) {
		if p.Verify(parent, addr, user) {
			return true
		}
	}
	return false
}

// lookupUser reports whether (user from ip OR hostname) matches any entry in the
// host->users table. Exactly one of ip/hostname is used. Mirrors
// IpVerify::lookup_user.
func lookupUser(table map[string][]string, user string, ip net.IP, hostname string) bool {
	if len(table) == 0 {
		return false
	}
	for hostKey, users := range table {
		var hostMatches bool
		if ip != nil {
			hostMatches = matchNetwork(hostKey, ip)
		} else {
			hostMatches = matchWildcard(hostKey, hostname, true)
		}
		if hostMatches && matchUserList(users, user) {
			return true
		}
	}
	return false
}

// --- helpers ---

func looksLikeNetwork(s string) bool {
	// A network literal for split_entry purposes: bare IP, CIDR, dotted netmask,
	// or octet wildcard. matchNetwork's parser accepts exactly these forms.
	if net.ParseIP(s) != nil {
		return true
	}
	if slash := strings.IndexByte(s, '/'); slash >= 0 {
		if net.ParseIP(s[:slash]) != nil {
			return true
		}
	}
	if _, _, ok := ipv4OctetWildcard(s); ok {
		return true
	}
	return false
}

func tokenize(list string) []string {
	return strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

func configBool(cfg ConfigGetter, key string, def bool) bool {
	v, ok := cfg.Get(key)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "t", "yes", "y", "1":
		return true
	case "false", "f", "no", "n", "0":
		return false
	}
	return def
}

func defaultForwardResolve(host string) []string {
	ips, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil {
		return nil
	}
	return ips
}

func defaultReverseResolve(ip net.IP) []string {
	if ip == nil {
		return nil
	}
	names, err := net.DefaultResolver.LookupAddr(context.Background(), ip.String())
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, strings.TrimSuffix(n, "."))
	}
	return out
}
