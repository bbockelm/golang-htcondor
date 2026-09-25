package htcondor

import (
	"fmt"
	"strings"

	"github.com/bbockelm/cedar/addresses"
)

// Reaching a daemon on a private network we share with it.
//
// A daemon behind CCB advertises a sinful carrying a CCBID, and a client
// normally has to go through the broker because it cannot open a connection
// to the execute node. That is not true of a client sitting on the same
// private network -- an htcondor-api pod beside the pool, most often -- and
// going through the broker anyway costs real things: streaming needs a broker
// on HTCondor 25.13 or newer, and reversal needs an inbound path into the
// container, which means a hostPort or Service, per-replica address plumbing,
// a firewall opening and a network policy.
//
// HTCondor already has the convention for saying "we are on the same
// network": PRIVATE_NETWORK_NAME. A daemon publishes its own as PrivNet in
// the sinful, and a client whose name matches skips the broker. This is the
// Go side of that, and it follows what C++ does in Daemon::Set_addr rather
// than inventing a rule:
//
//   - PrivNet matches and the sinful carries a PrivAddr: use the private
//     address, which drops the broker with it.
//   - PrivNet matches and there is no PrivAddr: keep the public address and
//     drop only the CCB contact, because the address was reachable all along
//     and only the broker was in the way.
//   - No match: unchanged, broker and all.

// rewriteForPrivateNetwork returns the address to dial, and whether the
// private network was matched.
//
// ourNet empty means the client set no PRIVATE_NETWORK_NAME and nothing can
// match. An empty PrivNet on the target means the same from the other side.
// Neither is an error: not sharing a private network is the ordinary case.
func rewriteForPrivateNetwork(address, ourNet string) (string, bool) {
	ourNet = strings.TrimSpace(ourNet)
	if ourNet == "" {
		return address, false
	}
	sinful, err := addresses.ParseSinful(address)
	if err != nil {
		// Not parseable here is not this function's problem to report: the
		// dial will fail with a better message than anything invented now.
		return address, false
	}
	if sinful.PrivateNet == "" || sinful.PrivateNet != ourNet {
		return address, false
	}

	if priv := strings.TrimSpace(sinful.PrivateAddr); priv != "" {
		return withAlias(ensureSinfulBrackets(priv), sinful.Alias), true
	}

	// No private address, so the public one is what to dial -- without the
	// broker.
	return stripSinfulParam(address, "ccbid"), true
}

// stripSinfulParam removes one parameter from a sinful, leaving the rest of
// the string exactly as it was.
//
// By surgery rather than by re-serializing the parsed form, which cedar
// cannot do anyway: the pairs that stay keep their original bytes, so a
// parameter this build does not know about, or an encoding it would have
// spelled differently, survives being handed on.
func stripSinfulParam(address, drop string) string {
	openB, closeB := "", ""
	body := strings.TrimSpace(address)
	if strings.HasPrefix(body, "<") && strings.HasSuffix(body, ">") {
		openB, closeB = "<", ">"
		body = body[1 : len(body)-1]
	}
	i := strings.IndexByte(body, '?')
	if i < 0 {
		return address
	}
	primary, query := body[:i], body[i+1:]

	kept := make([]string, 0, 8)
	for _, pair := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
		key := pair
		if eq := strings.IndexByte(pair, '='); eq >= 0 {
			key = pair[:eq]
		}
		// Decoded for the comparison, raw for the output: a percent-encoded
		// spelling of the key has to be dropped too, and everything that
		// stays has to stay byte-for-byte.
		key = sinfulDecode(key)
		// Case-folded. HTCondor writes this one as "CCBID", and matching
		// literally is invisible when it fails: the parameter stays, the
		// address still parses, and it goes on meaning exactly what the
		// caller was trying to stop it meaning -- here, that the daemon
		// must be reached through a broker.
		if strings.EqualFold(key, drop) {
			continue
		}
		kept = append(kept, pair)
	}
	if len(kept) == 0 {
		return openB + primary + closeB
	}
	return openB + primary + "?" + strings.Join(kept, "&") + closeB
}

// ensureSinfulBrackets wraps a bare "host:port" the way C++ does before
// re-parsing a PrivAddr, since the two spellings both appear in the wild.
func ensureSinfulBrackets(addr string) string {
	if strings.HasPrefix(addr, "<") {
		return addr
	}
	return "<" + addr + ">"
}

// withAlias carries the alias onto a rewritten address.
//
// The alias is what SSL authentication verifies the daemon's certificate
// against, and the private address does not carry one of its own. Dropping it
// while rewriting would turn a working SSL dial into a hostname mismatch --
// which is why the C++ side lifts the alias out before it rewrites and keeps
// it too.
func withAlias(address, alias string) string {
	if alias == "" {
		return address
	}
	parsed, err := addresses.ParseSinful(address)
	if err != nil {
		return address
	}
	if parsed.Alias != "" {
		// The private address named its own; the daemon's choice wins over
		// one carried across from the address it replaced.
		return address
	}
	body := strings.TrimSpace(address)
	openB, closeB := "", ""
	if strings.HasPrefix(body, "<") && strings.HasSuffix(body, ">") {
		openB, closeB = "<", ">"
		body = body[1 : len(body)-1]
	}
	sep := "?"
	if strings.ContainsRune(body, '?') {
		sep = "&"
	}
	return openB + body + sep + "alias=" + sinfulEncode(alias) + closeB
}

// sinfulEncode escapes a sinful parameter value the way HTCondor does.
//
// Not url.QueryEscape, which is a different encoding and disagrees where it
// matters: Go writes a space as "+", and HTCondor's decoder treats "+" as a
// literal plus -- it is in the unescaped set -- so the value comes back
// changed. The rule here is needsUrlEncodeEscape from condor_sinful.cpp:
// alphanumerics and . _ - : # [ ] + pass through, everything else becomes
// %xx in lower case.
func sinfulEncode(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if sinfulSafeByte(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02x", c)
	}
	return b.String()
}

func sinfulSafeByte(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return true
	}
	switch c {
	case '.', '_', '-', ':', '#', '[', ']', '+':
		return true
	}
	return false
}

// sinfulDecode reverses it, for comparing a key against a known name.
//
// Also not the net/url function: that one decodes "+" to a space, which
// would make a key spelled with a plus compare equal to one spelled with a
// space. Only %xx means anything here.
func sinfulDecode(v string) string {
	if !strings.ContainsRune(v, '%') {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '%' && i+2 < len(v) {
			if hi, ok1 := unhex(v[i+1]); ok1 {
				if lo, ok2 := unhex(v[i+2]); ok2 {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
