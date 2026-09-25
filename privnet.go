package htcondor

import (
	"net/url"
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
		if decoded, err := url.QueryUnescape(key); err == nil {
			key = decoded
		}
		if key == drop {
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
	return openB + body + sep + "alias=" + url.QueryEscape(alias) + closeB
}
