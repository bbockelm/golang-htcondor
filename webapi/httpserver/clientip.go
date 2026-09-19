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

package httpserver

import (
	"net"
	"net/http"
	"strings"
)

// Client addresses for the access log.
//
// A forwarded header is a claim made by whoever connected, and anyone can
// make it. Honouring X-Forwarded-For unconditionally lets a caller write
// any address it likes into this server's logs -- which is worth something
// to somebody trying to make an audit trail point elsewhere.
//
// So a header is read only when the peer that sent it is a configured
// proxy. Unconfigured, the peer address is what gets logged: behind an
// ingress that is the ingress, which is honest -- this server genuinely
// does not know who is behind it -- rather than a number an attacker chose.

// parseCIDRs turns a configured list into matchers.
//
// A bare address is accepted as well as a prefix, since naming a single
// ingress is the common case and writing /32 for it is a papercut.
func parseCIDRs(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(raw); err == nil {
			out = append(out, network)
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, &net.ParseError{Type: "CIDR address or IP", Text: raw}
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

// ipInAny reports whether ip falls in one of the networks.
func ipInAny(ip net.IP, networks []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// hostOnly strips a port from an address if one is present.
//
// Written with SplitHostPort rather than by hunting for the last colon: a
// bare IPv6 address is full of colons, and cutting at the last one turns
// 2001:db8::1 into 2001:db8:.
func hostOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// No port, or an IPv6 literal without brackets. Both are already hosts.
	return strings.Trim(addr, "[]")
}

// clientIP resolves the address to log for a request.
//
// With no trusted proxies configured, this is the peer address and nothing
// else is consulted.
//
// With them configured, the X-Forwarded-For chain is walked from the RIGHT,
// discarding entries that are themselves trusted proxies, and the first
// address that is not one is the client. Taking the leftmost entry instead
// -- the usual shortcut -- is wrong precisely when it matters: proxies
// APPEND, so a caller that sends its own X-Forwarded-For puts a value of
// its choosing at the front of the list, ahead of the address the ingress
// observed.
//
// X-Real-IP is honoured only as a fallback, and only from a trusted peer.
// It carries a single address with no chain, so there is nothing to walk.
func clientIP(r *http.Request, trusted []*net.IPNet) string {
	peer := hostOnly(r.RemoteAddr)
	if len(trusted) == 0 {
		return peer
	}
	peerIP := net.ParseIP(peer)
	if !ipInAny(peerIP, trusted) {
		// The connection did not come from a proxy we know, so whatever it
		// says about who it is forwarding for is unverifiable.
		return peer
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := hostOnly(parts[i])
			ip := net.ParseIP(candidate)
			if ip == nil {
				// Unparseable entry: the chain is not trustworthy past this
				// point, so stop rather than skipping over it.
				break
			}
			if !ipInAny(ip, trusted) {
				return candidate
			}
		}
		// Every hop was a trusted proxy and none named a client. Fall
		// through: the peer is the most specific thing actually known.
	}

	if xrip := hostOnly(r.Header.Get("X-Real-IP")); xrip != "" {
		if net.ParseIP(xrip) != nil {
			return xrip
		}
	}
	return peer
}
