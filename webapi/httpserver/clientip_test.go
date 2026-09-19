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
	"net/http/httptest"
	"testing"
)

func mustCIDRs(t *testing.T, entries ...string) []*net.IPNet {
	t.Helper()
	n, err := parseCIDRs(entries)
	if err != nil {
		t.Fatalf("parseCIDRs(%v): %v", entries, err)
	}
	return n
}

func request(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// The spoofing case, and the reason this exists: an arbitrary caller must
// not be able to choose what this server records as its address.
func TestForwardedHeadersAreIgnoredFromAnUnknownPeer(t *testing.T) {
	trusted := mustCIDRs(t, "10.0.0.0/8")

	got := clientIP(request("203.0.113.9:5555", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-IP":       "5.6.7.8",
	}), trusted)

	if got != "203.0.113.9" {
		t.Errorf("clientIP = %q; a header from an untrusted peer was believed", got)
	}
}

// With nothing configured, nothing is believed.
func TestNoTrustedProxiesMeansNoHeaders(t *testing.T) {
	got := clientIP(request("203.0.113.9:5555", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
	}), nil)
	if got != "203.0.113.9" {
		t.Errorf("clientIP = %q, want the peer address", got)
	}
}

// The ordinary case: one ingress, which observed the real client.
func TestTrustedProxyForwardsTheClient(t *testing.T) {
	trusted := mustCIDRs(t, "10.0.0.0/8")
	got := clientIP(request("10.1.2.3:44444", map[string]string{
		"X-Forwarded-For": "198.51.100.7",
	}), trusted)
	if got != "198.51.100.7" {
		t.Errorf("clientIP = %q, want the forwarded client", got)
	}
}

// The subtle one. Proxies APPEND, so a caller that sends its own
// X-Forwarded-For puts a value of its choosing at the FRONT of the list.
// Taking the leftmost entry -- the usual shortcut -- hands the spoofer
// exactly what they asked for.
func TestASpoofedPrefixDoesNotWin(t *testing.T) {
	trusted := mustCIDRs(t, "10.0.0.0/8")

	got := clientIP(request("10.1.2.3:44444", map[string]string{
		// "1.2.3.4" is what the caller injected; "198.51.100.7" is what the
		// ingress actually observed and appended.
		"X-Forwarded-For": "1.2.3.4, 198.51.100.7",
	}), trusted)

	if got == "1.2.3.4" {
		t.Error("the caller's injected prefix was logged as the client address")
	}
	if got != "198.51.100.7" {
		t.Errorf("clientIP = %q, want the address the ingress observed", got)
	}
}

// Several trusted hops: walk past all of them to the first address that is
// not one of ours.
func TestChainOfTrustedProxies(t *testing.T) {
	trusted := mustCIDRs(t, "10.0.0.0/8", "192.168.0.0/16")
	got := clientIP(request("10.1.2.3:44444", map[string]string{
		"X-Forwarded-For": "198.51.100.7, 192.168.5.5, 10.9.9.9",
	}), trusted)
	if got != "198.51.100.7" {
		t.Errorf("clientIP = %q, want the client beyond the proxy hops", got)
	}
}

// X-Real-IP has no chain to walk, so it is a fallback only, and only from
// a peer we trust.
func TestXRealIPOnlyFromATrustedPeer(t *testing.T) {
	trusted := mustCIDRs(t, "10.0.0.0/8")

	if got := clientIP(request("10.1.2.3:4", map[string]string{"X-Real-IP": "198.51.100.7"}), trusted); got != "198.51.100.7" {
		t.Errorf("trusted X-Real-IP = %q", got)
	}
	if got := clientIP(request("203.0.113.9:4", map[string]string{"X-Real-IP": "198.51.100.7"}), trusted); got != "203.0.113.9" {
		t.Errorf("untrusted X-Real-IP was believed: %q", got)
	}
}

// Garbage in the chain stops the walk rather than being skipped over: past
// an entry that cannot be parsed, the rest is not trustworthy.
func TestUnparseableChainEntryStopsTheWalk(t *testing.T) {
	trusted := mustCIDRs(t, "10.0.0.0/8")
	got := clientIP(request("10.1.2.3:4", map[string]string{
		"X-Forwarded-For": "198.51.100.7, not-an-ip, 10.9.9.9",
	}), trusted)
	if got == "198.51.100.7" {
		t.Error("walked past an unparseable entry to a value behind it")
	}
	if got != "10.1.2.3" {
		t.Errorf("clientIP = %q, want the peer once the chain is unusable", got)
	}
}

// A bare IPv6 address is full of colons; cutting at the last one -- which
// the previous implementation did -- turns 2001:db8::1 into 2001:db8:.
func TestIPv6AddressesSurviveIntact(t *testing.T) {
	if got := hostOnly("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Errorf("hostOnly with port = %q", got)
	}
	if got := hostOnly("2001:db8::1"); got != "2001:db8::1" {
		t.Errorf("hostOnly bare = %q, want it unmangled", got)
	}
	if got := hostOnly("198.51.100.7:443"); got != "198.51.100.7" {
		t.Errorf("hostOnly v4 = %q", got)
	}

	// The client must sit OUTSIDE the trusted prefix, or the walk is right
	// to treat it as another proxy hop: 2001:db8:beef::9 is inside
	// 2001:db8::/32.
	trusted := mustCIDRs(t, "2001:db8::/32")
	got := clientIP(request("[2001:db8::5]:44", map[string]string{
		"X-Forwarded-For": "2001:db9:beef::9",
	}), trusted)
	if got != "2001:db9:beef::9" {
		t.Errorf("clientIP = %q, want the forwarded v6 client intact", got)
	}
}

// A single address is accepted where a prefix is expected: naming one
// ingress is the common case.
func TestParseCIDRsAcceptsBareAddresses(t *testing.T) {
	nets, err := parseCIDRs([]string{"10.1.2.3", "192.168.0.0/16", "  "})
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 {
		t.Fatalf("parsed %d networks, want 2", len(nets))
	}
	if !ipInAny(net.ParseIP("10.1.2.3"), nets) {
		t.Error("a bare address did not match itself")
	}
	if ipInAny(net.ParseIP("10.1.2.4"), nets) {
		t.Error("a bare address matched a neighbour; it should be a /32")
	}
	if _, err := parseCIDRs([]string{"not-an-address"}); err == nil {
		t.Error("garbage was accepted")
	}
}
