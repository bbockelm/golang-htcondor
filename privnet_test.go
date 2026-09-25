package htcondor

import (
	"strings"
	"testing"

	"github.com/bbockelm/cedar/addresses"
)

// The two cases C++ implements in Daemon::Set_addr, which this follows
// rather than inventing a rule of its own.
func TestPrivateNetworkRewrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		ourNet  string
		want    func(t *testing.T, got string)
		matched bool
	}{
		{
			// A PrivAddr is the common shape: the daemon published the
			// address it can be reached at from inside, so use it. The
			// broker goes with the address it belonged to.
			name:    "private address is used and the broker goes with it",
			address: "<192.0.2.9:9618?PrivNet=pool-a&PrivAddr=<10.0.0.9:9618>&ccbid=192.0.2.1:9618%23123>",
			ourNet:  "pool-a",
			matched: true,
			want: func(t *testing.T, got string) {
				if !strings.Contains(got, "10.0.0.9:9618") {
					t.Errorf("did not dial the private address: %s", got)
				}
				if strings.Contains(got, "ccbid") {
					t.Errorf("still routed through the broker: %s", got)
				}
			},
		},
		{
			// No PrivAddr: the public address was reachable all along and
			// only the broker was in the way, so drop just the broker.
			name:    "without a private address only the broker is dropped",
			address: "<192.0.2.9:9618?PrivNet=pool-a&ccbid=192.0.2.1:9618%23123&noUDP>",
			ourNet:  "pool-a",
			matched: true,
			want: func(t *testing.T, got string) {
				if strings.Contains(got, "ccbid") {
					t.Errorf("the broker survived: %s", got)
				}
				if !strings.Contains(got, "192.0.2.9:9618") {
					t.Errorf("lost the public address: %s", got)
				}
				// Everything else the sinful carried has to survive.
				if !strings.Contains(got, "noUDP") {
					t.Errorf("dropped an unrelated parameter: %s", got)
				}
				if !strings.Contains(got, "PrivNet=pool-a") {
					t.Errorf("dropped PrivNet: %s", got)
				}
			},
		},
		{
			name:    "a different network is not matched",
			address: "<192.0.2.9:9618?PrivNet=pool-b&PrivAddr=<10.0.0.9:9618>&ccbid=192.0.2.1:9618%23123>",
			ourNet:  "pool-a",
			matched: false,
		},
		{
			name:    "no PrivNet on the target",
			address: "<192.0.2.9:9618?ccbid=192.0.2.1:9618%23123>",
			ourNet:  "pool-a",
			matched: false,
		},
		{
			// A client that claims no network matches nothing, which is
			// what an unset PRIVATE_NETWORK_NAME has to mean.
			name:    "no network configured here",
			address: "<192.0.2.9:9618?PrivNet=pool-a&PrivAddr=<10.0.0.9:9618>>",
			ourNet:  "",
			matched: false,
		},
		{
			name:    "an unparseable address is left alone",
			address: "%%%not-a-sinful",
			ourNet:  "pool-a",
			matched: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, matched := rewriteForPrivateNetwork(tc.address, tc.ourNet)
			if matched != tc.matched {
				t.Fatalf("matched = %v, want %v (got %q)", matched, tc.matched, got)
			}
			if !matched {
				if got != tc.address {
					t.Errorf("an unmatched address was rewritten: %q -> %q", tc.address, got)
				}
				return
			}
			tc.want(t, got)
			// Whatever comes out has to be dialable.
			if _, err := addresses.ParseSinful(got); err != nil {
				t.Errorf("the rewritten address does not parse: %q: %v", got, err)
			}
		})
	}
}

// SSL verifies the daemon's certificate against the alias, and the private
// address does not carry one. Dropping it while rewriting turns a working
// SSL dial into a hostname mismatch -- which is why the C++ side lifts the
// alias out before it rewrites and keeps it.
func TestPrivateRewriteCarriesTheAlias(t *testing.T) {
	got, matched := rewriteForPrivateNetwork(
		"<192.0.2.9:9618?alias=ep1.example.org&PrivNet=pool-a&PrivAddr=<10.0.0.9:9618>>", "pool-a")
	if !matched {
		t.Fatal("expected a match")
	}
	parsed, err := addresses.ParseSinful(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	if parsed.Alias != "ep1.example.org" {
		t.Errorf("alias = %q, want it carried onto the private address (%s)", parsed.Alias, got)
	}
	if parsed.Host != "10.0.0.9" {
		t.Errorf("host = %q, want the private address", parsed.Host)
	}
}

// A private address that names its own alias keeps it: the daemon's choice
// wins over one carried across from the address it replaced.
func TestPrivateAddressKeepsItsOwnAlias(t *testing.T) {
	got, _ := rewriteForPrivateNetwork(
		"<192.0.2.9:9618?alias=public.example&PrivNet=p&PrivAddr=<10.0.0.9:9618?alias=private.example>>", "p")
	parsed, _ := addresses.ParseSinful(got)
	if parsed.Alias != "private.example" {
		t.Errorf("alias = %q, want the private address's own", parsed.Alias)
	}
}

// Parameters that stay must stay byte-for-byte, including ones this build
// does not know about.
func TestStripSinfulParamPreservesTheRest(t *testing.T) {
	got := stripSinfulParam("<1.2.3.4:9618?sock=abc&ccbid=5.6.7.8:9618%239&future=keep%20me>", "ccbid")
	if strings.Contains(got, "ccbid") {
		t.Errorf("ccbid survived: %s", got)
	}
	for _, want := range []string{"sock=abc", "future=keep%20me"} {
		if !strings.Contains(got, want) {
			t.Errorf("lost %q from %s", want, got)
		}
	}
	if !strings.HasPrefix(got, "<") || !strings.HasSuffix(got, ">") {
		t.Errorf("lost the brackets: %s", got)
	}
}

// Dropping the only parameter must not leave a dangling "?".
func TestStripSinfulParamDropsTheQuestionMark(t *testing.T) {
	got := stripSinfulParam("<1.2.3.4:9618?ccbid=5.6.7.8:9618%239>", "ccbid")
	if got != "<1.2.3.4:9618>" {
		t.Errorf("got %q, want a bare sinful", got)
	}
}

// The multi-address form. C++ replaces the whole address with the private
// one, so addrs goes with it; and where there is no private address it
// keeps the sinful intact but for the broker, so addrs stays.
func TestPrivateRewriteHandlesAddrs(t *testing.T) {
	withPriv, _ := rewriteForPrivateNetwork(
		"<192.0.2.9:9618?addrs=192.0.2.9-9618+[2001-db8--1]-9618&PrivNet=p&PrivAddr=<10.0.0.9:9618>&ccbid=x:9618%231>", "p")
	if strings.Contains(withPriv, "addrs=") {
		t.Errorf("the public addrs list survived onto the private address: %s", withPriv)
	}

	noPriv, _ := rewriteForPrivateNetwork(
		"<192.0.2.9:9618?addrs=192.0.2.9-9618+[2001-db8--1]-9618&PrivNet=p&ccbid=x:9618%231>", "p")
	if !strings.Contains(noPriv, "addrs=192.0.2.9-9618+[2001-db8--1]-9618") {
		t.Errorf("the addrs list was lost or mangled: %s", noPriv)
	}
	if strings.Contains(noPriv, "ccbid") {
		t.Errorf("the broker survived: %s", noPriv)
	}
}

// The encoding has to be HTCondor's, not net/url's. They disagree where it
// matters: Go writes a space as "+", and HTCondor's decoder treats "+" as a
// literal plus, so a value round-trips changed.
func TestSinfulEncodingMatchesHTCondor(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"ep1.example.org", "ep1.example.org"}, // hostnames pass through
		{"a b", "a%20b"},                       // NOT "a+b"
		{"a+b", "a+b"},                         // plus is in the unescaped set
		{"a&b", "a%26b"},                       // the separator must never survive raw
		{"a;b", "a%3bb"},
		{"a=b", "a%3db"},
		{"<10.0.0.9:9618>", "%3c10.0.0.9:9618%3e"},
	} {
		if got := sinfulEncode(tc.in); got != tc.want {
			t.Errorf("sinfulEncode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Round-tripping is the property that matters, and the one net/url breaks.
func TestSinfulEncodingRoundTrips(t *testing.T) {
	for _, s := range []string{"ep1.example.org", "a b", "a+b", "a&b=c;d", "<10.0.0.9:9618?sock=x>", ""} {
		if got := sinfulDecode(sinfulEncode(s)); got != s {
			t.Errorf("round trip of %q gave %q", s, got)
		}
	}
}

// A plus is a plus. Decoding it as a space -- which net/url does -- would
// make two different keys compare equal.
func TestSinfulDecodeDoesNotTreatPlusAsSpace(t *testing.T) {
	// Both a percent escape and a plus, so this goes through the decoding
	// loop rather than the no-escapes fast path. With only a plus it would
	// return early and prove nothing about how a plus is decoded.
	if got := sinfulDecode("a+b%20c"); got != "a+b c" {
		t.Errorf("sinfulDecode(\"a+b%%20c\") = %q, want \"a+b c\": the plus is a plus and %%20 is a space", got)
	}
	if got := sinfulDecode("a+b"); got != "a+b" {
		t.Errorf("sinfulDecode(\"a+b\") = %q, want the plus left alone", got)
	}
}

// An alias carried onto a private address must be escaped HTCondor's way,
// and must come back out of the parser unchanged.
func TestAliasSurvivesEncodingOnRewrite(t *testing.T) {
	got, matched := rewriteForPrivateNetwork(
		"<192.0.2.9:9618?alias=ep1.example.org&PrivNet=p&PrivAddr=<10.0.0.9:9618>>", "p")
	if !matched {
		t.Fatal("expected a match")
	}
	if strings.Contains(got, "+") {
		t.Errorf("Go-style escaping leaked into the address: %s", got)
	}
	parsed, err := addresses.ParseSinful(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	if parsed.Alias != "ep1.example.org" {
		t.Errorf("alias = %q after a round trip through the encoder", parsed.Alias)
	}
}
