package authz

import (
	"net"
	"testing"
)

func TestMatchWildcard(t *testing.T) {
	cases := []struct {
		pattern, str string
		anycase      bool
		want         bool
	}{
		// exact
		{"condor@pool.example", "condor@pool.example", false, true},
		{"condor@pool.example", "other@pool.example", false, false},
		{"Condor@Pool", "condor@pool", true, true},
		{"Condor@Pool", "condor@pool", false, false},
		// prefix "xyz*"
		{"condor@*", "condor@pool.example", true, true},
		{"condor@*", "schedd@pool.example", true, false},
		{"192.168.*", "192.168.1.5", false, true}, // (string prefix; network handled separately)
		// suffix "*xyz" anchored at the end of the string
		{"*.cs.wisc.edu", "node.cs.wisc.edu", true, true},
		{"*.cs.wisc.edu", "node.cs.wisc.edu.evil.com", true, false}, // trailing content after the suffix -> no match
		{"*@pool.example", "condor@pool.example", true, true},
		{"*@pool.example", "condor@other.example", true, false},
		// middle "ab*cd" -> prefix AND suffix
		{"daemon*@pool", "daemon.host@pool", true, true},
		{"daemon*@pool", "daemon.host@other", true, false},
		{"daemon*@pool", "schedd.host@pool", true, false},
		// "*" matches anything
		{"*", "anything-at-all", true, true},
		{"*", "", true, true},
	}
	for _, tc := range cases {
		if got := matchWildcard(tc.pattern, tc.str, tc.anycase); got != tc.want {
			t.Errorf("matchWildcard(%q, %q, anycase=%v) = %v, want %v", tc.pattern, tc.str, tc.anycase, got, tc.want)
		}
	}
}

func TestMatchNetwork(t *testing.T) {
	cases := []struct {
		pattern string
		ip      string
		want    bool
	}{
		{"*", "192.168.1.5", true},
		{"*/*", "10.0.0.1", true},
		// CIDR
		{"192.168.0.0/16", "192.168.1.5", true},
		{"192.168.0.0/16", "192.169.1.5", false},
		{"10.0.0.0/8", "10.5.6.7", true},
		{"2001:db8::/32", "2001:db8::1", true},
		{"2001:db8::/32", "2001:db9::1", false},
		// dotted netmask
		{"192.168.0.0/255.255.0.0", "192.168.50.1", true},
		{"192.168.0.0/255.255.0.0", "192.170.50.1", false},
		// octet wildcard
		{"192.168.1.*", "192.168.1.200", true},
		{"192.168.1.*", "192.168.2.200", false},
		{"10.*", "10.9.8.7", true},
		{"10.*", "11.9.8.7", false},
		// bare address
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1", "127.0.0.2", false},
		{"::1", "::1", true},
		// malformed octet wildcard (star not trailing) -> no match
		{"192.*.1.0", "192.168.1.0", false},
		// hostname pattern is not a network -> no match against IP
		{"*.cs.wisc.edu", "192.168.1.1", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if got := matchNetwork(tc.pattern, ip); got != tc.want {
			t.Errorf("matchNetwork(%q, %q) = %v, want %v", tc.pattern, tc.ip, got, tc.want)
		}
	}
}

func TestMatchUserList(t *testing.T) {
	list := []string{"condor@pool.example", "*@trusted.example"}
	if !matchUserList(list, "condor@pool.example") {
		t.Error("exact user should match")
	}
	if !matchUserList(list, "anyone@trusted.example") {
		t.Error("wildcard domain should match")
	}
	if matchUserList(list, "mallory@evil.example") {
		t.Error("unlisted user should not match")
	}
}
