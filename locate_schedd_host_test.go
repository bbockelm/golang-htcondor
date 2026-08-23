package htcondor

import "testing"

// TestParseScheddHost covers the spellings HTCondor documents for
// SCHEDD_HOST: a bare hostname, name@hostname, and either with a port.
func TestParseScheddHost(t *testing.T) {
	cases := []struct {
		in         string
		name, host string
		addr       string
	}{
		{"", "", "", ""},
		{"   ", "", "", ""},
		{"ap1.example.edu", "", "ap1.example.edu", ""},
		{"submit@ap1.example.edu", "submit", "ap1.example.edu", ""},
		{" submit @ ap1.example.edu ", "submit", "ap1.example.edu", ""},
		{"ap1.example.edu:9618", "", "ap1.example.edu:9618", "ap1.example.edu:9618"},
		{"submit@ap1.example.edu:9618", "submit", "ap1.example.edu:9618", "ap1.example.edu:9618"},
		{"[2001:db8::1]:9618", "", "[2001:db8::1]:9618", "[2001:db8::1]:9618"},
		// A bare IPv6 literal is a host, not a host:port.
		{"2001:db8::1", "", "2001:db8::1", ""},
	}
	for _, tc := range cases {
		got := ParseScheddHost(tc.in)
		if got.Name != tc.name || got.Host != tc.host {
			t.Errorf("ParseScheddHost(%q) = {Name:%q Host:%q}, want {Name:%q Host:%q}", tc.in, got.Name, got.Host, tc.name, tc.host)
		}
		if addr := got.Address(); addr != tc.addr {
			t.Errorf("ParseScheddHost(%q).Address() = %q, want %q", tc.in, addr, tc.addr)
		}
		if want := tc.in != "" && tc.host != ""; got.IsSet() != want {
			t.Errorf("ParseScheddHost(%q).IsSet() = %v, want %v", tc.in, got.IsSet(), want)
		}
	}
}

// TestScheddTargetCollectorConstraint checks the constraint each form
// produces, since a wrong one silently selects the wrong schedd.
func TestScheddTargetCollectorConstraint(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"ap1.example.edu":        `Machine == "ap1.example.edu" || Name == "ap1.example.edu"`,
		"submit@ap1.example.edu": `Name == "submit@ap1.example.edu" || Name == "submit"`,
	}
	for in, want := range cases {
		if got := ParseScheddHost(in).CollectorConstraint(); got != want {
			t.Errorf("ParseScheddHost(%q).CollectorConstraint() = %q, want %q", in, got, want)
		}
	}
}
