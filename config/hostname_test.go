package config

import (
	"strings"
	"testing"
)

func TestShortFromFQDN(t *testing.T) {
	cases := map[string]string{
		"ap43.uw.osg-htc.org": "ap43",
		"ap43":                "ap43",
		"a.b":                 "a",
		"":                    "",
	}
	for in, want := range cases {
		if got := shortFromFQDN(in); got != want {
			t.Errorf("shortFromFQDN(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDetectHostnamesInvariants checks the split contract against the real host:
// the short name carries no dot, and the FQDN's first label is the short name.
func TestDetectHostnamesInvariants(t *testing.T) {
	short, fqdn := detectHostnames()
	if strings.Contains(short, ".") {
		t.Errorf("short hostname %q unexpectedly contains a dot", short)
	}
	if short != shortFromFQDN(fqdn) {
		t.Errorf("short %q is not the first label of fqdn %q", short, fqdn)
	}
}

// TestFullHostnameGate is the reproduction of the reported failure: a config
// that gates on `"$(FULL_HOSTNAME)" == "<fqdn>"`. With FULL_HOSTNAME set to a
// bare short name the comparison silently failed; here we pin that once
// FULL_HOSTNAME is a qualified name, an equality gate against it evaluates true.
func TestFullHostnameGate(t *testing.T) {
	// Drive the config directly with a known FULL_HOSTNAME so the test does not
	// depend on the runner's DNS, exercising the same expansion + $INT path the
	// real config uses.
	txt := `FULL_HOSTNAME = ap43.uw.osg-htc.org
HOSTCHECK = "$(FULL_HOSTNAME)" == "ap43.uw.osg-htc.org" || "$(FULL_HOSTNAME)" == "ospool-ap4043.chtc.wisc.edu"
if $INT(HOSTCHECK)
  TEST_GUARDED_KNOB = /var/lib/condor/job_queue/job_queue.log
endif
`
	cfg, err := NewFromReader(strings.NewReader(txt))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := cfg.Get("TEST_GUARDED_KNOB")
	if !ok || got != "/var/lib/condor/job_queue/job_queue.log" {
		t.Errorf("TEST_GUARDED_KNOB = %q (set=%v); the FULL_HOSTNAME gate did not fire", got, ok)
	}
}

// TestNetworkHostnameOverridesFullHostname reproduces the PATH AP1 failure:
// the OS/DNS name is path-ap2101.chtc.wisc.edu, but a config.d file sets
// NETWORK_HOSTNAME = ap1.facility.path-cc.io (gated on the current
// FULL_HOSTNAME, checking both FQDNs). C++ HTCondor then recomputes
// FULL_HOSTNAME to the NETWORK_HOSTNAME, so the schedd advertises -- and is
// discovered as -- ap1.facility.path-cc.io. Before the fix the Go config left
// FULL_HOSTNAME as the DNS name, so the derived schedd name never matched the
// collector and discovery timed out.
func TestNetworkHostnameOverridesFullHostname(t *testing.T) {
	const dnsName = "path-ap2101.chtc.wisc.edu"
	const advertised = "ap1.facility.path-cc.io"

	txt := `PROD_HOSTNAME_CHECK_AP1 = "$(FULL_HOSTNAME)" == "ap1.facility.path-cc.io" || "$(FULL_HOSTNAME)" == "path-ap2101.chtc.wisc.edu"
if $INT(PROD_HOSTNAME_CHECK_AP1)
  NETWORK_HOSTNAME = ap1.facility.path-cc.io
endif
`
	// Pin FULL_HOSTNAME to the DNS name the host boots under, so the gate
	// evaluates against it exactly as it does on the real machine.
	c := NewEmpty()
	c.Set("FULL_HOSTNAME", dnsName)
	if err := c.parseAndExecute(strings.NewReader(txt)); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Precondition: the gated knob fired.
	if nh, _ := c.Get("NETWORK_HOSTNAME"); nh != advertised {
		t.Fatalf("NETWORK_HOSTNAME = %q, want %q (gate did not fire)", nh, advertised)
	}

	// The fix: applying it rewrites FULL_HOSTNAME (and the short HOSTNAME).
	c.applyNetworkHostname()

	if got, _ := c.Get("FULL_HOSTNAME"); got != advertised {
		t.Errorf("FULL_HOSTNAME = %q, want %q", got, advertised)
	}
	if got, _ := c.Get("HOSTNAME"); got != "ap1" {
		t.Errorf("HOSTNAME = %q, want %q", got, "ap1")
	}
	// UID_DOMAIN defaults to $(FULL_HOSTNAME); it must follow the override,
	// since a macro resolved lazily should see the new value.
	if got, _ := c.Get("UID_DOMAIN"); got != advertised {
		t.Errorf("UID_DOMAIN = %q, want %q (derived value did not follow FULL_HOSTNAME)", got, advertised)
	}
}

// TestNetworkHostnameUnsetLeavesFullHostname: with no NETWORK_HOSTNAME, the
// detected FULL_HOSTNAME must stand -- the override is opt-in.
func TestNetworkHostnameUnsetLeavesFullHostname(t *testing.T) {
	c := NewEmpty()
	c.Set("FULL_HOSTNAME", "host.example.org")
	c.applyNetworkHostname()
	if got, _ := c.Get("FULL_HOSTNAME"); got != "host.example.org" {
		t.Errorf("FULL_HOSTNAME = %q, want it unchanged", got)
	}
}
