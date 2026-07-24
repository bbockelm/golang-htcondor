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
