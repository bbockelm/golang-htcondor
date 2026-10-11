package config

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// fakeHosts is a hostSystem with fixed answers. A CanonicalName for a name not
// in canon fails, as getaddrinfo does for an unknown name.
type fakeHosts struct {
	hostname string
	canon    map[string]string
	addrs    map[string][]string
	route    map[string]string
	best     string
	lookups  []string // names CanonicalName was asked about
}

func (f *fakeHosts) Hostname() (string, error) { return f.hostname, nil }

func (f *fakeHosts) CanonicalName(host string) (string, error) {
	f.lookups = append(f.lookups, host)
	if c, ok := f.canon[host]; ok {
		return c, nil
	}
	return "", fmt.Errorf("lookup %s: no such host", host)
}

func (f *fakeHosts) LookupHost(host string) ([]string, error) {
	if a, ok := f.addrs[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("lookup %s: no such host", host)
}

func (f *fakeHosts) RouteAddr(host string) (string, error) {
	if a, ok := f.route[host]; ok {
		return a, nil
	}
	return "", fmt.Errorf("no route to %s", host)
}

func (f *fakeHosts) BestAddr() string { return f.best }

// TestLocalHostnamesMatchesCpp pins localHostnames to C++
// init_local_hostname_impl and condor_gethostname (ipv6_hostname.cpp).
func TestLocalHostnamesMatchesCpp(t *testing.T) {
	for _, tc := range []struct {
		name        string
		params      map[string]string
		sys         fakeHosts
		short, fqdn string
		noLookup    bool // the canonical name must not be asked for
	}{
		{
			// A Mac's /etc/hosts maps its own name to localhost, and
			// getaddrinfo's canonical name is taken although it has no dot.
			name:  "canonical name without a dot",
			sys:   fakeHosts{hostname: "F4HP7QL65F", canon: map[string]string{"F4HP7QL65F": "localhost"}},
			short: "localhost", fqdn: "localhost",
		},
		{
			name:  "short name qualified by its canonical name",
			sys:   fakeHosts{hostname: "ap43", canon: map[string]string{"ap43": "ap43.uw.osg-htc.org"}},
			short: "ap43", fqdn: "ap43.uw.osg-htc.org",
		},
		{
			// C++ asks for the canonical name whether or not the name has a dot.
			name:  "dotted name replaced by its canonical name",
			sys:   fakeHosts{hostname: "ap40.uw.osg-htc.org", canon: map[string]string{"ap40.uw.osg-htc.org": "ospool-ap2140.chtc.wisc.edu"}},
			short: "ospool-ap2140", fqdn: "ospool-ap2140.chtc.wisc.edu",
		},
		{
			name:  "no canonical name",
			sys:   fakeHosts{hostname: "ap43"},
			short: "ap43", fqdn: "ap43",
		},
		{
			name:   "DEFAULT_DOMAIN_NAME qualifies a short name",
			params: map[string]string{"DEFAULT_DOMAIN_NAME": "example.org"},
			sys:    fakeHosts{hostname: "ap43"},
			short:  "ap43", fqdn: "ap43.example.org",
		},
		{
			name:   "DEFAULT_DOMAIN_NAME with a leading dot",
			params: map[string]string{"DEFAULT_DOMAIN_NAME": ".example.org"},
			sys:    fakeHosts{hostname: "ap43"},
			short:  "ap43", fqdn: "ap43.example.org",
		},
		{
			name:   "DEFAULT_DOMAIN_NAME does not qualify a dotted name",
			params: map[string]string{"DEFAULT_DOMAIN_NAME": "example.org"},
			sys:    fakeHosts{hostname: "ap43", canon: map[string]string{"ap43": "ap43.uw.osg-htc.org"}},
			short:  "ap43", fqdn: "ap43.uw.osg-htc.org",
		},
		{
			name:   "NETWORK_HOSTNAME is not looked up",
			params: map[string]string{"NETWORK_HOSTNAME": "ap1.facility.path-cc.io"},
			sys:    fakeHosts{hostname: "path-ap2101", canon: map[string]string{"ap1.facility.path-cc.io": "elsewhere.example.org"}},
			short:  "ap1", fqdn: "ap1.facility.path-cc.io", noLookup: true,
		},
		{
			name:   "short NETWORK_HOSTNAME takes DEFAULT_DOMAIN_NAME",
			params: map[string]string{"NETWORK_HOSTNAME": "ap1", "DEFAULT_DOMAIN_NAME": "example.org"},
			sys:    fakeHosts{hostname: "path-ap2101"},
			short:  "ap1", fqdn: "ap1.example.org", noLookup: true,
		},
		{
			name:   "NO_DNS names the NETWORK_INTERFACE address",
			params: map[string]string{"NO_DNS": "true", "NETWORK_INTERFACE": "10.0.0.5", "DEFAULT_DOMAIN_NAME": "example.org"},
			sys:    fakeHosts{hostname: "ap43", canon: map[string]string{"10-0-0-5.example.org": "x.example.org"}},
			short:  "10-0-0-5", fqdn: "10-0-0-5.example.org", noLookup: true,
		},
		{
			name:   "NO_DNS with a NETWORK_INTERFACE pattern",
			params: map[string]string{"NO_DNS": "true", "NETWORK_INTERFACE": "*", "DEFAULT_DOMAIN_NAME": "example.org"},
			sys:    fakeHosts{hostname: "ap43", best: "192.168.1.7"},
			short:  "192-168-1-7", fqdn: "192-168-1-7.example.org", noLookup: true,
		},
		{
			name:   "NO_DNS name may not begin with a dash",
			params: map[string]string{"NO_DNS": "true", "NETWORK_INTERFACE": "::1", "DEFAULT_DOMAIN_NAME": "example.org"},
			sys:    fakeHosts{hostname: "ap43"},
			short:  "0--1", fqdn: "0--1.example.org", noLookup: true,
		},
		{
			name:   "NO_DNS without DEFAULT_DOMAIN_NAME",
			params: map[string]string{"NO_DNS": "true", "NETWORK_INTERFACE": "10.0.0.5"},
			sys:    fakeHosts{hostname: "ap43"},
			short:  "", fqdn: "", noLookup: true,
		},
		{
			name:   "NO_DNS routes to COLLECTOR_HOST",
			params: map[string]string{"NO_DNS": "true", "NETWORK_INTERFACE": "", "COLLECTOR_HOST": "cm.example.org:9618", "DEFAULT_DOMAIN_NAME": "example.org"},
			sys:    fakeHosts{hostname: "ap43", route: map[string]string{"cm.example.org": "10.1.2.3"}},
			short:  "10-1-2-3", fqdn: "10-1-2-3.example.org", noLookup: true,
		},
		{
			name:   "NO_DNS resolves the host name",
			params: map[string]string{"NO_DNS": "true", "NETWORK_INTERFACE": "", "DEFAULT_DOMAIN_NAME": "example.org"},
			sys:    fakeHosts{hostname: "ap43", addrs: map[string][]string{"ap43": {"10.9.8.7", "10.9.8.8"}}},
			short:  "10-9-8-7", fqdn: "10-9-8-7.example.org", noLookup: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			param := func(name string) (string, bool) {
				v, ok := tc.params[name]
				return v, ok
			}
			sys := tc.sys
			short, fqdn := localHostnames(param, &sys)
			if short != tc.short || fqdn != tc.fqdn {
				t.Errorf("localHostnames = (%q, %q), want (%q, %q)", short, fqdn, tc.short, tc.fqdn)
			}
			if tc.noLookup && len(sys.lookups) > 0 {
				t.Errorf("asked for the canonical name of %v", sys.lookups)
			}
		})
	}
}

// useFakeHosts makes the configurations the test loads compute host names on f.
func useFakeHosts(t *testing.T, f *fakeHosts) {
	t.Helper()
	old := localHostSystem
	localHostSystem = f
	t.Cleanup(func() { localHostSystem = old })
}

// loadConfigFiles loads a configuration from a root config file and a
// LOCAL_CONFIG_FILE, as a daemon does.
func loadConfigFiles(t *testing.T, root, local string) *Config {
	t.Helper()
	dir := t.TempDir()
	localPath := filepath.Join(dir, "condor_config.local")
	rootPath := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(localPath, []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	root = "LOCAL_CONFIG_DIR =\nLOCAL_CONFIG_FILE = " + localPath + "\n" + root
	if err := os.WriteFile(rootPath, []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONDOR_CONFIG", rootPath)
	cfg, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestNetworkHostnameOverridesFullHostname reproduces the PATH AP1 failure:
// the OS/DNS name is path-ap2101.chtc.wisc.edu, but a config.d file sets
// NETWORK_HOSTNAME = ap1.facility.path-cc.io (gated on the current
// FULL_HOSTNAME, checking both FQDNs). C++ HTCondor then recomputes
// FULL_HOSTNAME to the NETWORK_HOSTNAME, so the schedd advertises -- and is
// discovered as -- ap1.facility.path-cc.io, and UID_DOMAIN follows.
func TestNetworkHostnameOverridesFullHostname(t *testing.T) {
	useFakeHosts(t, &fakeHosts{hostname: "path-ap2101", canon: map[string]string{"path-ap2101": "path-ap2101.chtc.wisc.edu"}})
	cfg := loadConfigFiles(t, "", `PROD_HOSTNAME_CHECK_AP1 = "$(FULL_HOSTNAME)" == "ap1.facility.path-cc.io" || "$(FULL_HOSTNAME)" == "path-ap2101.chtc.wisc.edu"
if $INT(PROD_HOSTNAME_CHECK_AP1)
  NETWORK_HOSTNAME = ap1.facility.path-cc.io
endif
`)
	for knob, want := range map[string]string{
		"NETWORK_HOSTNAME": "ap1.facility.path-cc.io",
		"FULL_HOSTNAME":    "ap1.facility.path-cc.io",
		"HOSTNAME":         "ap1",
		"UID_DOMAIN":       "ap1.facility.path-cc.io",
	} {
		if got, _ := cfg.Get(knob); got != want {
			t.Errorf("%s = %q, want %q", knob, got, want)
		}
	}
}

// TestFullHostnameFollowsRootConfig: a DEFAULT_DOMAIN_NAME in the root config
// file qualifies FULL_HOSTNAME before the local chain is read, as C++ inserts
// it after the root file, and a FULL_HOSTNAME a config file sets is replaced
// by the computed one, as C++ reinsert_specials replaces it.
func TestFullHostnameFollowsRootConfig(t *testing.T) {
	useFakeHosts(t, &fakeHosts{hostname: "node7"})
	cfg := loadConfigFiles(t, "DEFAULT_DOMAIN_NAME = example.org\n", `if $(FULL_HOSTNAME) == node7.example.org
  SEEN_QUALIFIED = true
endif
FULL_HOSTNAME = overridden.example.org
`)
	for knob, want := range map[string]string{
		"SEEN_QUALIFIED": "true",
		"FULL_HOSTNAME":  "node7.example.org",
		"HOSTNAME":       "node7",
		"UID_DOMAIN":     "node7.example.org",
	} {
		if got, _ := cfg.Get(knob); got != want {
			t.Errorf("%s = %q, want %q", knob, got, want)
		}
	}
}

// TestFullHostnameMatchesCondorConfigVal compares HOSTNAME, FULL_HOSTNAME and
// UID_DOMAIN with what the installed condor_config_val reports for the same
// configuration on this machine. Skipped when condor_config_val is not
// installed.
func TestFullHostnameMatchesCondorConfigVal(t *testing.T) {
	ccv, err := exec.LookPath("condor_config_val")
	if err != nil {
		t.Skip("condor_config_val not installed")
	}
	for name, body := range map[string]string{
		"detected":            "",
		"DEFAULT_DOMAIN_NAME": "DEFAULT_DOMAIN_NAME = example.org\n",
		"NETWORK_HOSTNAME":    "NETWORK_HOSTNAME = ap1\nDEFAULT_DOMAIN_NAME = example.org\n",
		"NO_DNS":              "NO_DNS = true\nNETWORK_INTERFACE = 127.0.0.1\nDEFAULT_DOMAIN_NAME = example.org\n",
		"UID_DOMAIN":          "UID_DOMAIN = $(FULL_HOSTNAME)\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "condor_config")
			body = "LOCAL_CONFIG_DIR =\nLOCAL_CONFIG_FILE =\nLOG = " + dir + "\n" + body
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			knobs := []string{"HOSTNAME", "FULL_HOSTNAME", "UID_DOMAIN"}
			cmd := exec.CommandContext(context.Background(), ccv, knobs...)
			cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+path)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("condor_config_val: %v", err)
			}
			want := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(want) != len(knobs) {
				t.Fatalf("condor_config_val printed %q", out)
			}

			t.Setenv("CONDOR_CONFIG", path)
			cfg, err := New()
			if err != nil {
				t.Fatal(err)
			}
			for i, knob := range knobs {
				if got, _ := cfg.Get(knob); got != strings.TrimSpace(want[i]) {
					t.Errorf("%s = %q, condor_config_val says %q", knob, got, strings.TrimSpace(want[i]))
				}
			}
		})
	}
}
