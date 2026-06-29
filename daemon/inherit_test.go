package daemon

import "testing"

// TestExtractSharedPortFromInherit covers the parser that pulls the SharedPort
// fd + endpoint name out of CONDOR_INHERIT — the load-bearing step in the
// DaemonCore-style shared-port wiring. The "real-world" case is from a live
// condor_master 25.8.2 running a Go binary as a DaemonCore daemon; keeping the
// exact string here means a future change to the cedar SharedPortEndpoint
// serialization trips a unit test before it breaks a deployment.
func TestExtractSharedPortFromInherit(t *testing.T) {
	cases := []struct {
		name     string
		inherit  string
		wantFD   int
		wantName string
		wantOK   bool
	}{
		{
			name: "real-world condor_master 25.8.2 inherit",
			inherit: `29 <172.17.0.4:9618?addrs=172.17.0.4-9618&alias=ca081efc9ffd&noUDP&sock=master_29_7856> 0 ` +
				`SharedPort:7124acce2ba4697b1a8ae73e978007a61dafa5334a7dc60583248a16228a1857/http_api_29_7856*15*6*0*0*0*0***1**0*0*0*0*0*0*0* 0`,
			wantFD:   15,
			wantName: "7124acce2ba4697b1a8ae73e978007a61dafa5334a7dc60583248a16228a1857/http_api_29_7856",
			wantOK:   true,
		},
		{
			name:    "non-DC daemon (no SharedPort token)",
			inherit: "29 <172.17.0.4:9618?sock=master> 0 0",
			wantOK:  false,
		},
		{name: "empty inherit string", inherit: "", wantOK: false},
		{
			name:    "malformed SharedPort token (no asterisk)",
			inherit: "29 <sinful> 0 SharedPort:no-fields-here 0",
			wantOK:  false,
		},
		{
			name:    "malformed SharedPort token (non-numeric fd)",
			inherit: "29 <sinful> 0 SharedPort:cookie/name*notanumber*6*0 0",
			wantOK:  false,
		},
		{
			name:     "SharedPort before terminator (defensive)",
			inherit:  "1234 <addr> 0 SharedPort:cookie/name*7*6*0*0*0*0***1**0*0* 0",
			wantFD:   7,
			wantName: "cookie/name",
			wantOK:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd, name, ok := extractSharedPortFromInherit(tc.inherit)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (fd=%d, name=%q)", ok, tc.wantOK, fd, name)
			}
			if !tc.wantOK {
				return
			}
			if fd != tc.wantFD {
				t.Errorf("fd = %d, want %d", fd, tc.wantFD)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
		})
	}
}

func TestEndpointBaseName(t *testing.T) {
	cases := map[string]string{
		"cookie/http_api_29_7856": "http_api_29_7856",
		"cookie/ccb":              "ccb",
		"no-slash":                "<unknown>",
		"trailing/":               "<unknown>",
	}
	for in, want := range cases {
		if got := endpointBaseName(in); got != want {
			t.Errorf("endpointBaseName(%q) = %q, want %q", in, got, want)
		}
	}
}
