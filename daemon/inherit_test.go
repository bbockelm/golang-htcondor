package daemon

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

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

// TestExtractInheritedCommandSocket covers the parser for the inherit-list command socket
// condor_master passes when USE_SHARED_PORT=False (issue #119). The distinguishing signal
// from shared-port mode: there the inherit-list is empty (the "0" sentinel is the first
// entry) and the socket is a SharedPort: token instead.
func TestExtractInheritedCommandSocket(t *testing.T) {
	cases := []struct {
		name    string
		inherit string
		wantFD  int
		wantOK  bool
	}{
		{"non-shared-port TCP command socket", "123 <sinful> 14*5*0*0*0 0", 14, true},
		{"TCP ReliSock then UDP SafeSock: adopt the first", "123 <sinful> 14*5*0 16*5*0 0", 14, true},
		{"shared-port mode: inherit-list empty (sentinel first)", "29 <sinful> 0 SharedPort:cookie/name*15*6*0 0", 0, false},
		{"no inherited sockets", "29 <sinful> 0 0", 0, false},
		{"empty inherit string", "", 0, false},
		{"malformed fd", "123 <sinful> notanum*5 0", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd, ok := extractInheritedCommandSocket(tc.inherit)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (fd=%d)", ok, tc.wantOK, fd)
			}
			if tc.wantOK && fd != tc.wantFD {
				t.Errorf("fd = %d, want %d", fd, tc.wantFD)
			}
		})
	}
}

// TestResolveInheritedListener passes a real TCP listener's fd through a CONDOR_INHERIT
// inherit-list and asserts resolveInheritedListener adopts it as a working listener that
// accepts connections dialed to the original address.
func TestResolveInheritedListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f, err := ln.(*net.TCPListener).File() // a dup fd standing in for the inherited one
	if err != nil {
		t.Fatal(err)
	}
	// resolveInheritedListener takes ownership of the fd number and closes its reference,
	// so we do not close f ourselves.
	t.Setenv("CONDOR_INHERIT", fmt.Sprintf("123 <sinful> %d*5*0*0 0", f.Fd()))

	logger, err := logging.New(&logging.Config{OutputPath: "stderr", SkipGlobalInstall: true})
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := resolveInheritedListener(logger)
	if err != nil {
		t.Fatal(err)
	}
	if adopted == nil {
		t.Fatal("expected to adopt the inherited command socket")
	}
	defer adopted.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := adopted.Accept()
		accepted <- c
	}()
	dc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	select {
	case c := <-accepted:
		if c == nil {
			t.Fatal("adopted listener Accept returned nil")
		}
		_ = c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("adopted listener did not accept a connection to the inherited socket")
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
