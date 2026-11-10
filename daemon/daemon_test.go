package daemon

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestDeriveAdvertisedSinful(t *testing.T) {
	cases := []struct {
		name       string
		serverAddr string
		sock       string
		want       string
		wantOK     bool
	}{
		{"plain", "<192.168.1.1:9618>", "ccb", "192.168.1.1:9618?sock=ccb", true},
		{"master has its own sock", "<10.0.0.5:9618?sock=master>", "ccb_1234", "10.0.0.5:9618?sock=ccb_1234", true},
		{"no sock id", "<192.168.1.1:9618>", "", "", false},
		{"unparseable", "not-a-sinful", "ccb", "", false},

		// Issue #896: every parameter but sock= is how the shared-port server is
		// reached, and rebuilding the address from host and port threw all of it away.
		{
			"keeps alias, addrs and noUDP",
			"<131.169.223.39:9618?addrs=131.169.223.39-9618+[2001-638-700-10df--1-27]-9618&alias=bird-htc-sched22.desy.de&noUDP&sock=master_2737578_626e>",
			"htcondordb",
			"131.169.223.39:9618?addrs=131.169.223.39-9618+[2001-638-700-10df--1-27]-9618&alias=bird-htc-sched22.desy.de&noUDP&sock=htcondordb",
			true,
		},
		{
			"keeps CCBID and PrivNet",
			"<10.0.0.5:9618?CCBID=192.168.0.1:9618%23123&PrivNet=cluster&sock=master>",
			"http_api",
			"10.0.0.5:9618?CCBID=192.168.0.1:9618%23123&PrivNet=cluster&sock=http_api",
			true,
		},
		{
			// The sock key is matched the way the address is read, not literally.
			"replaces an oddly-cased sock",
			"<10.0.0.5:9618?alias=host.example&SOCK=master>",
			"http_api",
			"10.0.0.5:9618?alias=host.example&sock=http_api",
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := deriveAdvertisedSinful(tc.serverAddr, tc.sock)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("deriveAdvertisedSinful(%q, %q) = (%q, %v), want (%q, %v)",
					tc.serverAddr, tc.sock, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// The derived address must stay unbracketed: callers bracket it themselves when they
// write it into an ad attribute or an address file, and a bracketed return gives them
// "<<...>>".
func TestDeriveAdvertisedSinfulIsUnbracketed(t *testing.T) {
	for _, in := range []string{
		"<10.0.0.5:9618?alias=host.example&sock=master>",
		"10.0.0.5:9618?alias=host.example&sock=master",
		"<10.0.0.5:9618>",
	} {
		got, ok := deriveAdvertisedSinful(in, "http_api")
		if !ok {
			t.Fatalf("deriveAdvertisedSinful(%q) not ok", in)
		}
		if strings.HasPrefix(got, "<") || strings.HasSuffix(got, ">") {
			t.Errorf("deriveAdvertisedSinful(%q) = %q, want no angle brackets", in, got)
		}
	}
}

func TestWithHostAlias(t *testing.T) {
	cases := []struct {
		name  string
		addr  string
		alias string
		want  string
	}{
		{
			"attaches to a plain bind",
			"192.168.1.1:9618",
			"host.example.edu",
			"192.168.1.1:9618?alias=host.example.edu",
		},
		{
			"attaches alongside existing parameters",
			"192.168.1.1:9618?noUDP&sock=http_api",
			"host.example.edu",
			"192.168.1.1:9618?noUDP&sock=http_api&alias=host.example.edu",
		},
		{
			// The shared-port server's own alias wins: it is the name that server's
			// certificate is actually issued for.
			"leaves an existing alias alone",
			"192.168.1.1:9618?alias=real.example.edu&sock=http_api",
			"other.example.edu",
			"192.168.1.1:9618?alias=real.example.edu&sock=http_api",
		},
		{
			"unset HOST_ALIAS changes nothing",
			"192.168.1.1:9618?sock=http_api",
			"",
			"192.168.1.1:9618?sock=http_api",
		},
		{
			// Escaped rather than allowed to re-cut the address into other parameters.
			"escapes a value that would otherwise break the address",
			"192.168.1.1:9618",
			"evil&sock=stolen",
			"192.168.1.1:9618?alias=evil%26sock%3dstolen",
		},
		{
			// '#' is legal in a sinful, so it is NOT escaped -- and a CCB contact is
			// this address plus "#<id>", split on the last '#'.
			"drops an alias holding a CCB hop separator",
			"192.168.1.1:9618?sock=ccb",
			"host.example#99",
			"192.168.1.1:9618?sock=ccb",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.NewEmpty()
			cfg.Set("HOST_ALIAS", tc.alias)
			if got := withHostAlias(tc.addr, cfg); got != tc.want {
				t.Errorf("withHostAlias(%q, HOST_ALIAS=%q) = %q, want %q", tc.addr, tc.alias, got, tc.want)
			}
		})
	}
}

func TestWithHostAliasNilConfig(t *testing.T) {
	if got := withHostAlias("192.168.1.1:9618", nil); got != "192.168.1.1:9618" {
		t.Errorf("withHostAlias with nil config = %q, want the address unchanged", got)
	}
}
