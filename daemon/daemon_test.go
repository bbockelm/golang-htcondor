package daemon

import "testing"

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
