package daemon

import (
	"net"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/config"
)

// A daemon that is not behind a shared port advertises the address of the socket it
// actually bound. Before AdvertisedAddress existed this returned nothing, so PublishAd
// left MyAddress off the ad and every daemon filled it in again by hand.
func TestAdvertisedAddressFallsBackToTheListener(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("HOST_ALIAS", "ap40.chtc.wisc.edu")
	d := testDaemon(t, cfg)

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	d.commandListener = ln

	got := d.AdvertisedAddress()
	want := ln.Addr().String() + "?alias=ap40.chtc.wisc.edu"
	if got != want {
		t.Errorf("AdvertisedAddress() = %q, want %q", got, want)
	}
}

func TestAdvertisedAddressWithoutAListener(t *testing.T) {
	d := testDaemon(t, config.NewEmpty())
	if got := d.AdvertisedAddress(); got != "" {
		t.Errorf("AdvertisedAddress() = %q, want %q", got, "")
	}
}

// The shared-port sinful wins over the listener, whose address behind a shared port is
// a Unix socket path nobody can dial.
func TestAdvertisedAddressPrefersTheSharedPortSinful(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("HOST_ALIAS", "ap40.chtc.wisc.edu")
	d := testDaemon(t, cfg)
	d.sharedPortName = "http_api"
	d.sharedPortAdvertised = "131.169.223.39:9618?addrs=131.169.223.39-9618&alias=bird.desy.de&noUDP&sock=http_api"

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	d.commandListener = ln

	// The shared-port server's alias is kept; HOST_ALIAS does not override it.
	want := "131.169.223.39:9618?addrs=131.169.223.39-9618&alias=bird.desy.de&noUDP&sock=http_api"
	if got := d.AdvertisedAddress(); got != want {
		t.Errorf("AdvertisedAddress() = %q, want %q", got, want)
	}
}

// Issue #896 end to end: the MyAddress a Go daemon puts on its collector ad must carry
// the alias an SSL client verifies the host certificate against.
func TestPublishAdMyAddressCarriesTheAlias(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("HOST_ALIAS", "bird-htc-sched22.desy.de")
	d := testDaemon(t, cfg)
	d.sharedPortName = "http_api"
	d.sharedPortAdvertised = "131.169.223.39:9618?addrs=131.169.223.39-9618+[2001-638-700-10df--1-27]-9618&noUDP&sock=http_api"

	ad := classad.New()
	d.PublishAd(ad)

	got, ok := ad.EvaluateAttrString("MyAddress")
	if !ok {
		t.Fatal("ad has no MyAddress")
	}
	for _, want := range []string{
		"alias=bird-htc-sched22.desy.de",
		"addrs=131.169.223.39-9618+[2001-638-700-10df--1-27]-9618",
		"noUDP",
		"sock=http_api",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("MyAddress = %q, missing %q", got, want)
		}
	}
	if !strings.HasPrefix(got, "<") || !strings.HasSuffix(got, ">") {
		t.Errorf("MyAddress = %q, want it bracketed exactly once", got)
	}
	if strings.HasPrefix(got, "<<") {
		t.Errorf("MyAddress = %q, double-bracketed", got)
	}
}
