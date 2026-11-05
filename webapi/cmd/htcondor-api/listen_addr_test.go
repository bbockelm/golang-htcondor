package main

import (
	"flag"
	"testing"
)

// withListenFlag makes -listen look as it would after the command line
// set it, and puts the flag state back afterwards.
func withListenFlag(t *testing.T, value string) {
	t.Helper()
	origSet, origValue := flag.CommandLine, *listenAddr
	t.Cleanup(func() { flag.CommandLine, *listenAddr = origSet, origValue })

	fs := flag.NewFlagSet(origSet.Name(), flag.ContinueOnError)
	fs.StringVar(listenAddr, "listen", origValue, "Address to listen on")
	if err := fs.Parse([]string{"-listen", value}); err != nil {
		t.Fatalf("parse -listen: %v", err)
	}
	flag.CommandLine = fs
}

// An address typed on the command line is the operator's most deliberate
// statement of where to listen, so it outranks HTTP_API_LISTEN_ADDR --
// which otherwise still sets the address, the flag's default being only a
// default.
func TestListenFlagOutranksConfig(t *testing.T) {
	cfg := cfgWith(t, map[string]string{"HTTP_API_LISTEN_ADDR": ":8443"})

	t.Run("flag given", func(t *testing.T) {
		withListenFlag(t, ":443")
		if got, _, _, _, _ := getHTTPConfig(cfg); got != ":443" {
			t.Errorf("listen address = %q, want %q (the -listen flag)", got, ":443")
		}
	})

	t.Run("flag left at its default", func(t *testing.T) {
		if got, _, _, _, _ := getHTTPConfig(cfg); got != ":8443" {
			t.Errorf("listen address = %q, want %q (HTTP_API_LISTEN_ADDR)", got, ":8443")
		}
	})

	t.Run("neither", func(t *testing.T) {
		if got, _, _, _, _ := getHTTPConfig(cfgWith(t, nil)); got != *listenAddr {
			t.Errorf("listen address = %q, want the flag default %q", got, *listenAddr)
		}
	})
}
