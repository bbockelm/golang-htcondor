package main

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/webui"
)

// The footer band is a JSON array in an HTCondor configuration file,
// which is an awkward pairing: this is the documented way to write one
// (docs/server.md, "Web UI branding"), read through the same parser the
// daemon uses, and handed to the same parser the daemon hands it to.
// A config-parser change that broke the form the documentation tells
// operators to use would otherwise be found by an operator.
func TestFooterLogosHeredocParses(t *testing.T) {
	cfg := configFrom(t, `HTTP_API_WEBUI_SITE_NAME = UChicago ATLAS Analysis Facility

HTTP_API_WEBUI_FOOTER_LOGOS @=json
  [
    {"src": "/branding/af.svg",  "alt": "UChicago ATLAS Analysis Facility", "href": "https://af.uchicago.edu/"},
    {"src": "/branding/uc.svg",  "alt": "University of Chicago"}
  ]
@json
`)
	name, _ := cfg.Get("HTTP_API_WEBUI_SITE_NAME")
	if name != "UChicago ATLAS Analysis Facility" {
		t.Errorf("HTTP_API_WEBUI_SITE_NAME = %q", name)
	}

	raw, ok := cfg.Get("HTTP_API_WEBUI_FOOTER_LOGOS")
	if !ok {
		t.Fatal("HTTP_API_WEBUI_FOOTER_LOGOS is not set")
	}
	logos, err := webui.ParseLogos(raw)
	if err != nil {
		t.Fatalf("ParseLogos(%q): %v", raw, err)
	}
	if len(logos) != 2 {
		t.Fatalf("logos = %+v", logos)
	}
	if logos[0].Href != "https://af.uchicago.edu/" || logos[1].Alt != "University of Chicago" {
		t.Errorf("logos = %+v", logos)
	}
}

// And the single-line form, for a site with one logo.
func TestFooterLogosOneLineParses(t *testing.T) {
	cfg := configFrom(t, `HTTP_API_WEBUI_FOOTER_LOGOS = [{"src": "/branding/af.svg", "alt": "ATLAS AF"}]`+"\n")
	raw, _ := cfg.Get("HTTP_API_WEBUI_FOOTER_LOGOS")
	logos, err := webui.ParseLogos(raw)
	if err != nil {
		t.Fatalf("ParseLogos(%q): %v", raw, err)
	}
	if len(logos) != 1 || logos[0].Alt != "ATLAS AF" {
		t.Errorf("logos = %+v", logos)
	}
}
