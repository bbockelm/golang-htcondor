package webui

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultBrandingInjectsNothing(t *testing.T) {
	page := []byte("<html><head><title>HTCondor Access Point</title></head><body>x</body></html>")
	if got := DefaultBranding().Inject(page); string(got) != string(page) {
		t.Errorf("the default branding rewrote the page:\n%s", got)
	}
	// And a deployment that set the name to what it already is still
	// gets the untouched export.
	b, err := Build(Options{SiteName: "HTCondor", SiteTagline: "Access Point"})
	if err != nil {
		t.Fatal(err)
	}
	if !b.IsDefault() {
		t.Errorf("Build(%q, %q) is not the default: %+v", "HTCondor", "Access Point", b)
	}
}

func TestBuildNamesTheSite(t *testing.T) {
	b, err := Build(Options{SiteName: "UChicago ATLAS Analysis Facility"})
	if err != nil {
		t.Fatal(err)
	}
	if b.SiteName != "UChicago ATLAS Analysis Facility" {
		t.Errorf("SiteName = %q", b.SiteName)
	}
	// A site that named itself is not also told it is an "Access Point"
	// unless it asked to be.
	if b.SiteTagline != "" {
		t.Errorf("SiteTagline = %q, want it dropped when the site names itself", b.SiteTagline)
	}
	if b.PageTitle != "UChicago ATLAS Analysis Facility" {
		t.Errorf("PageTitle = %q", b.PageTitle)
	}

	b, err = Build(Options{SiteName: "ATLAS AF", SiteTagline: "HTCondor"})
	if err != nil {
		t.Fatal(err)
	}
	if b.PageTitle != "ATLAS AF HTCondor" {
		t.Errorf("PageTitle = %q", b.PageTitle)
	}
}

func TestParseLogos(t *testing.T) {
	// Unset keeps the shipped band; "[]" removes it. The difference is
	// nil against empty, and the whole footer policy turns on it.
	if got, err := ParseLogos("  "); err != nil || got != nil {
		t.Errorf("ParseLogos(unset) = %v, %v; want nil, nil", got, err)
	}
	got, err := ParseLogos("[]")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf(`ParseLogos("[]") = %v; want an empty, non-nil list`, got)
	}

	got, err = ParseLogos(`[{"src":"/branding/af.svg","alt":"ATLAS AF","href":"https://af.example/"},
	                        {"src":"https://cdn.example/uc.png","alt":"UChicago"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Href != "https://af.example/" || got[1].Src != "https://cdn.example/uc.png" {
		t.Fatalf("ParseLogos = %+v", got)
	}
}

func TestParseLogosRefusesUnusableEntries(t *testing.T) {
	for name, raw := range map[string]string{
		"not an array":        `{"src":"/a.svg","alt":"A"}`,
		"no src":              `[{"alt":"A"}]`,
		"no alt":              `[{"src":"/a.svg"}]`,
		"script URL in src":   `[{"src":"javascript:alert(1)","alt":"A"}]`,
		"script URL in href":  `[{"src":"/a.svg","alt":"A","href":"javascript:alert(1)"}]`,
		"data URL":            `[{"src":"data:image/svg+xml;base64,PHN2Zz4=","alt":"A"}]`,
		"protocol-relative":   `[{"src":"//evil.example/a.svg","alt":"A"}]`,
		"scheme-less host":    `[{"src":"evil.example/a.svg","alt":"A"}]`,
		"newline in the href": "[{\"src\":\"/a.svg\",\"alt\":\"A\",\"href\":\"https://x\\n/y\"}]",
	} {
		if got, err := ParseLogos(raw); err == nil {
			t.Errorf("%s: ParseLogos(%s) = %+v, want an error", name, raw, got)
		}
	}
}

// A logo list that does not parse costs the site its logos and nothing
// else: the name it configured in the same file still applies, and the
// footer falls back to the shipped band.
func TestBuildKeepsTheRestWhenTheLogosAreWrong(t *testing.T) {
	b, err := Build(Options{SiteName: "ATLAS AF", FooterLogos: `[{"src":"/a.svg"}]`})
	if err == nil {
		t.Fatal("Build did not report the unusable logo list")
	}
	if !strings.Contains(err.Error(), "alt") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
	if b.SiteName != "ATLAS AF" {
		t.Errorf("SiteName = %q; the name should survive a bad logo list", b.SiteName)
	}
	if b.FooterLogos != nil || b.SoftwareCredit {
		t.Errorf("FooterLogos = %+v, SoftwareCredit = %v; want the shipped band", b.FooterLogos, b.SoftwareCredit)
	}
}

// The credit line is what keeps HTCondor and CHTC named on a site that
// put its own logos in the footer -- including one that configured an
// empty band to have no logos at all.
func TestSoftwareCreditFollowsTheConfiguredBand(t *testing.T) {
	for raw, want := range map[string]bool{
		"":                                 false,
		"[]":                               true,
		`[{"src":"/b/af.svg","alt":"AF"}]`: true,
	} {
		b, err := Build(Options{FooterLogos: raw})
		if err != nil {
			t.Fatal(err)
		}
		if b.SoftwareCredit != want {
			t.Errorf("FOOTER_LOGOS=%q: SoftwareCredit = %v, want %v", raw, b.SoftwareCredit, want)
		}
	}
}

func TestInject(t *testing.T) {
	page := []byte(`<!DOCTYPE html><html><head><title>HTCondor Access Point</title>` +
		`<link rel="icon" href="/icon.svg?abc"/><link rel="stylesheet" href="/_next/app.css"/>` +
		`</head><body><div id="x">HTCondor</div></body></html>`)
	b, err := Build(Options{
		SiteName:    "ATLAS AF",
		FooterLogos: `[{"src":"/branding/af.svg","alt":"ATLAS AF"}]`,
		Favicon:     "/branding/af.ico",
		CustomCSS:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	b.Rev = 7
	got := string(b.Inject(page))

	if !strings.Contains(got, "<title>ATLAS AF</title>") || strings.Contains(got, "<title>HTCondor Access Point</title>") {
		t.Errorf("the title was not replaced:\n%s", got)
	}
	// One icon link, the site's: two would leave the browser to choose.
	if n := strings.Count(got, `rel="icon"`); n != 1 || !strings.Contains(got, `href="/branding/af.ico"`) {
		t.Errorf("icon links = %d:\n%s", n, got)
	}
	if !strings.Contains(got, `<link rel="stylesheet" href="/branding.css?rev=7"/></head>`) {
		t.Errorf("the site stylesheet is not the last thing in the head:\n%s", got)
	}
	// The app's own stylesheet still comes first, which is what lets the
	// site's override the brand colours.
	if strings.Index(got, "/_next/app.css") > strings.Index(got, "/branding.css") {
		t.Errorf("the site stylesheet is loaded before the app's:\n%s", got)
	}
	if !strings.Contains(got, `<div id="x">HTCondor</div></body>`) {
		t.Errorf("the body was touched:\n%s", got)
	}

	// The page carries the branding as a global, so the SPA has it
	// before its first render.
	_, script, ok := strings.Cut(got, "window."+brandingGlobal+"=")
	if !ok {
		t.Fatalf("the page carries no branding:\n%s", got)
	}
	script, _, ok = strings.Cut(script, ";</script>")
	if !ok {
		t.Fatalf("the injected script is unterminated:\n%s", got)
	}
	var round Branding
	if err := json.Unmarshal([]byte(script), &round); err != nil {
		t.Fatalf("the injected global is not JSON: %v\n%s", err, script)
	}
	if round.SiteName != "ATLAS AF" || len(round.FooterLogos) != 1 || !round.SoftwareCredit || !round.CustomCSS {
		t.Errorf("the injected branding = %+v", round)
	}
}

// A name holding HTML cannot close the script element it is injected
// into, nor open a tag in the title.
func TestInjectEscapes(t *testing.T) {
	b, err := Build(Options{SiteName: `</script><img src=x onerror=alert(1)>`})
	if err != nil {
		t.Fatal(err)
	}
	got := string(b.Inject([]byte("<html><head><title>t</title></head><body></body></html>")))
	// One </script>, the one Inject opened: the name did not close it.
	if strings.Contains(got, "<img src=x") || strings.Count(got, "</script>") != 1 {
		t.Errorf("the injected page escaped its context:\n%s", got)
	}
	if !strings.Contains(got, "&lt;/script&gt;") {
		t.Errorf("the title was not escaped:\n%s", got)
	}
}

func TestInjectLeavesAPageWithNoHeadAlone(t *testing.T) {
	b, _ := Build(Options{SiteName: "ATLAS AF"})
	page := []byte("<html><body>no head here</body></html>")
	if got := b.Inject(page); string(got) != string(page) {
		t.Errorf("Inject rewrote a page with no head:\n%s", got)
	}
}
