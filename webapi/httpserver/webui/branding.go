package webui

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Site branding: what a deployment that is not CHTC's may change about
// the web UI without forking it.
//
// The UI is a static export compiled into this binary, so none of it can
// be edited in place. What the server can do is tell the page, at the
// moment it serves it, what to call itself and what to put in its footer
// -- and serve the site's own logos and stylesheet alongside. That is
// what this file models: a small, validated value, injected into the HTML
// head and also offered as JSON at /api/v1/webui/branding.
//
// A deployment that configures none of it gets exactly the pages the UI
// ships with: the default value injects nothing at all, because the SPA's
// own built-in defaults are these same values.

// Default presentation, matching what the frontend hard-codes.
const (
	DefaultSiteName    = "HTCondor"
	DefaultSiteTagline = "Access Point"
)

// CSSPath is where the site stylesheet is served, when there is one.
const CSSPath = "/branding.css"

// Logo is one image in the footer's institutional band.
type Logo struct {
	// Src is the image URL: site-relative ("/branding/af.svg", normally
	// something out of HTTP_API_WEBUI_BRANDING_DIR) or absolute http(s).
	Src string `json:"src"`
	// Alt is the text a screen reader reads and a broken image shows.
	// Required: an unlabelled institutional logo tells a blind user
	// nothing about who runs the service.
	Alt string `json:"alt"`
	// Href, when set, makes the logo a link.
	Href string `json:"href,omitempty"`
}

// Branding is the resolved presentation of one deployment's web UI.
type Branding struct {
	// SiteName is the sidebar heading, SiteTagline the line beneath it,
	// and PageTitle the browser tab -- the two joined.
	SiteName    string `json:"site_name"`
	SiteTagline string `json:"site_tagline"`
	PageTitle   string `json:"page_title"`
	// FooterLogos is the institutional band at the foot of every page.
	// Nil is the band the UI ships with (CHTC, Morgridge, UW-Madison);
	// an empty list is no logos at all.
	FooterLogos []Logo `json:"footer_logos"`
	// SoftwareCredit asks the footer for its one-line "Powered by
	// HTCondor" credit, naming the Center for High Throughput Computing.
	// Set whenever the shipped logo band is not shown, so who wrote the
	// software is still said on every page -- and distinguished from who
	// runs the service, which is what the band above it says.
	SoftwareCredit bool `json:"software_credit"`
	// Favicon replaces the HTCondor mark in the browser tab.
	Favicon string `json:"favicon,omitempty"`
	// CustomCSS reports that this server serves a site stylesheet at
	// /branding.css, loaded after the page's own.
	CustomCSS bool `json:"custom_css,omitempty"`

	// Rev changes whenever anything above does. It busts the injected
	// HTML cache and the stylesheet's URL after a reconfigure.
	Rev uint64 `json:"-"`
}

// DefaultBranding is the presentation of an unconfigured deployment.
func DefaultBranding() Branding {
	return Branding{
		SiteName:    DefaultSiteName,
		SiteTagline: DefaultSiteTagline,
		PageTitle:   DefaultSiteName + " " + DefaultSiteTagline,
	}
}

// IsDefault reports that nothing about this branding differs from what
// the frontend already hard-codes, so the server has nothing to say and
// serves the exported HTML byte for byte.
func (b Branding) IsDefault() bool {
	d := DefaultBranding()
	return b.FooterLogos == nil && !b.SoftwareCredit &&
		b.Favicon == "" && !b.CustomCSS &&
		b.SiteName == d.SiteName && b.SiteTagline == d.SiteTagline &&
		b.PageTitle == d.PageTitle
}

// Options are the raw configured values, as they come out of the
// configuration file.
type Options struct {
	SiteName    string
	SiteTagline string
	// FooterLogos is a JSON array of {"src","alt","href"}. Empty keeps
	// the shipped band; "[]" removes it.
	FooterLogos string
	Favicon     string
	// CustomCSS reports that HTTP_API_WEBUI_CUSTOM_CSS names a readable
	// stylesheet. Resolving the path is the caller's job; this only
	// decides whether the page links to it.
	CustomCSS bool
}

// Build resolves configured values into a Branding.
//
// Every part is independent, and a part that does not parse falls back to
// the shipped default rather than taking the rest of the branding down
// with it: a typo in the logo list should cost a site its logos, not its
// web UI. The error names every such fallback, for the caller to log.
func Build(o Options) (Branding, error) {
	b := DefaultBranding()
	var problems []string

	if name := strings.TrimSpace(o.SiteName); name != "" {
		b.SiteName = name
	}
	// Distinguishable from unset: a site whose name says "access point"
	// already does not want it said twice.
	if tag := strings.TrimSpace(o.SiteTagline); tag != "" {
		b.SiteTagline = tag
	} else if strings.TrimSpace(o.SiteName) != "" {
		b.SiteTagline = ""
	}
	b.PageTitle = strings.TrimSpace(b.SiteName + " " + b.SiteTagline)

	logos, err := ParseLogos(o.FooterLogos)
	if err != nil {
		problems = append(problems, fmt.Sprintf("footer logos (%v); keeping the shipped band", err))
	} else {
		b.FooterLogos = logos
	}
	b.SoftwareCredit = b.FooterLogos != nil

	if fav := strings.TrimSpace(o.Favicon); fav != "" {
		if assetURLOK(fav) {
			b.Favicon = fav
		} else {
			problems = append(problems, fmt.Sprintf("favicon %q is not a site-relative or http(s) URL; keeping the HTCondor mark", fav))
		}
	}
	b.CustomCSS = o.CustomCSS

	if len(problems) > 0 {
		return b, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return b, nil
}

// ParseLogos reads the configured footer band.
//
// Returns nil for an unset value -- the shipped band -- and a non-nil
// empty slice for "[]", which is a site saying it wants no logos.
func ParseLogos(raw string) ([]Logo, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var in []Logo
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("not a JSON array of {\"src\",\"alt\",\"href\"}: %w", err)
	}
	out := make([]Logo, 0, len(in))
	for i, l := range in {
		l.Src = strings.TrimSpace(l.Src)
		l.Alt = strings.TrimSpace(l.Alt)
		l.Href = strings.TrimSpace(l.Href)
		switch {
		case l.Src == "":
			return nil, fmt.Errorf("logo %d has no src", i+1)
		case !assetURLOK(l.Src):
			return nil, fmt.Errorf("logo %d: src %q is not a site-relative or http(s) URL", i+1, l.Src)
		case l.Alt == "":
			return nil, fmt.Errorf("logo %d (%s) has no alt text", i+1, l.Src)
		case l.Href != "" && !assetURLOK(l.Href):
			return nil, fmt.Errorf("logo %d: href %q is not a site-relative or http(s) URL", i+1, l.Href)
		}
		out = append(out, l)
	}
	return out, nil
}

// assetURLOK reports whether a configured URL is one this UI will put in
// a src or an href.
//
// Site-relative paths and absolute http(s) only. The point is the
// schemes it leaves out: these strings reach an <a href> and an <img
// src>, so "javascript:" and "data:" are kept out of them even though
// the value came from the operator's own configuration file -- the
// operator pasting a logo URL from a vendor is not auditing it.
func assetURLOK(raw string) bool {
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n\t ") {
		return false
	}
	// Protocol-relative ("//host/x") inherits the page's scheme and is
	// not a site-relative path, so require a single leading slash.
	if strings.HasPrefix(raw, "/") {
		return !strings.HasPrefix(raw, "//")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// --- Injection into the served HTML -------------------------------------

// brandingGlobal is where the SPA reads its branding synchronously, before
// the first render, so a site's own name is never preceded by a frame of
// "HTCondor".
const brandingGlobal = "__HTCONDOR_BRANDING__"

var (
	titleRe    = regexp.MustCompile(`(?is)<title[^>]*>.*?</title>`)
	iconLinkRe = regexp.MustCompile(`(?is)<link[^>]*\srel=["']?(?:shortcut )?icon["']?[^>]*>`)
	headEndRe  = regexp.MustCompile(`(?i)</head>`)
)

// Inject rewrites one exported HTML page to carry this branding.
//
// Three edits, all inside <head>: the title, the favicon link, and a
// trailing block with the branding as a JavaScript global plus the site
// stylesheet. The stylesheet goes last on purpose -- it is loaded after
// the app's own, which is what lets a site redefine the --color-brand-*
// variables and recolour the whole UI.
//
// A page with no </head> is returned untouched; there is no such page in
// the export, and guessing where to put the block would be worse than
// leaving the site unbranded.
func (b Branding) Inject(page []byte) []byte {
	if b.IsDefault() {
		return page
	}
	end := headEndRe.FindIndex(page)
	if end == nil {
		return page
	}

	// Everything is spliced into the head; the rest of the document --
	// the body and the scripts Next put after it -- is untouched.
	out := append([]byte(nil), page[:end[0]]...)
	tail := page[end[0]:]

	if b.PageTitle != "" {
		if loc := titleRe.FindIndex(out); loc != nil {
			out = append(out[:loc[0]:loc[0]],
				append([]byte("<title>"+escapeHTMLText(b.PageTitle)+"</title>"), out[loc[1]:]...)...)
		}
	}
	if b.Favicon != "" {
		// Replaced rather than added: two icon links leave the browser
		// to choose, and it does not always choose the later one.
		out = iconLinkRe.ReplaceAll(out, nil)
		out = append(out, []byte(`<link rel="icon" href="`+escapeHTMLAttr(b.Favicon)+`"/>`)...)
	}

	// json.Marshal escapes <, > and & inside strings, so the payload
	// cannot close this script element.
	payload, err := json.Marshal(b)
	if err != nil {
		// Branding is a handful of validated strings; this cannot fail.
		// If it somehow does, an unbranded page beats a broken one.
		return page
	}
	out = append(out, []byte("<script>window."+brandingGlobal+"="+string(payload)+";</script>")...)
	if b.CustomCSS {
		out = append(out, fmt.Sprintf(`<link rel="stylesheet" href="%s?rev=%d"/>`, CSSPath, b.Rev)...)
	}
	return append(out, tail...)
}

func escapeHTMLText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func escapeHTMLAttr(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}
