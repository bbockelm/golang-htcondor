package siteapps

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MountPath is where an app is served, with a trailing slash.
func MountPath(id string) string { return "/site/" + id + "/" }

// appGlobal is what the page sees as window.__HTCONDOR_APP__.
type appGlobal struct {
	ID   string `json:"id"`
	Base string `json:"base"`
	Name string `json:"name"`
}

// HeadHTML is the block spliced into every page a site app serves.
//
// It answers the one question a bundle cannot answer for itself: where
// am I mounted? The id is the file name an operator gave the zip, so
// the same bundle may be served at /site/cryoem/ or /site/cryoem-next/
// and a base path baked in at build time would be wrong for one of
// them.
//
// Two mechanisms, because they serve different consumers. <base href>
// resolves relative asset URLs, which is what lets a bundle build with
// base: './' and work anywhere. window.__HTCONDOR_APP__ gives the
// client-side router the prefix as a string, which <base> cannot do --
// and which an app must not infer from location.pathname, since a
// route like /site/cryoem/jobs/12 is indistinguishable from a deeper
// mount point.
//
// The inline script is permitted by the server's CSP, which already
// allows 'unsafe-inline' for scripts because the Next.js static export
// depends on it.
func HeadHTML(app App) ([]byte, error) {
	base := MountPath(app.ID)
	payload, err := json.Marshal(appGlobal{ID: app.ID, Base: base, Name: app.Name})
	if err != nil {
		return nil, fmt.Errorf("encode the app global: %w", err)
	}

	var b strings.Builder
	b.WriteString(`<base href="`)
	b.WriteString(escapeAttr(base))
	b.WriteString(`">`)
	b.WriteString(`<script>window.__HTCONDOR_APP__=`)
	// JSON is not script-safe on its own: "</script>" inside a string
	// value ends the element early, and U+2028/U+2029 are line
	// terminators to a JavaScript parser but legal inside a JSON
	// string. The name comes from a manifest the site wrote, so this
	// is not a hostile input, but it is an input.
	b.WriteString(escapeScriptJSON(string(payload)))
	b.WriteString(`;</script>`)
	return []byte(b.String()), nil
}

// escapeAttr escapes a value for a double-quoted HTML attribute.
func escapeAttr(s string) string {
	r := strings.NewReplacer("&", "&amp;", `"`, "&quot;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// escapeScriptJSON makes a JSON document safe to embed in a <script>.
func escapeScriptJSON(s string) string {
	r := strings.NewReplacer(
		"<", `<`,
		">", `>`,
		"&", `&`,
		" ", ` `,
		" ", ` `,
	)
	return r.Replace(s)
}
