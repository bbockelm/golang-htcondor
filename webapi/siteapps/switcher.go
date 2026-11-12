package siteapps

import (
	"html/template"
	"net/http"
)

// switcherData is what the switcher template renders.
type switcherData struct {
	Apps []switcherApp
	// DashboardURL is the way back to the general-purpose console. It
	// is always offered: the switcher is also where somebody lands who
	// followed a bookmark into an app they no longer have, and a page
	// with no way onward is worse than a 404.
	DashboardURL string
}

type switcherApp struct {
	Name        string
	Description string
	URL         string
	Home        bool
}

// serveSwitcher renders the caller's apps at /site/.
//
// Server-rendered, with no build step and no JavaScript, because it has
// to work for the one case that matters most: somebody in two groups,
// following a link from their PI, who needs to land somewhere they can
// read. It is also the right thing to bookmark or paste into a lab
// wiki, since it resolves per-viewer -- the same URL sends each person
// to their own set.
func (h *Handler) serveSwitcher(w http.ResponseWriter, r *http.Request) {
	caller := h.identify(r)
	if !caller.Authenticated {
		h.login(w, r)
		return
	}

	entries := h.lib.VisibleTo(caller.Groups)
	data := switcherData{DashboardURL: "/", Apps: make([]switcherApp, 0, len(entries))}
	for _, e := range entries {
		data.Apps = append(data.Apps, switcherApp{
			Name:        e.App.Name,
			Description: e.App.Description,
			URL:         MountPath(e.App.ID),
			Home:        e.App.Home,
		})
	}

	// Listing which apps exist is itself scoped: this page shows only
	// what the caller could already open, so it leaks nothing the gate
	// would not.
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Cookie")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := switcherTmpl.Execute(w, data); err != nil {
		// The response is already begun, so there is nothing useful to
		// say to the client; the handler's logger is not reachable from
		// here and a half-rendered page is its own signal.
		return
	}
}

// switcherTmpl is html/template, so every app name and description a
// site wrote is escaped on the way out. These come from manifests an
// operator deployed rather than from a user, which makes them trusted
// input and not safe input.
var switcherTmpl = template.Must(template.New("switcher").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your apps</title>
<style>
:root{--bg:#fff;--fg:#1a1d21;--muted:#5c6670;--line:#d9dee3;--accent:#1f6feb;color-scheme:light dark}
@media(prefers-color-scheme:dark){:root{--bg:#15181c;--fg:#e6e9ec;--muted:#9aa4af;--line:#2b3137;--accent:#4d8ef7}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.5}
main{max-width:40rem;margin:0 auto;padding:3rem 1rem}
h1{font-size:1.5rem;margin:0 0 .25rem}
p.lede{color:var(--muted);margin:0 0 2rem}
ul{list-style:none;padding:0;margin:0}
li{margin-bottom:.75rem}
a.app{display:block;padding:1rem;border:1px solid var(--line);border-radius:8px;text-decoration:none;color:inherit}
a.app:hover,a.app:focus{border-color:var(--accent);outline:none}
a.app .name{font-weight:600}
a.app .desc{color:var(--muted);font-size:.9rem}
.badge{font-size:.75rem;color:var(--accent);border:1px solid var(--accent);border-radius:999px;padding:.05rem .5rem;margin-left:.5rem}
.foot{margin-top:2rem;font-size:.9rem}
.foot a{color:var(--accent)}
.empty{padding:1rem;border:1px dashed var(--line);border-radius:8px;color:var(--muted)}
</style>
</head>
<body>
<main>
<h1>Your apps</h1>
{{if .Apps}}
<p class="lede">Choose where to go.</p>
<ul>
{{range .Apps}}
<li><a class="app" href="{{.URL}}">
<span class="name">{{.Name}}{{if .Home}}<span class="badge">Home</span>{{end}}</span>
{{if .Description}}<div class="desc">{{.Description}}</div>{{end}}
</a></li>
{{end}}
</ul>
{{else}}
<p class="lede">You do not have access to any apps on this access point.</p>
<div class="empty">If you were expecting one, ask whoever sent you the link which group it is shared with.</div>
{{end}}
<p class="foot"><a href="{{.DashboardURL}}">Go to the full HTCondor console</a></p>
</main>
</body>
</html>
`))
