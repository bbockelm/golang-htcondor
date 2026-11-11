package siteapps

import (
	"net/http"
	"strings"
	"time"
)

// shellPath is where the overlay script is served. Reserved: ValidateID
// refuses an id beginning with "_", so no bundle can shadow it.
const shellPath = "/site/_shell.js"

// shellMeta lets an app decline the overlay.
//
// An app with its own fixed header may not survive a bar being put
// above it. Declining costs that app the switcher, which is why the
// switcher at /site/ is always a link away and always correct.
const shellMeta = `name="htcondor-shell"`

// serveShell hands out the overlay script.
//
// Served to any authenticated caller rather than gated per app: it
// contains no site content, and it fetches /api/v1/auth/me itself,
// which is where the group filtering actually happens. Gating the
// script per app would also mean a different URL per app and a cache
// miss on every switch.
func (h *Handler) serveShell(w http.ResponseWriter, r *http.Request) {
	if caller := h.identify(r); !caller.Authenticated {
		// Not a redirect: this is a subresource of a page, and sending
		// a 302 to the login HTML would have the browser parse markup
		// as JavaScript. 204 leaves the page without a bar, which is
		// the right failure -- the page itself will have redirected.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	// Private, because which apps a viewer has is theirs; but
	// cacheable for a short while, since every page of every app pulls
	// it and the answer only changes when an operator redeploys.
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Header().Set("Vary", "Cookie")
	http.ServeContent(w, r, "_shell.js", shellModTime, strings.NewReader(shellJS))
}

// shellModTime is fixed, so conditional requests work and the script
// does not appear to change on every restart.
var shellModTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// shellJS is the overlay: an app switcher and the expert-mode door,
// rendered into a shadow root.
//
// Shadow DOM is the whole reason this is tolerable. The bar lives
// inside a page somebody else wrote, with CSS we have never seen; a
// shadow root means their styles cannot reach in and ours cannot leak
// out, so we are not negotiating specificity with a stranger's build.
//
// It renders NOTHING unless there is somewhere to go: one app and no
// expert door is the common case, and a bar that only says where you
// already are is clutter.
const shellJS = `(function () {
  "use strict";
  if (window.__HTCONDOR_SHELL__) return;
  window.__HTCONDOR_SHELL__ = true;

  var meta = document.querySelector('meta[` + shellMeta + `]');
  if (meta && meta.content === "none") return;

  function h(tag, props, kids) {
    var el = document.createElement(tag);
    for (var k in props) if (props[k] != null) el.setAttribute(k, props[k]);
    (kids || []).forEach(function (c) {
      el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return el;
  }

  fetch("/api/v1/auth/me", { credentials: "include" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (me) {
      if (!me || !me.authenticated) return;
      var apps = me.site_apps || [];
      var here = (window.__HTCONDOR_APP__ || {}).id;
      var others = apps.filter(function (a) { return a.id !== here; });
      var canLeave = !!me.app_only;
      // Nowhere to go: no bar. A strip that only names the page you
      // are on is noise in somebody else's interface.
      if (others.length === 0 && !canLeave) return;

      var host = document.createElement("div");
      host.setAttribute("data-htcondor-shell", "");
      var root = host.attachShadow({ mode: "open" });

      var style = document.createElement("style");
      style.textContent =
        ":host{all:initial}" +
        ".bar{position:fixed;top:0;left:0;right:0;height:36px;z-index:2147483000;" +
        "display:flex;align-items:center;gap:.75rem;padding:0 .75rem;box-sizing:border-box;" +
        "font:13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;" +
        "background:#15181c;color:#e6e9ec;border-bottom:1px solid #2b3137}" +
        ".name{font-weight:600;margin-right:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}" +
        "a{color:#9aa4af;text-decoration:none;padding:.2rem .5rem;border-radius:4px;white-space:nowrap}" +
        "a:hover,a:focus{background:rgba(255,255,255,.1);color:#fff;outline:none}";
      root.appendChild(style);

      var bar = h("div", { class: "bar", role: "navigation", "aria-label": "HTCondor apps" }, [
        h("span", { class: "name" }, [(window.__HTCONDOR_APP__ || {}).name || "Apps"]),
      ]);
      others.slice(0, 4).forEach(function (a) {
        bar.appendChild(h("a", { href: a.url }, [a.name]));
      });
      if (others.length > 4) bar.appendChild(h("a", { href: "/site/" }, ["All apps"]));
      if (canLeave) bar.appendChild(h("a", { href: "/site/expert" }, ["Expert mode"]));
      root.appendChild(bar);

      document.body.appendChild(host);
      // Tell the page how much room the bar took, and nudge it clear.
      // An app that cares reads the variable; one that does not still
      // gets its first 36px back.
      var de = document.documentElement;
      de.style.setProperty("--htcondor-shell-height", "36px");
      de.style.setProperty("scroll-padding-top", "36px");
      if (!document.body.style.paddingTop) document.body.style.paddingTop = "36px";
    })
    .catch(function () { /* no bar is better than a broken page */ });
})();
`
