package siteapps

import (
	_ "embed"
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
// above it. Declining costs that app the switcher and the way back,
// which is why the switcher at /site/ is always a link away and always
// correct.
//
// The script carries this selector too; they are kept in step by
// TestShellHonoursTheDeclineMeta rather than by concatenation, so the
// overlay stays a file a browser and a linter can read.
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

// shellJS is the overlay: where you are, the caller's other apps, and
// the way back to the full console, rendered into a shadow root.
//
// A file rather than a Go string literal: it is JavaScript, and a
// stylesheet, and it is tested in a browser-like environment by
// webapi/frontend/src/lib/siteAppShell.test.ts, all of which want real
// source rather than a quoted blob. It is embedded so the binary still
// carries everything it serves.
//
// It renders for every authenticated viewer. The previous version drew
// nothing unless there were other apps to list or an expert door to
// offer, which stranded the commonest case there is: one published app
// and a user who has the whole console, with no link back to it.
//
//go:embed shell.js
var shellJS string
