package webui

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

// An Option configures the SPA handler.
type Option func(*spaHandler)

// WithBranding gives the handler a source of site branding to splice
// into every HTML page it serves (see Branding.Inject). The function is
// called per request, so a reconfigure takes effect on the next page
// load; it may return the default branding, which injects nothing.
func WithBranding(f func() Branding) Option {
	return func(h *spaHandler) { h.branding = f }
}

// spaHandler serves the embedded export, with the site's branding
// spliced into the HTML.
type spaHandler struct {
	fsys     fs.FS
	branding func() Branding

	// Branded HTML, keyed by path. Rebuilt whenever the branding's
	// revision changes, which is only at startup and on a reconfigure.
	mu       sync.Mutex
	rev      uint64
	rendered map[string][]byte
}

// NewSPAHandler returns an http.Handler that serves the embedded frontend.
// It resolves Next.js static-export dynamic routes (e.g. [id] -> _) and
// falls back to index.html for client-side routing.
//
// When the frontend is not embedded (no embed_frontend build tag), the
// returned handler responds with 404 so the caller can fall back to a
// non-SPA welcome page.
func NewSPAHandler(opts ...Option) http.Handler {
	fsys, _ := DistFS()
	if fsys == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Frontend not embedded in this build", http.StatusNotFound)
		})
	}
	h := &spaHandler{fsys: fsys, rendered: map[string][]byte{}}
	for _, o := range opts {
		o(h)
	}
	return h
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fsys := h.fsys
	urlPath := strings.TrimPrefix(r.URL.Path, "/")
	if urlPath == "" {
		urlPath = "index.html"
	}

	// 1. Exact file (static assets, known pages).
	if fileExists(fsys, urlPath) {
		h.serve(w, r, urlPath)
		return
	}

	// 2. With .html extension (e.g. /jobs -> jobs.html).
	if !strings.Contains(path.Base(urlPath), ".") {
		if fileExists(fsys, urlPath+".html") {
			h.serve(w, r, urlPath+".html")
			return
		}
	}

	// 3. Next.js dynamic routes: replace non-matching segments with _.
	if resolved := resolveDynamicRoute(fsys, urlPath); resolved != "" {
		h.serve(w, r, resolved)
		return
	}

	// 4. SPA fallback for client-side routing.
	h.serve(w, r, "index.html")
}

// serve hands one export file to the client, branded if it is a page and
// the site configured any branding.
func (h *spaHandler) serve(w http.ResponseWriter, r *http.Request, name string) {
	if h.branding == nil || !strings.HasSuffix(name, ".html") {
		serveFile(w, r, h.fsys, name)
		return
	}
	b := h.branding()
	if b.IsDefault() {
		serveFile(w, r, h.fsys, name)
		return
	}
	page, ok := h.branded(name, b)
	if !ok {
		serveFile(w, r, h.fsys, name)
		return
	}
	// The export carries no useful modification time (embed zeroes it),
	// so there is none to hand the client here either; ServeContent
	// still sets the content type and answers a Range.
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(page))
}

// branded returns the page with the branding spliced in, rendering it on
// first use and keeping it until the branding changes. The export has a
// few dozen HTML files of a few kilobytes each.
func (h *spaHandler) branded(name string, b Branding) ([]byte, bool) {
	if !isSafeEmbeddedPath(name) {
		return nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rev != b.Rev {
		h.rev, h.rendered = b.Rev, map[string][]byte{}
	}
	if page, ok := h.rendered[name]; ok {
		return page, true
	}
	raw, err := fs.ReadFile(h.fsys, name)
	if err != nil {
		return nil, false
	}
	page := b.Inject(raw)
	h.rendered[name] = page
	return page, true
}

// resolveDynamicRoute attempts to match a URL path against Next.js static
// export dynamic route files. For [param] routes, Next.js generates files
// using _ as the placeholder (e.g. jobs/[id] -> jobs/_.html).
func resolveDynamicRoute(fsys fs.FS, urlPath string) string {
	suffix := ".html"
	if strings.HasSuffix(urlPath, ".txt") {
		suffix = ".txt"
		urlPath = strings.TrimSuffix(urlPath, ".txt")
	}

	segments := strings.Split(urlPath, "/")
	if len(segments) == 0 {
		return ""
	}

	resolved := make([]string, 0, len(segments))
	for i, seg := range segments {
		isLast := i == len(segments)-1

		if isLast {
			for _, candidate := range []string{seg, "_"} {
				filePath := strings.Join(append(resolved, candidate), "/") + suffix
				if fileExists(fsys, filePath) {
					return filePath
				}
			}
			return ""
		}

		literalDir := strings.Join(append(resolved, seg), "/")
		wildcardDir := strings.Join(append(resolved, "_"), "/")

		switch {
		case dirExists(fsys, literalDir):
			resolved = append(resolved, seg)
		case dirExists(fsys, wildcardDir):
			resolved = append(resolved, "_")
		default:
			return ""
		}
	}

	return ""
}

func fileExists(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return !stat.IsDir()
}

func dirExists(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.IsDir()
}

// serveFile is the single chokepoint for handing a path to
// http.ServeFileFS. The embed.FS we serve from already rejects
// "../" segments, but gosec G703 flags any user-controlled string
// that flows into a file-serving function regardless. Validate
// explicitly here so the security guarantee is local to this
// function rather than implicit in the FS implementation: only
// names that pass path.Clean unchanged AND contain no "..", "//",
// or leading "/" are served. Anything else gets a 404.
//
// In practice the callers (NewSPAHandler, resolveDynamicRoute)
// produce only safe names — they're built from the embed manifest
// after a fileExists check. The validation here is defense in
// depth.
func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	if !isSafeEmbeddedPath(name) {
		http.NotFound(w, r)
		return
	}
	// gosec G703: name is validated by isSafeEmbeddedPath above; the
	// taint tracker doesn't follow the check across the function
	// boundary. The validation rejects "..", absolute paths, NULs,
	// and anything path.Clean would alter — embed.FS rejects them
	// all anyway, so this is defense in depth.
	http.ServeFileFS(w, r, fsys, name) //nolint:gosec
}

// isSafeEmbeddedPath reports whether name is safe to pass to
// http.ServeFileFS over an embed.FS rooted at the package's dist
// directory. The rules: relative path, no ".." segments, no
// double-slashes, no NUL bytes. A nonzero name is required.
func isSafeEmbeddedPath(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "/") {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	if strings.Contains(name, "//") {
		return false
	}
	if strings.ContainsRune(name, 0) {
		return false
	}
	if path.Clean(name) != name {
		return false
	}
	return true
}
