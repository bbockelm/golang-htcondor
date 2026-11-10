package httpserver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/webui"
)

// Site branding for the web UI.
//
// The pages are a static export compiled into this binary, so a site that
// is not CHTC cannot change what they say about who runs the service
// without forking the build. These settings let the server say it
// instead: the name in the sidebar and the tab, the logos in the footer,
// a stylesheet of the site's own, and a directory its images come out of.
//
// Everything here is read on a request and nothing is constructed from
// it, so all of it is reloadable with condor_reconfig -- which is what an
// operator trying a logo out wants.
const (
	// brandingPath is the unauthenticated endpoint the SPA falls back to
	// when it was not served by this server (a `next dev` session, or
	// the exported files served statically in tests).
	brandingPath = "/api/v1/webui/branding"
	// brandingAssetPrefix is where HTTP_API_WEBUI_BRANDING_DIR is served.
	brandingAssetPrefix = "/branding/"
	// brandingCSSMaxBytes caps the site stylesheet. It is read into
	// memory on each request; a stylesheet is kilobytes, and the cap is
	// what stops a mistyped path from serving something that is not.
	brandingCSSMaxBytes = 1 << 20
)

// brandingAssetTypes is what HTTP_API_WEBUI_BRANDING_DIR may serve.
//
// An allowlist rather than content sniffing, because this directory is
// same-origin with the whole UI: an .html or .js file dropped in it
// alongside the logos would run with the session's cookies. Images,
// fonts and stylesheets cannot, so those are what it serves. (SVG is the
// exception people reach for -- it can carry script -- but only when
// opened as a document in its own tab, not as an <img>, and a logo
// without SVG is not much of a logo.)
var brandingAssetTypes = map[string]string{
	".avif":  "image/avif",
	".css":   "text/css; charset=utf-8",
	".gif":   "image/gif",
	".ico":   "image/vnd.microsoft.icon",
	".jpeg":  "image/jpeg",
	".jpg":   "image/jpeg",
	".png":   "image/png",
	".svg":   "image/svg+xml",
	".webp":  "image/webp",
	".woff":  "font/woff",
	".woff2": "font/woff2",
}

// brandingOptions are the configured values, as read from the file.
type brandingOptions struct {
	SiteName    string
	SiteTagline string
	FooterLogos string
	Favicon     string
	Dir         string
	CSSFile     string
}

// brandingSnapshot is one resolved configuration: what the pages are
// told, and the two paths the server reads from to back it.
type brandingSnapshot struct {
	branding webui.Branding
	dir      string
	cssFile  string
	// imgSrc is the space-separated list of absolute origins the site's
	// images come from, added to the img-src of every response's
	// Content-Security-Policy. Empty when every image is site-relative,
	// which is the usual case and the one the branding directory is
	// for.
	imgSrc string
}

// brandingState holds the live branding. Requests read it through an
// atomic pointer; a reconfigure replaces it whole, under the mutex that
// also guards the raw values each setter updates one of.
type brandingState struct {
	logger *logging.Logger

	mu   sync.Mutex
	opts brandingOptions

	rev atomic.Uint64
	cur atomic.Pointer[brandingSnapshot]
}

func newBrandingState(logger *logging.Logger, opts brandingOptions) *brandingState {
	s := &brandingState{logger: logger, opts: opts}
	s.rebuild()
	return s
}

// update applies one changed setting and rebuilds.
func (s *brandingState) update(f func(*brandingOptions)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.opts)
	s.rebuild()
}

// rebuild resolves the raw values. Caller holds mu, except in
// newBrandingState where nothing else can see the state yet.
func (s *brandingState) rebuild() {
	o := s.opts
	snap := &brandingSnapshot{
		dir:     strings.TrimSpace(o.Dir),
		cssFile: strings.TrimSpace(o.CSSFile),
	}
	if snap.dir != "" {
		if fi, err := os.Stat(snap.dir); err != nil || !fi.IsDir() {
			s.warn("HTTP_API_WEBUI_BRANDING_DIR is not a readable directory; the site's images will 404",
				"dir", snap.dir, "error", err)
		}
	}
	if snap.cssFile != "" {
		if fi, err := os.Stat(snap.cssFile); err != nil || fi.IsDir() {
			s.warn("HTTP_API_WEBUI_CUSTOM_CSS is not a readable file; the page will not link to it",
				"path", snap.cssFile, "error", err)
			snap.cssFile = ""
		}
	}

	b, err := webui.Build(webui.Options{
		SiteName:    o.SiteName,
		SiteTagline: o.SiteTagline,
		FooterLogos: o.FooterLogos,
		Favicon:     o.Favicon,
		CustomCSS:   snap.cssFile != "",
	})
	if err != nil {
		s.warn("Web UI branding is partly unusable", "error", err)
	}
	// Any change busts the rendered-page cache in the SPA handler and
	// the stylesheet's URL, so it has to move even when the branding
	// resolved to the same thing.
	b.Rev = s.rev.Add(1)
	snap.branding = b
	snap.imgSrc = imageOrigins(b)
	s.cur.Store(snap)
}

// imageOrigins collects the distinct origins of the branding's absolute
// image URLs, in configured order, for the content security policy.
func imageOrigins(b webui.Branding) string {
	var origins []string
	add := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			// Site-relative, which 'self' already covers.
			return
		}
		origin := u.Scheme + "://" + u.Host
		if !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
	}
	for _, l := range b.FooterLogos {
		add(l.Src)
	}
	add(b.Favicon)
	return strings.Join(origins, " ")
}

func (s *brandingState) warn(msg string, kv ...any) {
	if s.logger != nil {
		s.logger.Warn(logging.DestinationHTTP, msg, kv...)
	}
}

// snapshot is the branding in force. Nil-safe, so a Handler assembled
// without one -- as a test may -- still serves unbranded pages rather
// than panicking.
func (s *brandingState) snapshot() *brandingSnapshot {
	if s != nil {
		if snap := s.cur.Load(); snap != nil {
			return snap
		}
	}
	return &brandingSnapshot{branding: webui.DefaultBranding()}
}

// current is what the pages are told.
func (s *brandingState) current() webui.Branding {
	return s.snapshot().branding
}

// handleWebUIBranding handles GET /api/v1/webui/branding.
//
// Unauthenticated: it is the chrome of the login page as much as of the
// rest, and it says nothing that is not already in the HTML of every
// page this server serves. The SPA normally reads the same values out of
// that HTML and never calls this at all; it is here for the SPA served
// from somewhere else, and for anything that wants to ask.
func (s *Handler) handleWebUIBranding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	s.writeJSON(w, http.StatusOK, s.branding.current())
}

// handleBrandingCSS serves HTTP_API_WEBUI_CUSTOM_CSS at /branding.css.
//
// The page links to it after its own stylesheet, so a site can redefine
// the --color-brand-* custom properties and recolour the whole UI
// without a rebuild.
func (s *Handler) handleBrandingCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	file := s.branding.snapshot().cssFile
	if file == "" {
		http.NotFound(w, r)
		return
	}
	data, err := readCapped(file, brandingCSSMaxBytes)
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP, "Could not read the site stylesheet", "path", file, "error", err)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Re-read on every load: an operator editing their colours should
	// see them on a refresh, not after a cache expiry they cannot see.
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "branding.css", time.Time{}, bytes.NewReader(data))
}

// handleBrandingAsset serves HTTP_API_WEBUI_BRANDING_DIR under
// /branding/: the site's logos, and its favicon if it has one.
func (s *Handler) handleBrandingAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	dir := s.branding.snapshot().dir
	name := strings.TrimPrefix(r.URL.Path, brandingAssetPrefix)
	if dir == "" || name == "" || !fs.ValidPath(name) || strings.HasSuffix(name, "/") {
		http.NotFound(w, r)
		return
	}
	ctype, ok := brandingAssetTypes[strings.ToLower(path.Ext(name))]
	if !ok {
		// Not a refusal of the file so much as of the type: see
		// brandingAssetTypes.
		http.NotFound(w, r)
		return
	}

	// os.Root confines the open to the configured directory -- no "..",
	// and no following a symlink out of it -- which matters because the
	// name comes from the URL.
	root, err := os.OpenRoot(dir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(name)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.logger.Debug(logging.DestinationHTTP, "Could not open a branding asset",
				"dir", dir, "name", name, "error", err)
		}
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// A logo changes when the operator changes it, and then its
	// modification time changes with it, so a short cache with
	// revalidation is enough.
	w.Header().Set("Cache-Control", "public, max-age=300")
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// readCapped reads at most limit bytes of a file, erroring when there
// are more rather than silently serving a truncated one.
func readCapped(name string, limit int64) ([]byte, error) {
	// gosec G304: name is HTTP_API_WEBUI_CUSTOM_CSS, read from the
	// daemon's own configuration file. Nothing from a request reaches
	// it -- the URL it is served at is a constant.
	f, err := os.Open(name) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data := make([]byte, limit+1)
	n, err := io.ReadFull(f, data)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if int64(n) > limit {
		return nil, fmt.Errorf("file is larger than %d bytes", limit)
	}
	return data[:n], nil
}
