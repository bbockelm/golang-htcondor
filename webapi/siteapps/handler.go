package siteapps

import (
	"net/http"
	"strings"
	"sync"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/webui"
)

// Caller is what the server knows about whoever is asking.
type Caller struct {
	// Authenticated reports whether there is a session at all.
	Authenticated bool
	// Groups the caller holds.
	Groups []string
}

// IdentifyFunc resolves the caller from a request. The server supplies
// one that reads its browser session; this package does no
// authentication of its own.
type IdentifyFunc func(*http.Request) Caller

// LoginRedirectFunc sends an unauthenticated browser to the login page,
// arranged to come back here.
type LoginRedirectFunc func(http.ResponseWriter, *http.Request)

// Handler serves /site/.
type Handler struct {
	lib      *Library
	identify IdentifyFunc
	login    LoginRedirectFunc

	// Per-app SPA handlers, built on first use and discarded when the
	// library republishes that app. Keyed by the Entry pointer rather
	// than the id, so a reloaded bundle cannot be served by a handler
	// still holding the old one's filesystem.
	mu       sync.Mutex
	handlers map[*Entry]http.Handler
}

// NewHandler wires a library to the request path.
func NewHandler(lib *Library, identify IdentifyFunc, login LoginRedirectFunc) *Handler {
	return &Handler{
		lib:      lib,
		identify: identify,
		login:    login,
		handlers: map[*Entry]http.Handler{},
	}
}

// ServeHTTP routes /site/{id}/... to an app, after the group gate.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/site/")
	if rest == r.URL.Path {
		http.NotFound(w, r)
		return
	}

	id, _, _ := strings.Cut(rest, "/")
	if id == "" {
		h.serveSwitcher(w, r)
		return
	}
	if strings.HasPrefix(id, "_") {
		// Reserved for the server's own paths; none are registered yet.
		http.NotFound(w, r)
		return
	}

	caller := h.identify(r)
	if !caller.Authenticated {
		// A browser that is simply not logged in gets sent to log in,
		// rather than a 404 it would read as "my PI sent me a broken
		// link".
		h.login(w, r)
		return
	}

	entry, ok := h.lib.Get(id)
	if !ok || !entry.App.VisibleTo(caller.Groups) {
		// 404 rather than 403 for a caller outside the groups: the set
		// of app ids is itself site information, and a 403 confirms
		// which ones exist. Nothing in a non-member's interface links
		// here, so there is no usability cost to the stricter answer.
		http.NotFound(w, r)
		return
	}

	// These bytes are group-scoped. A shared cache in front of the
	// access point must not hold them, or it will serve one lab's app
	// to the next caller who asks.
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Vary", "Cookie")

	handler, err := h.handlerFor(entry)
	if err != nil {
		http.Error(w, "This app could not be prepared for serving.", http.StatusInternalServerError)
		return
	}
	http.StripPrefix("/site/"+id, handler).ServeHTTP(w, r)
}

// handlerFor returns the SPA handler for one app, building it once.
func (h *Handler) handlerFor(entry *Entry) (http.Handler, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if handler, ok := h.handlers[entry]; ok {
		return handler, nil
	}
	head, err := HeadHTML(entry.App)
	if err != nil {
		return nil, err
	}
	handler := webui.NewSPAHandlerFS(entry.FS(), webui.WithHeadHTML(head))
	// Bound the map: entries are retired by a reload and nothing else
	// removes them, so a server that redeploys an app every few
	// minutes for a year would otherwise accumulate handlers for
	// bundles that are long closed.
	if len(h.handlers) > maxCachedHandlers {
		h.handlers = map[*Entry]http.Handler{}
	}
	h.handlers[entry] = handler
	return handler, nil
}

// maxCachedHandlers bounds the per-entry handler cache. A site with
// more live apps than this has other problems; the number exists so
// the map cannot grow without limit across reloads.
const maxCachedHandlers = 256
