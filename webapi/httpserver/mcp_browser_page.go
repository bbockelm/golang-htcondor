// The page a person gets when they open the MCP endpoint in a browser.
//
// /mcp speaks JSON-RPC to a program. A person who follows a link to it
// gets 401 and a JSON error object, which is a correct answer to the
// request and tells them nothing about what to do next. That happens
// often, because this URL is the one thing a user needs in order to
// connect an assistant, so it is the thing sites paste into messages.
//
// A GET a browser made is answered with setup instructions for the
// harnesses people use. A GET an MCP client made -- the server-to-client
// stream of the streamable HTTP transport opens with one -- is passed
// through untouched. browserNavigation is where the two are told apart.

package httpserver

import (
	"html/template"
	"net/http"
	"strings"
	"sync"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/webui"
)

// mcpSetupPath serves the same page at a URL of its own, so it can be put
// in a message or a wiki without depending on the reader's browser
// sending the headers browserNavigation looks for.
const mcpSetupPath = "/mcp/setup"

// browserNavigation reports whether r is a person opening the URL in a
// browser rather than an MCP client doing protocol work.
//
// The streamable HTTP transport GETs this path too: that is how the
// server's side of the stream is opened. What separates the two is that
// the request has to ASK for HTML -- not merely fail to ask for the
// stream -- so everything that does not say it wants a page keeps the
// answer it gets today. That covers both an MCP client, which asks for
// text/event-stream, and curl, which sends Accept: */*: a script hitting
// this endpoint wants the JSON error, not a page about configuring
// Cursor.
//
// The two further tests are for things a browser navigation cannot
// carry, and each turns away a client that asked for HTML as well:
//
//   - Accept: text/event-stream, which the specification requires on the
//     stream GET. Only a client sending a broad Accept header reaches
//     this, which is the point of it.
//   - An Authorization header, an Mcp-Session-Id or an
//     MCP-Protocol-Version. A person following a link has no credential,
//     no session and no negotiated version.
func browserNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("Authorization") != "" ||
		r.Header.Get("Mcp-Session-Id") != "" ||
		r.Header.Get("MCP-Protocol-Version") != "" {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "text/event-stream") {
		return false
	}
	if strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml") {
		return true
	}
	// Sec-Fetch-Dest is set by every browser that sets it at all, and
	// "document" means the top-level page. It stands in for the Accept
	// header for a browser that sent an odd one.
	return strings.EqualFold(r.Header.Get("Sec-Fetch-Dest"), "document")
}

// withMCPBrowserHelp answers a browser with the setup page and hands
// everything else to the protocol endpoint.
//
// It fronts the endpoint rather than living inside it because the two
// transports -- the built-in one and the upstream SDK's -- both reject an
// unauthenticated request before either could reach this, and a person
// opening the URL has nothing to authenticate with.
func (h *Handler) withMCPBrowserHelp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if browserNavigation(r) {
			h.writeMCPSetupPage(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleMCPTrailingSlash sends /mcp/ to /mcp.
//
// The two are different paths, and only /mcp is registered, so /mcp/
// matched nothing and fell through to the JSON 404 -- for a person who
// typed the address with a trailing slash, and for a client that was
// configured with one, which simply did not work. 308 rather than 301
// because a redirected POST has to stay a POST: that is the protocol's
// own method, and a client downgrading it to GET would be told the
// endpoint is broken in a second way.
func (h *Handler) handleMCPTrailingSlash(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, mcpPath, http.StatusPermanentRedirect)
}

// handleMCPSetupPage serves the page at mcpSetupPath, for a link sent to
// someone directly. Unlike the interception above it does not inspect the
// request: whoever asked for this path asked for the page.
func (h *Handler) handleMCPSetupPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	h.writeMCPSetupPage(w, r)
}

// mcpSetupPageData is what the page says about this particular server.
type mcpSetupPageData struct {
	// SiteName heads the page. Empty where the site set no name, and the
	// template falls back to naming the access point generically.
	SiteName string
	// ServerURL is the endpoint to paste into a client: the canonical
	// public URL where the site set one, and otherwise the address this
	// request arrived at.
	ServerURL string
	// WebUI reports that this server also serves the web interface, so
	// the page can link to it. A server built without the SPA compiled
	// in would otherwise link at a 404.
	WebUI bool
}

// writeMCPSetupPage renders the page.
//
// 200, not 401: the page is a complete and correct answer to what was
// asked, and an error status would have browsers and link checkers treat
// instructions as a failure.
func (h *Handler) writeMCPSetupPage(w http.ResponseWriter, r *http.Request) {
	data := mcpSetupPageData{
		ServerURL: h.publicBaseURLFor(r) + mcpPath,
		WebUI:     webui.IsEmbedded(),
	}
	if h.branding != nil {
		data.SiteName = strings.TrimSpace(h.branding.current().SiteName)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A site renames itself and moves behind a different proxy; neither
	// is frequent, but a cached page outliving either is a page telling
	// someone to connect to the wrong host.
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if err := mcpSetupTemplate().Execute(w, data); err != nil {
		// The status is already written, so this cannot become an error
		// response. Log it: a template that fails to execute is a bug in
		// this file, and nothing else would show it.
		h.logger.Error(logging.DestinationHTTP, "Failed to render the MCP setup page", "error", err)
	}
}

// mcpSetupTemplate parses the page once, on first use.
var mcpSetupTemplate = sync.OnceValue(func() *template.Template {
	return template.Must(template.New("mcp-setup").Parse(mcpSetupHTML))
})
