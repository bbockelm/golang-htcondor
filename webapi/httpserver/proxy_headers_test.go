package httpserver

import "testing"

// TestJobProxyPathsOwnTheirHeaders: an app served through the job
// proxy sends its own CSP, and ours must not be layered on top.
//
// The concrete failure this prevents: applySecurityHeaders sets
// default-src 'self' with no worker-src, while VS Code in a browser
// runs its extension host and language services as workers created
// from blob: URLs. The editor loads and then quietly does nothing,
// which is far harder to diagnose than a page that fails outright.
func TestJobProxyPathsOwnTheirHeaders(t *testing.T) {
	transparent := []string{
		"/api/v1/jobs/12.0/proxy/8080/",
		"/api/v1/jobs/12.0/proxy/8080/static/main.js",
		"/api/v1/jobs/12.0/proxy/unix/vscode.sock/",
		"/api/v1/jobs/12.0/proxy/unix/vscode.sock/stable/out/vs/workbench/workbench.web.main.js",
		"/api/v1/jupyter/instances/abc/proxy/lab",
	}
	for _, p := range transparent {
		if !isTransparentProxyPath(p) {
			t.Errorf("isTransparentProxyPath(%q) = false; the upstream's headers will be overwritten", p)
		}
	}

	// Everything else is ours and must keep our headers. The files
	// case is the reason this matches structurally rather than looking
	// for "/proxy/" anywhere in the path: a job can have a file or a
	// directory called proxy, and that response is an ordinary API
	// response.
	ours := []string{
		"/api/v1/jobs",
		"/api/v1/jobs/12.0",
		"/api/v1/jobs/12.0/ssh",
		"/api/v1/jobs/12.0/files/proxy/notes.txt",
		"/api/v1/jobs/12.0/files/proxy",
		"/api/v1/whoami",
		"/",
		"",
	}
	for _, p := range ours {
		if isTransparentProxyPath(p) {
			t.Errorf("isTransparentProxyPath(%q) = true; this response loses our security headers", p)
		}
	}
}
