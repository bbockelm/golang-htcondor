package httpserver

// Reverse-proxy HTTP into a server a job is running, over the
// condor_ssh_to_job transport.
//
// Route: ANY /api/v1/jobs/{cluster}.{proc}/proxy/{port}/{rest...}
//
// This is the forward path: nothing runs inside the sandbox on our
// behalf, so there is no second principal to credential. The caller's
// own session authenticates them here, and the schedd's
// GET_JOB_CONNECT_INFO decides whether they may reach the job at all --
// it is registered at WRITE and checks job ownership, so a caller who
// is not the owner (and not a queue superuser) is refused there rather
// than by a check of ours that could drift out of agreement with it.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
)

// jobProxyDialTimeout bounds establishing the transport plus the
// connection to the port inside the job. The first request after a job
// starts pays a schedd RPC, a CEDAR handshake that may be relayed
// through CCB, an SSH handshake and an sshd spawn; later ones pay
// almost nothing because the transport is cached.
const jobProxyDialTimeout = 60 * time.Second

// jobProxyIdleConnTimeout is how long http.Transport keeps a pooled
// connection to the job. It must stay well under
// jobssh.DefaultIdleTimeout: a pooled connection holds a reference on
// the cached transport, so a longer timeout here would pin transports
// open that nothing is really using and defeat the reaper.
const jobProxyIdleConnTimeout = 90 * time.Second

// getOrCreateJobSSHCache lazily builds the transport cache.
func (s *Handler) getOrCreateJobSSHCache() (*jobssh.Cache, error) {
	s.jobSSHCacheMu.Lock()
	defer s.jobSSHCacheMu.Unlock()
	if s.jobSSHCache != nil {
		return s.jobSSHCache, nil
	}
	cache, err := jobssh.NewCache(jobssh.Options{
		Dial:   jobssh.ScheddDialer(s.getSchedd, s.ccbDialer),
		Logger: s.logger,
	})
	if err != nil {
		return nil, err
	}
	s.jobSSHCache = cache
	return cache, nil
}

// closeJobSSHCache releases every cached transport. Called from the
// handler's shutdown path.
func (s *Handler) closeJobSSHCache() {
	s.jobSSHCacheMu.Lock()
	cache := s.jobSSHCache
	s.jobSSHCache = nil
	s.jobSSHCacheMu.Unlock()
	if cache != nil {
		cache.Close()
	}
}

// parseProxyPort accepts only what can be a TCP port a job listens on.
// Port 0 is meaningless as a destination, so the whole range is closed.
func parseProxyPort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("port must be a number, got %q", s)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d is out of range", port)
	}
	return port, nil
}

// handleJobProxy proxies one request to 127.0.0.1:port inside the job.
//
// upstreamPath is what remains after /proxy/{port}, and is what the
// server in the job sees as its own path. Callers running a web app
// there should be told to mount it at the same prefix the browser uses
// (code-server's --abs-proxy-base-path, JupyterLab's base_url), since
// nothing here rewrites the HTML that comes back.
func (s *Handler) handleJobProxy(w http.ResponseWriter, r *http.Request, cluster, proc, port int, upstreamPath string) {
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	username := htcondor.GetAuthenticatedUserFromContext(ctx)

	// Superuser reach, on the same terms as the terminal: the session
	// is the grant, and what travels inside it is between the operator
	// and the job. Audited at the point the transport is opened.
	ctx, imp, err := s.superuserActionContext(ctx, r, cluster, proc)
	if err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if imp != nil {
		s.auditSuperuserAction(r, imp, "job-proxy", fmt.Sprintf("%d.%d", cluster, proc), nil)
	}

	// A universe with no starter can never be reached, however long we
	// retry, so say so as a 409 rather than letting it look like a
	// broken execute node.
	if msg, refuse := s.refuseRemoteAccessByUniverse(ctx, "proxy", cluster, proc); refuse {
		s.writeError(w, http.StatusConflict, msg)
		return
	}

	cache, err := s.getOrCreateJobSSHCache()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "job transport cache unavailable")
		return
	}

	// The transport is keyed by the identity it will authenticate as,
	// never by the job alone -- see jobssh.Key. Under superuser
	// impersonation that is the job's owner, which is who the schedd
	// builds the starter session as, so keying by the operator's own
	// name would hand a second operator the first one's transport.
	owner := htcondor.GetAuthenticatedUserFromContext(ctx)
	if owner == "" {
		owner = username
	}
	key := jobssh.Key{Owner: owner, Cluster: cluster, Proc: proc}
	target := fmt.Sprintf("127.0.0.1:%d", port)

	// Preserve the browser's Host. Our dialer ignores it -- the
	// destination is decided by key and target, not by routing -- but
	// web apps compare Host against Origin to reject cross-site
	// requests, and code-server and JupyterLab both do. Rewriting it
	// to a sentinel makes the app 404 its own internal API calls.
	browserHost := r.Host
	if browserHost == "" {
		browserHost = "condor-job.local"
	}
	outURL := *r.URL
	outURL.Scheme = "http"
	outURL.Host = browserHost
	outURL.Path = upstreamPath
	if outURL.Path == "" {
		outURL.Path = "/"
	}

	proxy := &httputil.ReverseProxy{
		// Director rather than Rewrite, matching the Jupyter proxy.
		// Rewrite is not a drop-in: ReverseProxy strips
		// X-Forwarded-For/-Host/-Proto before calling it and expects
		// SetXForwarded to put them back, which also sets -Host and
		// -Proto that Director mode never did. Web apps build their
		// own URLs from those headers, so swapping the hook silently
		// changes what the app thinks its address is.
		//nolint:staticcheck // SA1019: see above; migrating changes forwarded headers
		Director: func(req *http.Request) {
			req.URL = &outURL
			req.Host = outURL.Host
			// Do NOT delete Connection here. ReverseProxy inspects it
			// AFTER the Director runs to decide whether this is a
			// protocol upgrade (upgradeType() in
			// net/http/httputil/reverseproxy.go). Stripping it turns
			// every WebSocket handshake into a plain GET the app
			// answers with 400 -- which for an editor means it loads
			// and then never connects.
		},
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				dialCtx, cancel := context.WithTimeout(dialCtx, jobProxyDialTimeout)
				defer cancel()
				return cache.DialJob(dialCtx, key, "tcp", target)
			},
			// Keep-alives on, unlike the yamux proxy: there each
			// stream is single-use, whereas here a pooled connection
			// saves opening an SSH channel per request, which an
			// editor does constantly. The idle timeout keeps a pooled
			// connection from pinning the cached transport open.
			IdleConnTimeout:     jobProxyIdleConnTimeout,
			MaxIdleConnsPerHost: 8,
		},
		// Long-lived WebSocket and SSE connections: an editor's main
		// channel is one of them, and buffering it would look like the
		// UI hanging.
		FlushInterval: 100 * time.Millisecond,
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, perr error) {
			s.logger.Error(logging.DestinationHTTP, "job proxy failed",
				"user", username, "cluster", cluster, "proc", proc,
				"port", port, "error", perr)
			// 502: we reached the job (or could not), but the failure
			// is upstream of the caller either way. The body stays
			// vague on purpose -- perr can name internal addresses.
			s.writeError(rw, http.StatusBadGateway,
				fmt.Sprintf("could not reach port %d inside job %d.%d", port, cluster, proc))
		},
	}

	s.logger.Debug(logging.DestinationHTTP, "proxying into job",
		"user", username, "cluster", cluster, "proc", proc, "port", port, "path", upstreamPath)
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

// jobProxyUpstreamPath rebuilds the path the job's server should see
// from the segments after /proxy/{port}.
//
// A request for the prefix itself with no trailing slash ("/proxy/8080")
// becomes "/", so the app's index is served rather than a 404 -- but
// note that the browser then resolves the app's relative links against
// the prefix's parent. Callers should redirect to the trailing-slash
// form; this only keeps the bare form from being a dead end.
func jobProxyUpstreamPath(segments []string) string {
	if len(segments) == 0 {
		return "/"
	}
	return "/" + strings.Join(segments, "/")
}
