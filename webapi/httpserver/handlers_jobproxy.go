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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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

// Credential descriptors for jobssh.Key.Credential. See
// jobTransportCredential.
const (
	jobTransportMintedWrite   = "minted:write"
	jobTransportMintedLimited = "minted:limited"
)

// jobTransportKey is the cache key for a transport into cluster.proc
// opened under ctx, or an error saying why there is none.
//
// The owner is the identity ctx was resolved to, unchanged: it is not
// reduced to an HTCondor Owner here, so two actors that differ only in
// realm do not share a slot. bearer is the request's own bearer, ""
// for none; imp is the superuser impersonation ctx carries, if any.
//
// Under superuser impersonation ctx still names the caller --
// impersonate swaps only the credential -- so the impersonation goes
// into the key as well: a transport opened as the fallback identity on
// bob's behalf must never be returned to a plain lookup by the same
// caller, such as the SSH gateway's, where it would outlive the arm and
// the leads file with no superuser check and no audit. Two operators
// impersonating the same owner differ by Owner, so they do not share
// one either.
func jobTransportKey(ctx context.Context, bearer string, imp *Impersonation, cluster, proc int) (jobssh.Key, error) {
	owner := htcondor.GetAuthenticatedUserFromContext(ctx)
	if owner == "" {
		return jobssh.Key{}, fmt.Errorf("no authenticated identity")
	}
	cred := jobTransportCredential(ctx, bearer)
	if cred == "" {
		return jobssh.Key{}, fmt.Errorf("no HTCondor credential to reach the job with")
	}
	key := jobssh.Key{Owner: owner, Credential: cred, Cluster: cluster, Proc: proc}
	if imp != nil {
		key.Impersonation = imp.transportTag()
	}
	return key, nil
}

// jobTransportCredential describes the credential ctx would open a job
// transport with, for jobssh.Key.Credential. "" when it carries none.
//
// Two kinds, kept apart (an impersonation is told apart by
// jobssh.Key.Impersonation, not here):
//
//   - A bearer handed straight to cedar -- a forwarded IDTOKEN -- is
//     described by a digest of itself. Its identity was resolved by
//     asking the schedd, and only that one credential has been shown
//     to be good for it.
//   - A credential this server minted for an identity it established
//     itself (a session, a trusted header, an OAuth2 grant, an API key,
//     the SSH gateway) is re-minted per request or per channel, so a
//     digest would never match twice. It is described by what matters
//     for a transport instead: whether it carries WRITE, which is what
//     the schedd requires to open one. Every minted credential with
//     WRITE for this owner could open the transport itself, so sharing
//     among them grants nothing; one without WRITE gets a slot of its
//     own and cannot borrow a transport it could not have opened.
func jobTransportCredential(ctx context.Context, bearer string) string {
	sec, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok || sec.Token == "" {
		return ""
	}
	if bearer != "" && sec.Token == bearer {
		return "bearer:" + mcpActorKey(bearer)
	}
	if mintedCredentialMayWrite(sec.Token) {
		return jobTransportMintedWrite
	}
	return jobTransportMintedLimited
}

// mintedCredentialMayWrite reports whether an IDTOKEN this server
// minted carries WRITE: no scope claim at all is unrestricted.
//
// Read without verifying the signature, which is sound only because
// the token is this server's own: it is never applied to a bearer a
// caller supplied. A token that cannot be read is treated as limited.
func mintedCredentialMayWrite(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Scope *string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}
	if claims.Scope == nil {
		return true
	}
	for _, sc := range strings.Fields(*claims.Scope) {
		if sc == "condor:/WRITE" {
			return true
		}
	}
	return false
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

// jobProxyTarget names what to connect to inside the sandbox: a TCP
// port, or a Unix socket in the job's scratch directory.
//
// A socket is the better of the two and the one anything we launch
// should use. A TCP port bound to 127.0.0.1 in a sandbox is reachable
// by any local user on the execute node unless the job has its own
// network namespace, which no pool can be assumed to configure,
// whereas a socket is protected by file permissions. The port form
// stays because it is the only way to reach a job somebody else set
// up.
type jobProxyTarget struct {
	Port   int    // TCP port; used when Socket is empty
	Socket string // bare filename in the scratch directory
}

func (t jobProxyTarget) describe() string {
	if t.Socket != "" {
		return "socket " + t.Socket
	}
	return fmt.Sprintf("port %d", t.Port)
}

func (t jobProxyTarget) dial(ctx context.Context, cache *jobssh.Cache, key jobssh.Key) (net.Conn, error) {
	if t.Socket != "" {
		return cache.DialJobUnix(ctx, key, t.Socket)
	}
	return cache.DialJob(ctx, key, "tcp", fmt.Sprintf("127.0.0.1:%d", t.Port))
}

// handleJobProxy proxies one request to a target inside the job.
//
// upstreamPath is what remains after /proxy/{port}, and is what the
// server in the job sees as its own path. Callers running a web app
// there should be told to mount it at the same prefix the browser uses
// (code-server's --abs-proxy-base-path, JupyterLab's base_url), since
// nothing here rewrites the HTML that comes back.
func (s *Handler) handleJobProxy(w http.ResponseWriter, r *http.Request, cluster, proc int, target jobProxyTarget, upstreamPath string) {
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
	if username == "" {
		// A transport is keyed by who is asking; with nobody to key it
		// by there is nothing this request may use.
		s.writeError(w, http.StatusUnauthorized, "Authentication failed: no authenticated identity")
		return
	}

	// Superuser reach, on the same terms as the terminal: the session
	// is the grant, and what travels inside it is between the operator
	// and the job. Audited at the point the transport is opened.
	ctx, imp, err := s.superuserActionContext(ctx, r, cluster, proc)
	if err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}
	// Except for project leads: the app is served on this origin, so it
	// would run owner-controlled code in the lead's session. See
	// refuseProjectLeadInteractiveApp.
	if refusal := refuseProjectLeadInteractiveApp(imp); refusal != nil {
		s.auditSuperuserAction(r, imp, "job-proxy", fmt.Sprintf("%d.%d", cluster, proc), refusal)
		s.writeError(w, http.StatusForbidden, refusal.Error())
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

	// Redirect the bare prefix to its trailing-slash form before doing
	// any work.
	//
	// Neither code-server nor openvscode-server can be told the path it
	// is served under (code-server's --abs-proxy-base-path configures
	// its OWN built-in proxy, not this), so the supported arrangement
	// is a reverse proxy that strips the prefix while the app emits
	// relative URLs. That only works if the browser's address ends in a
	// slash: at /proxy/unix/vscode.sock a relative "static/x.js"
	// resolves to /proxy/unix/static/x.js and nothing loads, while at
	// /proxy/unix/vscode.sock/ it resolves correctly.
	//
	// 307 rather than 308: the redirect is right only while this job
	// exists, and a permanent one would be cached against a URL that
	// stops meaning anything when the job ends.
	if upstreamPath == "/" && !strings.HasSuffix(r.URL.Path, "/") {
		// Built from the job id and the target, never from the request
		// path. A redirect assembled by appending to r.URL.Path carries
		// whatever the request put there: a path of "//evil.example"
		// makes "//evil.example/", which a browser reads as a
		// protocol-relative URL and follows off-site. The route prefix
		// happens to prevent that today, which is exactly the kind of
		// guarantee that stops being true when a route moves.
		//
		// Every part below is ours: cluster and proc are ints, the port
		// is an int, and the socket name was held to [A-Za-z0-9._-] in
		// parseProxyTarget.
		redirect := url.URL{Path: jobProxyPrefix(cluster, proc, target), RawQuery: r.URL.RawQuery}
		http.Redirect(w, r, redirect.String(), http.StatusTemporaryRedirect)
		return
	}

	cache, err := s.getOrCreateJobSSHCache()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "job transport cache unavailable")
		return
	}

	// Keyed by caller, credential and impersonation, never by the job
	// alone -- see jobTransportKey.
	key, err := jobTransportKey(ctx, bearerFromRequest(r), imp, cluster, proc)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

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
				return target.dial(dialCtx, cache, key)
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
				"target", target.describe(), "error", perr)
			// 502: we reached the job (or could not), but the failure
			// is upstream of the caller either way. The body stays
			// vague on purpose -- perr can name internal addresses.
			s.writeError(rw, http.StatusBadGateway,
				fmt.Sprintf("could not reach %s inside job %d.%d", target.describe(), cluster, proc))
		},
	}

	s.logger.Debug(logging.DestinationHTTP, "proxying into job",
		"user", username, "cluster", cluster, "proc", proc,
		"target", target.describe(), "path", upstreamPath)
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

// jobProxyPrefix is the canonical, trailing-slash URL for a target
// inside a job: what a browser must be at for the app's relative URLs
// to resolve.
func jobProxyPrefix(cluster, proc int, t jobProxyTarget) string {
	if t.Socket != "" {
		return fmt.Sprintf("/api/v1/jobs/%d.%d/proxy/unix/%s/", cluster, proc, t.Socket)
	}
	return fmt.Sprintf("/api/v1/jobs/%d.%d/proxy/%d/", cluster, proc, t.Port)
}

// parseProxyTarget reads the segment after /proxy/ as either the
// literal "unix" (the socket name then follows) or a TCP port.
func parseProxyTarget(segments []string) (jobProxyTarget, []string, error) {
	if len(segments) == 0 {
		return jobProxyTarget{}, nil, fmt.Errorf("expected a port or \"unix\"")
	}
	if segments[0] == "unix" {
		if len(segments) < 2 {
			return jobProxyTarget{}, nil, fmt.Errorf("unix needs a socket name: /proxy/unix/{name}/")
		}
		// Check the name here rather than at dial time. It is the only
		// part of the socket path a request controls, and refusing it
		// where it arrives gives a 400 saying what is wrong instead of
		// a 502 from a dial that was never going to work -- and leaves
		// nothing request-shaped in the redirect built below.
		if err := jobssh.ValidateSocketName(segments[1]); err != nil {
			return jobProxyTarget{}, nil, err
		}
		return jobProxyTarget{Socket: segments[1]}, segments[2:], nil
	}
	port, err := parseProxyPort(segments[0])
	if err != nil {
		return jobProxyTarget{}, nil, err
	}
	return jobProxyTarget{Port: port}, segments[1:], nil
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
