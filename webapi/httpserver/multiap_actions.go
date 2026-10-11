package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Multi-AP actions: every action names its job by a complete id, and is
// sent to the schedd of the access point the id names.
//
// handleMultiJobByID parses the id through the codec, routes it
// (multiap.Service.Route), records the AP on the request's context and
// hands the request to the same handlers single-AP mode uses, with the
// path rewritten to the job's local cluster.proc. Those handlers reach
// their schedd through scheddFor, which in this mode answers only from
// that context: a handler reached without a route gets a schedd that
// cannot connect, never "the" schedd, because there is none.

// scheddFor returns the schedd an action on ctx's job goes to: the one
// schedd in single-AP mode; in multi-AP mode, the AP the request was
// routed to.
//
// In multi-AP mode it fails closed twice. With no routed AP on ctx there
// is no right answer, and the call is counted as a bug like any other
// use of the single-schedd accessor. With no caller credential on ctx
// the action would have to run as this daemon -- a queue superuser on
// the AP -- so it is refused rather than sent; CredentialOrigin refuses
// that fallback too, and this makes the refusal not depend on it.
func (h *Handler) scheddFor(ctx context.Context) *htcondor.Schedd {
	if h.multi == nil {
		return h.getSchedd()
	}
	t, ok := multiap.TargetFrom(ctx)
	if !ok || t.Member.Schedd == nil {
		return h.multiAPScheddMisuse()
	}
	if _, ok := htcondor.GetSecurityConfigFromContext(ctx); !ok {
		h.logger.Error(logging.DestinationSecurity,
			"Refusing an action with no caller credential attached", "access_point", t.Member.Name)
		return multiap.NoSchedd
	}
	return t.Member.Schedd
}

// jobPathID is the job id a response or a URL this server builds should
// carry: cluster.proc in single-AP mode, the codec's complete form for a
// request routed to an AP.
func (h *Handler) jobPathID(ctx context.Context, cluster, proc int) string {
	if h.multi != nil {
		if t, ok := multiap.TargetFrom(ctx); ok {
			return h.multi.codec.Format(jobid.ID{Schedd: t.Member.Name, Cluster: int64(cluster), Proc: int64(proc)})
		}
	}
	return fmt.Sprintf("%d.%d", cluster, proc)
}

// routedJobID is jobPathID for a handler that holds the job id as the
// text it was routed with ("123.0" after the rewrite).
func (h *Handler) routedJobID(ctx context.Context, local string) string {
	if h.multi == nil {
		return local
	}
	t, ok := multiap.TargetFrom(ctx)
	if !ok || t.ID.Schedd == "" {
		return local
	}
	return h.multi.codec.Format(t.ID)
}

// routedSchedd is the AP a request was routed to, or "".
func routedSchedd(ctx context.Context) string {
	if t, ok := multiap.TargetFrom(ctx); ok {
		return t.Member.Name
	}
	return ""
}

// multiAPJobActionAllowed reports whether multi-AP mode serves method on
// /api/v1/jobs/{id}/{rest}. An allowlist: every sub-resource is named
// with the methods its handler accepts, and anything else -- a new
// sub-resource nobody has routed yet -- is refused.
//
// match-analysis is not served: it reads the pool's slots as well as the
// job, and has not been taught which collector view belongs to which AP.
func multiAPJobActionAllowed(method, rest string) bool {
	sub, tail, _ := strings.Cut(rest, "/")
	get := method == http.MethodGet
	switch sub {
	case "hold", "release", "warm":
		return tail == "" && method == http.MethodPost
	case "stdout", "stderr", "log", "peek", "dag", "watch", "ssh":
		return tail == "" && get
	case "output":
		return (tail == "" && get) || (tail == "share" && method == http.MethodPost)
	case "input":
		switch tail {
		case "":
			return method == http.MethodPut
		case "multipart", "share":
			return method == http.MethodPost
		}
		return false
	case "files":
		return tail != "" && get
	case "proxy":
		// Whatever the job's server speaks; the proxy handler decides.
		return true
	}
	return false
}

// handleMultiJobByID serves /api/v1/jobs/{id}[/...] in multi-AP mode.
func (h *Handler) handleMultiJobByID(w http.ResponseWriter, r *http.Request, parts []string) {
	first := parts[0]
	if len(parts) == 1 {
		switch first {
		case "hold", "release":
			// POST /api/v1/jobs/hold|release: a bulk action.
			if r.Method != http.MethodPost {
				h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
				return
			}
			h.handleMultiBulkAction(w, r, first)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			h.handleMultiGetJob(w, r, first)
			return
		}
		if r.Method != http.MethodDelete && r.Method != http.MethodPatch {
			h.refuseMultiAP(w, r)
			return
		}
	} else if !multiAPJobActionAllowed(r.Method, strings.Join(parts[1:], "/")) {
		// The server-wide allowlist already refused this; kept here so
		// the dispatcher does not depend on being reached only through it.
		h.refuseMultiAP(w, r)
		return
	}

	id, err := h.multi.codec.Parse(first)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}
	user := ""
	if !id.Complete() {
		// Refused either way; authenticating first lets the refusal
		// name the caller's own candidates.
		var ok bool
		if _, user, ok = h.multiAPCaller(w, r); !ok {
			return
		}
	}
	m, err := h.multi.svc.Route(r.Context(), user, id)
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	id = id.WithSchedd(m.Name)
	ctx := multiap.WithTarget(r.Context(), multiap.Target{Member: m, ID: id})
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// A change this server makes on the AP: until the hub has seen
		// it, a bulk action must not skip the AP on the hub's word.
		// Noted at the start and again at the end, because the schedd
		// applies a slow one (a spool upload) when it finishes.
		h.multi.svc.NoteWrite(m.Name)
		defer h.multi.svc.NoteWrite(m.Name)
	}

	// The handlers below parse the job from the path, and know only
	// cluster.proc; the AP rides on the context.
	routed := r.WithContext(ctx)
	u := *r.URL
	rest := ""
	if len(parts) > 1 {
		rest = "/" + strings.Join(parts[1:], "/")
	}
	u.Path = fmt.Sprintf("/api/v1/jobs/%d.%d%s", id.Cluster, id.Proc, rest)
	u.RawPath = ""
	routed.URL = &u
	h.serveJobByID(w, routed)
}

// --- per-AP queue superusers -------------------------------------------------

// apSuperusers holds each member's QUEUE_SUPER_USERS, read from that
// member. Cross-user power in multi-AP mode is per AP: being a queue
// superuser on one AP must not reach the jobs of any other.
type apSuperusers struct {
	reg       multiap.Registry
	uidDomain string
	logger    *logging.Logger

	mu       sync.Mutex
	policies map[string]*superuserPolicy // by lower-cased AP name
	ctx      context.Context             // set by run; policies started after it inherit it
}

func newAPSuperusers(reg multiap.Registry, uidDomain string, logger *logging.Logger) *apSuperusers {
	return &apSuperusers{reg: reg, uidDomain: uidDomain, logger: logger, policies: map[string]*superuserPolicy{}}
}

// memberSuperUserSource reads one member's QUEUE_SUPER_USERS from its
// current schedd handle, which the registry replaces when the AP's
// address changes.
type memberSuperUserSource struct {
	reg  multiap.Registry
	name string
}

func (s memberSuperUserSource) QueueSuperUsers(ctx context.Context) ([]string, error) {
	m, ok := s.reg.Get(s.name)
	if !ok || m.Schedd == nil {
		return nil, fmt.Errorf("access point %s has no known address", s.name)
	}
	return m.Schedd.QueueSuperUsers(ctx)
}

// run keeps a policy per member, polling each from its own AP, until ctx
// ends.
func (a *apSuperusers) run(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
	t := time.NewTicker(apregistry.DefaultInterval)
	defer t.Stop()
	for {
		for _, m := range a.reg.Members() {
			a.policy(m.Name)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// policy returns ap's policy, creating (and, once run has started,
// starting) it on first use.
func (a *apSuperusers) policy(ap string) *superuserPolicy {
	key := strings.ToLower(ap)
	a.mu.Lock()
	defer a.mu.Unlock()
	if p, ok := a.policies[key]; ok {
		return p
	}
	p := newSuperuserPolicy(memberSuperUserSource{reg: a.reg, name: ap}, a.uidDomain, "", 0, a.logger)
	a.policies[key] = p
	if a.ctx != nil {
		go p.Run(a.ctx)
	}
	return p
}

// isQueueSuperUser reports whether actor is in ap's QUEUE_SUPER_USERS.
// Unknown -- never read, or not a member -- is false.
func (a *apSuperusers) isQueueSuperUser(ap, actor string) bool {
	if a == nil || ap == "" || actor == "" {
		return false
	}
	if _, ok := a.reg.Get(ap); !ok {
		return false
	}
	p := a.policy(ap)
	if !p.known() {
		return false
	}
	_, isSuper := p.ImpersonationIdentity(actor)
	return isSuper
}

// apQueueSuperUser is the per-AP superuser check multi-AP mode uses, and
// hands to MCP: in tests a fixed table replaces the polled policies.
func (m *multiAPMode) apQueueSuperUser(ap, actor string) bool {
	if m.queueSuperUser != nil {
		return m.queueSuperUser(ap, actor)
	}
	return m.superusers.isQueueSuperUser(ap, actor)
}

// --- member trust probe ------------------------------------------------------

// trustProbeSubject is the local part of the identity the trust probe's
// token is minted for. It names this server, and is never a real user.
const trustProbeSubject = "htcondor-api-trust-probe"

// probeMemberTrust checks that a member accepts this server's tokens:
// it pings the AP with a token minted from the pool signing key for
// trustProbeSubject@UID_DOMAIN and requires the AP to report exactly
// that identity, and then asks the AP its UID_DOMAIN.
//
// A trust-domain or signing-key mismatch fails silently in practice --
// cedar drops a token whose issuer the peer does not trust and offers
// nothing usable, which reaches an action as an unrelated EOF -- so it is
// found here, once, instead. The identity check catches an AP that maps
// tokens to some other identity. The UID_DOMAIN read is separate because
// a schedd reports a token's subject verbatim: the ping alone does not
// say what UID_DOMAIN the AP qualifies its own users with, and v1 needs
// every member to agree on it.
//
// A member that cannot be reached is inconclusive, not untrusted.
func (h *Handler) probeMemberTrust(ctx context.Context, m apregistry.Member) error {
	if m.Schedd == nil {
		return fmt.Errorf("no address: %w", apregistry.ErrInconclusive)
	}
	if h.signingKeyPath == "" || h.trustDomain == "" || h.uidDomain == "" {
		return fmt.Errorf("this server has no signing key, TRUST_DOMAIN or UID_DOMAIN to mint a probe token with: %w",
			apregistry.ErrInconclusive)
	}
	want := trustProbeSubject + "@" + h.uidDomain
	now := time.Now()
	token, err := generateMCPAccessJWT(filepath.Dir(h.signingKeyPath), filepath.Base(h.signingKeyPath),
		want, h.trustDomain, now.Unix(), now.Add(5*time.Minute).Unix(), []string{"READ"})
	if err != nil {
		return fmt.Errorf("minting the probe token: %w: %w", err, apregistry.ErrInconclusive)
	}
	sec, err := htcondor.NewClientSecurityConfigWithConfig(ctx, h.clientConfig, token, "", 0, "CLIENT", nil)
	if err != nil {
		return fmt.Errorf("building the probe's security configuration: %w: %w", err, apregistry.ErrInconclusive)
	}
	ctx = htcondor.WithSecurityConfig(htcondor.WithUserRequest(ctx, "access point trust probe"), sec)

	res, err := m.Schedd.PingWithOptions(ctx, &htcondor.PingOptions{Command: htcondor.DCNopRead})
	if err != nil {
		if unreachable(err) {
			return fmt.Errorf("the access point did not answer: %w: %w", err, apregistry.ErrInconclusive)
		}
		return fmt.Errorf("the access point refused a token signed with this server's key for trust domain %s: %w", h.trustDomain, err)
	}
	if !sameIdentity(res.User, want) {
		return fmt.Errorf("the access point identified this server's token as %q, not %q", res.User, want)
	}
	uid, ok, err := m.Schedd.ConfigVal(ctx, "UID_DOMAIN")
	switch {
	case err != nil:
		// Not every AP answers DC_CONFIG_VAL to an ordinary identity.
		// The token was accepted and mapped correctly, which is the part
		// that would make every action fail.
		h.logger.Info(logging.DestinationSecurity, "Could not read an access point's UID_DOMAIN during its trust probe",
			"access_point", m.Name, "error", err)
	case ok && !strings.EqualFold(strings.TrimSpace(uid), h.uidDomain):
		return fmt.Errorf("the access point's UID_DOMAIN is %q, and this server's is %q", uid, h.uidDomain)
	}
	return nil
}

// sameIdentity compares two user@domain identities as HTCondor does:
// the user part exactly, the domain without regard to case.
func sameIdentity(got, want string) bool {
	gi, wi := strings.LastIndex(got, "@"), strings.LastIndex(want, "@")
	if gi < 0 || wi < 0 {
		return got == want
	}
	return got[:gi] == want[:wi] && strings.EqualFold(got[gi+1:], want[wi+1:])
}

// unreachable reports whether a probe failed before any handshake: the
// AP is down or the network is, which says nothing about trust.
func unreachable(err error) bool {
	var authz *security.AuthorizationError
	if errors.As(err, &authz) {
		return false
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	// A reset is what a restarted schedd's stale shared-port address
	// gives (wrapScheddConnectError): the next registry poll brings the
	// new address, and a fresh probe.
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	for _, s := range []string{"connection refused", "no route to host", "network is unreachable", "no such host",
		"i/o timeout", "connection reset by peer"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
