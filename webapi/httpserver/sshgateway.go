// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/jobssh"
	"github.com/bbockelm/golang-htcondor/webapi/sshgateway"
	"github.com/bbockelm/golang-htcondor/webapi/sshkeys"
	"golang.org/x/crypto/ssh"
)

// sshGatewayClientID is the public OAuth2 client the gateway drives the
// device flow as. Seeded at startup the way the Swagger client is.
const sshGatewayClientID = "ssh-gateway"

// sshGatewayScopes are what a terminal in a job needs.
//
// condor:/WRITE and nothing wider: the schedd registers
// GET_JOB_CONNECT_INFO at WRITE, so that one scope covers shell access
// and there is no reason to ask for more. offline_access is what lets a
// session outlive its access token.
//
// condor:/READ because attaching to a session by name lists the
// caller's jobs first, which is a READ command; WRITE alone would
// leave that lookup refused. No offline_access: the HTCondor
// credential is minted here per connection, so a refresh token would
// be captured and never used.
var sshGatewayScopes = []string{"openid", "condor:/READ", "condor:/WRITE"}

// withCondorCredential attaches an HTCondor credential minted for
// username with scopes, so everything done under the returned context
// runs as that person rather than as this daemon.
//
// Extracted from mcpAuthContext so the SSH gateway shares it. A second
// copy would be a second place for the SecurityTag to be forgotten --
// and forgetting it is not a subtle bug: cedar's client session cache
// is keyed {SecurityTag, address, command}, so with an empty tag one
// caller's request resumes a session another caller authenticated and
// runs as them.
func (h *Handler) withCondorCredential(ctx context.Context, username string, scopes []string) (context.Context, error) {
	if h.signingKeyPath == "" || h.trustDomain == "" {
		// Nothing to mint with. The caller still gets a usable context;
		// the schedd will decide what an unauthenticated one may do.
		return ctx, nil
	}
	htcToken, err := h.generateHTCondorTokenWithScopes(username, scopes)
	if err != nil {
		return ctx, fmt.Errorf("minting an HTCondor token for %q: %w", username, err)
	}
	secConfig, err := htcondor.NewClientSecurityConfig(ctx, htcToken, "", 0, "CLIENT", nil)
	if err != nil {
		return ctx, fmt.Errorf("building a security config for %q: %w", username, err)
	}
	secConfig.SecurityTag = username
	return htcondor.WithSecurityConfig(ctx, secConfig), nil
}

// startSSHGateway brings up the SSH gateway when one is configured.
//
// issuer is the OAuth2 issuer as finally resolved, which is why this
// runs after initializeOAuth2 rather than during construction.
func (h *Handler) startSSHGateway(ctx context.Context, issuer string) error {
	if strings.TrimSpace(h.sshGatewayAddress) == "" {
		return nil
	}
	if h.oauth2Provider == nil {
		return errors.New("the SSH gateway needs the OAuth2 provider, which is not configured; " +
			"enable MCP/OAuth2 or unset HTTP_API_SSH_GATEWAY_ADDRESS")
	}
	// Without these there is nothing to mint a per-caller HTCondor
	// credential with, and withCondorCredential hands back the context
	// unchanged. That is NOT harmless here: a context with no security
	// config falls through to GetSecurityConfig(cfg, ...) -- this
	// daemon's own configuration -- so every session would reach the
	// schedd as the daemon, which on a normal access point is a queue
	// superuser. Every other credential-minting surface in this server
	// refuses for the same reason; see apikey_condor.go and
	// dbmirror_token.go.
	if h.signingKeyPath == "" || h.trustDomain == "" {
		return errors.New("the SSH gateway needs HTTP_API_SIGNING_KEY and a trust domain to mint " +
			"per-caller HTCondor credentials; without them every session would authenticate as this " +
			"daemon rather than as the person connecting")
	}

	hostKey, err := sshkeys.Resolve(ctx, sshkeys.HostKey, sshkeys.Options{
		DB:          h.db,
		Sealer:      h.sealer,
		Logger:      h.logger,
		HostKeyFile: h.sshHostKeyFile,
	})
	if err != nil {
		// Deliberately fatal rather than "carry on without the
		// gateway". The address was set on purpose, and a listener
		// that silently does not exist is worse to diagnose than a
		// startup error naming what to fix -- which Resolve's errors
		// already do.
		return err
	}

	if err := h.seedSSHGatewayClient(ctx); err != nil {
		return err
	}

	// The CA is optional in a way the host key is not: without one,
	// the device flow is still a complete way in, so a deployment that
	// cannot keep a CA key loses convenience rather than access.
	caKey, caErr := sshkeys.Resolve(ctx, sshkeys.CAKey, sshkeys.Options{
		DB:        h.db,
		Sealer:    h.sealer,
		Logger:    h.logger,
		CAKeyFile: h.sshCAKeyFile,
	})
	switch {
	case caErr == nil:
		h.sshCASigner = caKey.Signer
	case errors.Is(caErr, sshkeys.ErrNoKeyStore):
		h.logger.Info(logging.DestinationHTTP,
			"No SSH certificate authority; the gateway will accept the device flow only",
			"reason", caErr)
	default:
		// A CA that exists and cannot be opened is the same hazard as
		// a host key that cannot: silently minting a replacement would
		// invalidate every certificate already issued.
		return caErr
	}

	cache, err := h.getOrCreateJobSSHCache()
	if err != nil {
		return fmt.Errorf("preparing the job transport cache: %w", err)
	}

	gatewayIssuer := strings.TrimSpace(h.sshGatewayIssuer)
	if gatewayIssuer == "" {
		gatewayIssuer = issuer
	}

	auth, err := sshgateway.NewAuthenticator(sshgateway.Options{
		Flow: &sshgateway.HTTPFlow{
			Issuer:   gatewayIssuer,
			ClientID: sshGatewayClientID,
			Scopes:   sshGatewayScopes,
		},
		Identity: h.sshGatewayIdentity,
		Logger:   h.logger,
		Prompt:   h.sshGatewayPromptName(issuer),
	})
	if err != nil {
		return err
	}

	bans, err := h.sshGatewayBanlist()
	if err != nil {
		return err
	}

	var certs *sshgateway.CertAuth
	if h.sshCASigner != nil {
		certs = &sshgateway.CertAuth{
			Authority: h.sshCASigner.PublicKey(),
			Scopes:    sshGatewayScopes,
			Bans:      bans,
		}
	}

	// Present a host certificate when there is a CA to sign one with,
	// so a client that trusts the CA verifies this gateway without
	// pinning its host key. Falling back to the bare key is not a
	// silent downgrade: it is the same thing the gateway did before
	// host certificates existed, and it is what a deployment with no
	// CA key has always had.
	var hostCert ssh.Signer
	if h.sshCASigner != nil {
		// No principals, so the certificate is good for every name.
		// This process does not know the names it is reached by -- it
		// binds :2222 behind whatever the operator put in front of it
		// -- and a certificate naming the wrong one fails closed for
		// everybody. HTTP_API_SSH_GATEWAY_HOST looks like the answer
		// and is not: it is one name, it is documented as cosmetic, and
		// promoting it would break the first deployment reached by an
		// alias.
		signer, err := sshgateway.NewHostCertSigner(
			hostKey.Signer, h.sshCASigner, nil, time.Now())
		if err != nil {
			return fmt.Errorf("issuing the gateway's host certificate: %w", err)
		}
		hostCert = signer
	}

	listener := &sshgateway.Listener{
		Addr:     h.sshGatewayAddress,
		HostKey:  hostKey.Signer,
		HostCert: hostCert,
		Auth:     auth,
		Certs:    certs,
		Server: &sshgateway.Server{
			Transport:  cache,
			Resolve:    h.sshGatewayResolve,
			Credential: h.sshGatewayCredential,
			Logger:     h.logger,
		},
		Bans:   bans,
		Logger: h.logger,
	}

	h.sshGateway = listener
	h.logger.Info(logging.DestinationHTTP, "Starting the SSH gateway",
		"address", h.sshGatewayAddress,
		"issuer", gatewayIssuer,
		"host_key", hostKey.Fingerprint,
		"host_key_source", hostKey.Source,
		"host_certificate", hostCert != nil,
		"certificates", certs != nil,
		"lockout", bans != nil)

	// Bind before returning, so a port already in use fails startup
	// the way a missing host key does rather than leaving a listener
	// that silently is not there.
	if err := listener.Listen(ctx); err != nil {
		return err
	}
	go func() {
		if err := listener.Serve(ctx); err != nil {
			h.logger.Error(logging.DestinationHTTP, "The SSH gateway stopped", "error", err)
		}
	}()
	go h.probeSSHGatewayIssuer(ctx, gatewayIssuer)
	return nil
}

// probeSSHGatewayIssuer checks, once, that the device endpoint the
// gateway will drive is actually reachable from this process.
//
// It has to run in the background: startSSHGateway is called from
// Handler.Start, before the HTTP server is serving, so a synchronous
// probe would fail on every startup. The delay is for the same reason.
//
// Worth doing at all because the failure is otherwise invisible until a
// user tries to log in, and reaches them only as "could not start the
// login flow" -- which names neither the URL nor the setting. The issuer
// defaults to the OAuth2 issuer, and that default is itself a hardcoded
// http://localhost:8080 when nothing configured one, so "points at a
// server that is not there" is the expected state of an unconfigured
// deployment rather than an exotic one.
func (h *Handler) probeSSHGatewayIssuer(ctx context.Context, issuer string) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	endpoint := strings.TrimSuffix(issuer, "/") + "/mcp/oauth2/device/authorize"
	form := url.Values{}
	form.Set("client_id", sshGatewayClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.logger.Error(logging.DestinationHTTP,
			"The SSH gateway cannot reach the device endpoint it authenticates with; every login will fail. "+
				"Set HTTP_API_SSH_GATEWAY_ISSUER to a URL this process can reach, or HTTP_API_OAUTH2_ISSUER "+
				"to this server's real address",
			"endpoint", endpoint, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	if resp.StatusCode != http.StatusOK {
		h.logger.Error(logging.DestinationHTTP,
			"The SSH gateway's device endpoint answered unexpectedly; logins are likely to fail",
			"endpoint", endpoint, "status", resp.Status)
		return
	}
	h.logger.Info(logging.DestinationHTTP,
		"The SSH gateway reached its device endpoint", "endpoint", endpoint)
}

// stopSSHGateway closes the listener and waits for connections in
// flight, so a terminal is not cut off mid-keystroke by a reload.
func (h *Handler) stopSSHGateway() {
	if h.sshGateway == nil {
		return
	}
	if err := h.sshGateway.Close(); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Closing the SSH gateway", "error", err)
	}
	h.sshGateway = nil
}

// sshGatewayPromptName is what the login prompt calls this service.
func (h *Handler) sshGatewayPromptName(issuer string) string {
	if u, err := parseURL(issuer); err == nil && u.Host != "" {
		return u.Host
	}
	return issuer
}

// sshGatewayIdentity resolves who an approved grant belongs to.
//
// The access token is introspected rather than parsed: it is one this
// server issued, so fosite is the thing that can say whether it is
// still valid and what it was granted. A token's claims are not an
// identity until something authoritative says so.
func (h *Handler) sshGatewayIdentity(ctx context.Context, g *sshgateway.Grant) (string, error) {
	_, ar, err := h.oauth2Provider.GetProvider().IntrospectToken(
		ctx, g.AccessToken, fosite.AccessToken, newEmptySession())
	if err != nil {
		return "", fmt.Errorf("introspecting the access token: %w", err)
	}
	// ownerFromActor, the same truncation the certificate endpoint
	// applies, so the two paths cannot disagree about who somebody is.
	//
	// It keeps the part before the last "@", which is what HTCondor
	// calls an Owner -- a domain-qualified name matches no job and no
	// session, so the device flow would create a fresh session on every
	// connection and never find the one it just made. Which realm a
	// subject came from is the issuer's business to keep unambiguous.
	return ownerFromActor(h.extractUsernameFromToken(ar)), nil
}

// sshGatewaySessionSize is what a session created by the gateway asks
// for. A zero field means the interactive package's own default, so an
// unset deployment gets exactly what it got before these knobs
// existed.
//
// Worth configuring because these sessions are created by somebody
// typing `ssh`, not by somebody filling in a form: nobody chose the
// size, so the site has to.
type sshGatewaySessionSize struct {
	Cpus     int
	MemoryMB int
	DiskMB   int
}

// sshGatewaySessionWait bounds how long a caller waits for a session
// they just asked for to start running.
//
// Generous because it covers a negotiation cycle and a sandbox setup,
// and bounded because the caller is sitting at a terminal.
const sshGatewaySessionWait = 3 * time.Minute

// sshGatewayCredential mints the caller's HTCondor credential.
//
// Called per channel rather than per connection: the IDTOKEN lasts five
// minutes because over HTTP a fresh one is minted per request, and an
// SSH connection lasts as long as somebody leaves a terminal open. A
// credential minted at accept time is expired by the time a later
// channel uses it, and an expired one does not fail closed -- cedar
// falls back to this daemon's own pool credential and the schedd
// refuses the command with the daemon's name in the error.
func (h *Handler) sshGatewayCredential(ctx context.Context, account string, scopes []string) (context.Context, error) {
	if account == "" {
		return nil, errors.New("no account to mint a credential for")
	}
	cctx, err := h.withCondorCredential(ctx, account, scopes)
	if err != nil {
		return nil, err
	}
	// Belt and braces with the startup check. withCondorCredential is
	// deliberately lenient -- the MCP path forwards tokens it does not
	// mint -- so a missing credential has to be caught rather than
	// carried, or the channel silently runs as this daemon.
	if _, ok := htcondor.GetSecurityConfigFromContext(cctx); !ok {
		return nil, fmt.Errorf("no HTCondor credential could be minted for %q; refusing to run the "+
			"session as this daemon", account)
	}
	return cctx, nil
}

// sshGatewayResolve turns a target into a job.
//
// Ownership is not checked here. The schedd checks it, on every
// GET_JOB_CONNECT_INFO, against the credential the context carries --
// and it is the only thing whose answer is authoritative. Repeating the
// check here would add a second opinion that can only ever be wrong in
// the direction of letting somebody in.
func (h *Handler) sshGatewayResolve(ctx context.Context, account string, t sshgateway.Target, report func(string)) (jobssh.Key, error) {
	if t.IsJob() {
		return jobssh.Key{Owner: account, Cluster: t.Cluster, Proc: t.Proc}, nil
	}
	return h.sshGatewaySession(ctx, account, t, report)
}

// sshGatewaySession attaches to the caller's named interactive session,
// creating it if there is not one.
//
// Any username that is not a job id lands here, so `ssh work@gateway`
// and a bare `ssh gateway` from a machine whose local login is "work"
// are the same request. That is the point: a user who does not care
// which job they get should not have to name one.
//
// KNOWN GAP: creating a session blocks here with nothing on the
// caller's terminal, because resolution happens before the session
// channel is accepted and there is nowhere to write until it is.
// Moving it after Accept is what the progress display needs, and is
// the next piece of work.
func (h *Handler) sshGatewaySession(ctx context.Context, account string, t sshgateway.Target, report func(string)) (jobssh.Key, error) {
	name := t.Name
	mgr := h.mcpServer.InteractiveManager()
	if mgr == nil {
		return jobssh.Key{}, fmt.Errorf(
			"interactive sessions are not available on this server, so %q cannot be started; "+
				"connect to a job you already have, as in 12345.0", name)
	}
	caller := interactive.Caller{Actor: account, Owner: account}

	if info, err := findInteractiveSession(ctx, mgr, caller, name); err != nil {
		return jobssh.Key{}, err
	} else if info != nil {
		return h.sshGatewayAwaitRunning(ctx, mgr, caller, name, *info, report)
	}

	report(fmt.Sprintf("Submitting session %q", name))
	info, err := mgr.Create(ctx, caller, interactive.CreateSpec{
		Name:     name,
		Cpus:     h.sshGatewaySessionSpec.Cpus,
		MemoryMB: h.sshGatewaySessionSpec.MemoryMB,
		DiskMB:   h.sshGatewaySessionSpec.DiskMB,
	})
	if err != nil {
		return jobssh.Key{}, fmt.Errorf("starting session %q: %w", name, err)
	}
	h.logger.Info(logging.DestinationHTTP, "SSH gateway started an interactive session",
		"account", account, "session", name, "job", info.JobID,
		// Whether they asked for this session by name or took the
		// default, and the username verbatim -- an operator
		// correlating a user's report to a job wants both.
		"explicit", t.Explicit, "username", t.Raw)
	return h.sshGatewayAwaitRunning(ctx, mgr, caller, name, *info, report)
}

// findInteractiveSession returns the caller's session called name, or
// nil when they have none.
func findInteractiveSession(ctx context.Context, mgr *interactive.Manager, caller interactive.Caller, name string) (*interactive.Info, error) {
	sessions, err := mgr.List(ctx, caller)
	if err != nil {
		return nil, fmt.Errorf("looking for session %q: %w", name, err)
	}
	for i := range sessions {
		if sessions[i].Name == name {
			return &sessions[i], nil
		}
	}
	return nil, nil
}

// sshGatewayAwaitRunning waits for a session's job to start.
//
// A job that is not running yet has no starter to reach, so returning
// its id would produce a connection failure that reads like the gateway
// is broken rather than like the queue being busy. A job that is HELD
// never will run, and saying so beats waiting out the timeout.
func (h *Handler) sshGatewayAwaitRunning(ctx context.Context, mgr *interactive.Manager, caller interactive.Caller, name string, info interactive.Info, report func(string)) (jobssh.Key, error) {
	if report == nil {
		report = func(string) {}
	}
	const (
		jobStatusRunning = 2
		jobStatusHeld    = 5
	)

	deadline := time.Now().Add(sshGatewaySessionWait)
	for {
		switch info.JobStatus {
		case jobStatusRunning:
			return jobssh.Key{Owner: caller.Owner, Cluster: info.ClusterID, Proc: info.ProcID}, nil
		case jobStatusHeld:
			reason := info.HoldReason
			if reason == "" {
				reason = "no reason given"
			}
			return jobssh.Key{}, fmt.Errorf("session %q (job %s) is held: %s", name, info.JobID, reason)
		}

		report(fmt.Sprintf("Session %q (job %s) is %s", name, info.JobID, strings.ToLower(info.Status)))

		if time.Now().After(deadline) {
			return jobssh.Key{}, fmt.Errorf(
				"session %q (job %s) is still %s after %s; it is queued and will keep waiting, so reconnect shortly",
				name, info.JobID, strings.ToLower(info.Status), sshGatewaySessionWait)
		}

		select {
		case <-ctx.Done():
			// Deliberately NOT removing the job. A caller who gave up
			// waiting almost always wants the session they asked for;
			// reconnecting picks it up once it starts, and the lease
			// and watchdog reclaim it if they never come back.
			// Removing it would make Ctrl-C destroy several minutes of
			// queue position.
			return jobssh.Key{}, fmt.Errorf(
				"stopped waiting for session %q (job %s). It is still starting -- reconnect to pick it up: %w",
				name, info.JobID, ctx.Err())
		case <-time.After(2 * time.Second):
		}

		found, err := findInteractiveSession(ctx, mgr, caller, name)
		if err != nil {
			return jobssh.Key{}, err
		}
		if found == nil {
			return jobssh.Key{}, fmt.Errorf("session %q disappeared while waiting for it to start", name)
		}
		info = *found
	}
}

// seedSSHGatewayClient makes sure the public client the gateway drives
// the device flow as exists.
//
// A public client with no secret, exactly as the device-authorize
// endpoint expects: it performs no client authentication, so a secret
// here would protect nothing and would have to be stored somewhere.
func (h *Handler) seedSSHGatewayClient(ctx context.Context) error {
	storage := h.oauth2Provider.GetStorage()
	if _, err := storage.GetClient(ctx, sshGatewayClientID); err == nil {
		return nil
	}
	client := &fosite.DefaultClient{
		ID:         sshGatewayClientID,
		Secret:     nil,
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		Scopes:     sshGatewayScopes,
		Public:     true,
	}
	if err := storage.CreateClient(ctx, client); err != nil {
		return fmt.Errorf("creating the SSH gateway OAuth2 client: %w", err)
	}
	h.markSeededClient(ctx, sshGatewayClientID, "SSH gateway")
	h.logger.Info(logging.DestinationHTTP, "Created the SSH gateway OAuth2 client",
		"client_id", sshGatewayClientID, "scopes", sshGatewayScopes)
	return nil
}

// SSHGatewayLockoutConfig configures the gateway's fail2ban-style
// lockout: how many failed logins a source may accumulate before new
// connections from it are refused, and for how long.
//
// The zero value is the enabled default. Only Disabled turns it off,
// so a deployment that says nothing gets the protection.
type SSHGatewayLockoutConfig struct {
	// Threshold and NetThreshold are the failure budgets for one host
	// and for the network around it. Zero means the package default.
	Threshold    int
	NetThreshold int

	// Window is how long failures are remembered, BanTime how long
	// the first lockout lasts, and MaxBanTime the ceiling the
	// doubling stops at. Zero means the package default.
	Window     time.Duration
	BanTime    time.Duration
	MaxBanTime time.Duration

	// TrustedNetworks are addresses and CIDR blocks that are never
	// counted and never locked out.
	TrustedNetworks []string

	// Disabled turns the lockout off entirely.
	Disabled bool
}

// sshGatewayBanlist builds the lockout list, or nil when it is off.
//
// A bad trusted-network list is a startup error rather than a warning.
// The setting exists so an operator cannot be locked out of their own
// gateway, and silently ignoring a typo in it would leave them
// believing they are safe.
func (h *Handler) sshGatewayBanlist() (*sshgateway.Banlist, error) {
	cfg := h.sshGatewayLockout
	if cfg.Disabled {
		h.logger.Warn(logging.DestinationHTTP,
			"The SSH gateway will not lock out sources that repeatedly fail to log in",
			"setting", "HTTP_API_SSH_GATEWAY_LOCKOUT_DISABLE")
		return nil, nil
	}

	trusted, err := sshgateway.ParseTrustedNetworks(cfg.TrustedNetworks)
	if err != nil {
		return nil, fmt.Errorf("HTTP_API_SSH_GATEWAY_LOCKOUT_TRUSTED: %w", err)
	}

	return sshgateway.NewBanlist(sshgateway.BanlistOptions{
		HostThreshold: cfg.Threshold,
		NetThreshold:  cfg.NetThreshold,
		Window:        cfg.Window,
		BanTime:       cfg.BanTime,
		MaxBanTime:    cfg.MaxBanTime,
		Trusted:       trusted,
		Logger:        h.logger,
	}), nil
}
