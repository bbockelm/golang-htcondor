// Implementation of condor_ssh_to_job over the CEDAR wire, exposed as
// Go-native primitives that return an *ssh.Client backed by golang.org/x/crypto/ssh.
//
// Flow (mirrors the C++ tool, see reference/htcondor/src/condor_tools/ssh_to_job.cpp):
//
//  1. GET_JOB_CONNECT_INFO to schedd:
//       - Returns StarterIpAddr + ClaimId for an on-demand session the schedd
//         minted on the starter on the user's behalf.
//       - Schedd handler: condor_schedd.V6/schedd.cpp:18044
//       - Schedd RPC stub:   condor_daemon_client/dc_schedd.cpp:1704
//
//  2. START_SSHD to starter, resuming the schedd-minted session:
//       - Returns a base64 RSA private key (for the user) and a base64 SSH
//         host pubkey (for known_hosts pinning).
//       - Starter handler: condor_starter.V6.1/starter.cpp:1260
//       - After the response ClassAd is fully received, the starter dup2's
//         the same TCP socket onto sshd's stdin/stdout
//         (condor_starter.V6.1/starter.cpp:1665) — from then on the wire is
//         raw SSH.
//
//  3. Hand the underlying net.Conn to golang.org/x/crypto/ssh.NewClientConn.
//     Cedar's Stream uses the bare net.Conn (not a buffered reader) and its
//     receive buffer is empty after EndMessageRead, so no bytes are lost in
//     the handoff.
//
// SCM_RIGHTS is *not* on the wire anywhere in this flow — it appears in the
// C++ tool only as a same-host trick to feed the post-handshake socket fd to
// a child process running OpenSSH's ProxyCommand. We bypass that entirely.

package htcondor

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"golang.org/x/crypto/ssh"
)

// startSSHDCommand is the CEDAR command code for asking a starter to spawn
// sshd and return its host/client keys. STARTER_COMMANDS_BASE = 1500, +2.
// See reference/htcondor/src/condor_includes/condor_commands.h:493.
const startSSHDCommand = 1502

// Session-info we ask the starter to use for the schedd-minted session. We
// pin Encryption=YES because the START_SSHD reply ClassAd contains the user's
// private SSH key in cleartext base64, and Integrity=YES so the request can't
// be silently mutated.
const sshSessionInfo = `[Encryption="YES";Integrity="YES";]`

// JobConnectInfo is the result of a GET_JOB_CONNECT_INFO call against the
// schedd. It is everything you need to talk to the starter on behalf of the
// user without going through the schedd again.
type JobConnectInfo struct {
	StarterAddr    string // sinful string of the starter
	ClaimID        string // claim id for the schedd-minted starter session
	StarterVersion string // starter's HTCondor version banner
	RemoteHost     string // slot name (cosmetic only, useful for logs)

	// Embedded for downstream calls; we keep the schedd's address around so
	// callers can retry or report errors that mention the originating schedd.
	scheddAddr string
}

// GetJobConnectInfo invokes the schedd's GET_JOB_CONNECT_INFO RPC for
// ClusterId.ProcId and returns the address of the starter and the claim id
// for an on-demand session. The schedd authenticates the caller and verifies
// they own the job before minting the session.
func (s *Schedd) GetJobConnectInfo(ctx context.Context, clusterID, procID int) (*JobConnectInfo, error) {
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, commands.GET_JOB_CONNECT_INFO, "CLIENT", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", s.address, err)
	}
	defer func() { _ = htcondorClient.Close() }()

	stream := htcondorClient.GetStream()

	requestAd := classad.New()
	_ = requestAd.Set("ClusterId", int64(clusterID))
	_ = requestAd.Set("ProcId", int64(procID))
	_ = requestAd.Set("SessionInfo", sshSessionInfo)

	reqMsg := message.NewMessageForStream(stream)
	if err := reqMsg.PutClassAd(ctx, requestAd); err != nil {
		return nil, fmt.Errorf("failed to send GET_JOB_CONNECT_INFO request: %w", err)
	}
	if err := reqMsg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to finish GET_JOB_CONNECT_INFO request: %w", err)
	}

	respMsg := message.NewMessageFromStream(stream)
	respAd, err := respMsg.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read GET_JOB_CONNECT_INFO response: %w", err)
	}

	if ok, found := respAd.EvaluateAttrBool("Result"); !found || !ok {
		errStr, _ := respAd.EvaluateAttrString("ErrorString")
		holdReason, _ := respAd.EvaluateAttrString("HoldReason")
		jobStatus, _ := respAd.EvaluateAttrInt("JobStatus")
		switch {
		case errStr != "":
			return nil, fmt.Errorf("schedd refused GET_JOB_CONNECT_INFO for %d.%d: %s", clusterID, procID, errStr)
		case holdReason != "":
			return nil, fmt.Errorf("schedd refused GET_JOB_CONNECT_INFO for %d.%d (job %d held): %s", clusterID, procID, jobStatus, holdReason)
		default:
			return nil, fmt.Errorf("schedd refused GET_JOB_CONNECT_INFO for %d.%d (status=%d)", clusterID, procID, jobStatus)
		}
	}

	info := &JobConnectInfo{scheddAddr: s.address}
	info.StarterAddr, _ = respAd.EvaluateAttrString("StarterIpAddr")
	info.ClaimID, _ = respAd.EvaluateAttrString("ClaimId")
	info.StarterVersion, _ = respAd.EvaluateAttrString("Version")
	info.RemoteHost, _ = respAd.EvaluateAttrString("RemoteHost")

	if info.StarterAddr == "" || info.ClaimID == "" {
		return nil, fmt.Errorf("malformed GET_JOB_CONNECT_INFO response: missing StarterIpAddr or ClaimId")
	}
	return info, nil
}

// sshKeyPair holds the per-session keys the starter generates. These come
// out of the starter response base64-encoded.
type sshKeyPair struct {
	remoteUser     string
	hostPublicKey  ssh.PublicKey // for known_hosts pinning
	clientIdentity ssh.Signer    // for PublicKeys auth
}

// startSSHDOnStarter performs the START_SSHD handshake and returns the raw
// post-handshake net.Conn (positioned at the first SSH byte) plus the keys.
// Callers should hand the conn to ssh.NewClientConn — it must not be wrapped
// in any further buffered reader, since cedar's Stream reads directly from
// the conn and any extra buffering would swallow sshd's banner.
func (info *JobConnectInfo) startSSHDOnStarter(ctx context.Context) (net.Conn, *sshKeyPair, error) {
	claim := security.ParseClaimID(info.ClaimID)
	if claim == nil || claim.SecSessionID() == "" {
		return nil, nil, fmt.Errorf("malformed ClaimId: missing session id")
	}

	// Build a one-shot session cache pre-populated with the schedd-minted
	// starter session so cedar's ClientHandshake can resume it by command
	// code rather than performing a full DC_AUTHENTICATE round-trip.
	//
	// We construct the SessionEntry by hand instead of using cedar's
	// CreateNonNegotiatedSession. The reason: HTCondor's ExportSecSessionInfo
	// emits CryptoMethods with a *backwards-compat* preferred order
	// (BLOWFISH > 3DES > AES — see condor_secman.cpp:getPreferredOldCryptProtocol)
	// and the modern full list under CryptoMethodsList. cedar v0.0.23 picks
	// from the legacy CryptoMethods field, lands on BLOWFISH, and then
	// silently disables encryption because its setupStreamEncryption only
	// arms AES-GCM. The starter encrypts; we don't; the body looks like
	// noise to the starter and START_SSHD times out reading it.
	//
	// We pin AES-GCM here because the modern HTCondor stack always supports
	// it (it's the only one in CryptoMethodsList that cedar's stream layer
	// actually implements).
	entry, err := buildAESStarterSession(claim, info.StarterAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to import starter session: %w", err)
	}
	cache := security.NewSessionCache()
	cache.Store(entry)
	cache.MapCommand("", info.StarterAddr, fmt.Sprintf("%d", startSSHDCommand), claim.SecSessionID())

	// Build the SecurityConfig from the configured CLIENT auth methods
	// (so SSL/Kerberos/etc. are offered when configured) but keep the
	// AES pin and the REQUIRED encryption/integrity levels — those
	// matter for the session-resume happy path where ExportSecSessionInfo
	// emits a legacy CryptoMethods preferred order that cedar would
	// otherwise misinterpret. Auth methods only kick in if the resume
	// fails and ClientHandshake falls back to fresh authentication;
	// in that fallback path we want the same configured methods every
	// other client uses.
	//
	// Token is empty here: the schedd-minted ClaimID seeded in `cache`
	// IS the credential, and we want NewClientSecurityConfig to leave
	// AuthMethods alone rather than prepending TOKEN.
	secConfig, err := NewClientSecurityConfig(ctx, "", info.StarterAddr, startSSHDCommand, "CLIENT", cache)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build starter security config: %w", err)
	}
	secConfig.CryptoMethods = []security.CryptoMethod{security.CryptoAES}
	secConfig.Authentication = security.SecurityRequired
	secConfig.Encryption = security.SecurityRequired
	secConfig.Integrity = security.SecurityRequired

	htcondorClient, err := client.ConnectAndAuthenticate(ctx, info.StarterAddr, secConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resume starter session at %s: %w", info.StarterAddr, err)
	}
	// We deliberately do NOT defer Close on success — ownership of the
	// underlying net.Conn transfers to the SSH client.
	closeOnFail := htcondorClient
	defer func() {
		if closeOnFail != nil {
			_ = closeOnFail.Close()
		}
	}()

	stream := htcondorClient.GetStream()

	// Send the START_SSHD request ClassAd. The server-side handler at
	// reference/htcondor/src/condor_starter.V6.1/starter.cpp:1276 reads this
	// next. Shell/ATTR_NAME are optional; we leave Shell empty so the user's
	// configured shell on the execute node is used.
	reqAd := classad.New()
	if info.RemoteHost != "" {
		_ = reqAd.Set("Name", info.RemoteHost)
	}
	reqMsg := message.NewMessageForStream(stream)
	if err := reqMsg.PutClassAd(ctx, reqAd); err != nil {
		return nil, nil, fmt.Errorf("failed to send START_SSHD request: %w", err)
	}
	if err := reqMsg.FinishMessage(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to finish START_SSHD request: %w", err)
	}

	// Read the response ClassAd. Per starter.cpp:1645-1655 it contains
	// Result, RemoteUser, SshPublicServerKey, SshPrivateClientKey.
	respMsg := message.NewMessageFromStream(stream)
	respAd, err := respMsg.GetClassAd(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read START_SSHD response: %w", err)
	}

	if ok, found := respAd.EvaluateAttrBool("Result"); !found || !ok {
		errStr, _ := respAd.EvaluateAttrString("ErrorString")
		retry, _ := respAd.EvaluateAttrBool("Retry")
		if errStr != "" {
			return nil, nil, fmt.Errorf("starter rejected START_SSHD: %s (retry=%t)", errStr, retry)
		}
		return nil, nil, fmt.Errorf("starter rejected START_SSHD (retry=%t)", retry)
	}

	keys, err := parseSSHReplyKeys(respAd)
	if err != nil {
		return nil, nil, err
	}

	rawConn := stream.GetConnection()
	if rawConn == nil {
		return nil, nil, errors.New("cedar stream has no underlying net.Conn")
	}

	// Transfer ownership of the conn to the caller. Suppress the deferred
	// close. Any further reads/writes to the cedar stream are forbidden
	// (they would corrupt the SSH framing).
	closeOnFail = nil
	return rawConn, keys, nil
}

func parseSSHReplyKeys(respAd *classad.ClassAd) (*sshKeyPair, error) {
	remoteUser, _ := respAd.EvaluateAttrString("RemoteUser")
	if remoteUser == "" {
		return nil, errors.New("START_SSHD response missing RemoteUser")
	}

	// HTCondor's #define is ATTR_SSH_PUBLIC_SERVER_KEY = "SSHPublicServerKey"
	// (uppercase SSH). The PelicanPlatform/classad Go bindings appear to be
	// case-sensitive, so look for the canonical form first.
	pubB64, _ := respAd.EvaluateAttrString("SSHPublicServerKey")
	if pubB64 == "" {
		pubB64, _ = respAd.EvaluateAttrString("SshPublicServerKey")
	}
	if pubB64 == "" {
		return nil, errors.New("START_SSHD response missing SSHPublicServerKey")
	}
	pubBytes, err := decodeCondorBase64(pubB64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode SshPublicServerKey: %w", err)
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SshPublicServerKey: %w", err)
	}

	privB64, _ := respAd.EvaluateAttrString("SSHPrivateClientKey")
	if privB64 == "" {
		privB64, _ = respAd.EvaluateAttrString("SshPrivateClientKey")
	}
	if privB64 == "" {
		return nil, errors.New("START_SSHD response missing SSHPrivateClientKey")
	}
	privBytes, err := decodeCondorBase64(privB64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode SshPrivateClientKey: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SshPrivateClientKey: %w", err)
	}

	return &sshKeyPair{
		remoteUser:     remoteUser,
		hostPublicKey:  hostKey,
		clientIdentity: signer,
	}, nil
}

// JobShellOptions tunes the SSH session. Zero values are fine for typical use.
type JobShellOptions struct {
	// HandshakeTimeout caps the SSH handshake (NewClientConn). Default 30s.
	HandshakeTimeout time.Duration
}

// OpenJobShell is the end-to-end convenience: GET_JOB_CONNECT_INFO + START_SSHD
// + crypto/ssh handshake. Returns a live *ssh.Client. The caller owns it and
// must Close() to release the underlying TCP connection.
//
// Briefly transient errors at the schedd are retried (up to ~30 s) — the same
// race the C++ condor_ssh_to_job tool retries through after a job first hits
// Running but before the startd has registered the starter address.
func (s *Schedd) OpenJobShell(ctx context.Context, clusterID, procID int, opts *JobShellOptions) (*ssh.Client, error) {
	info, err := getJobConnectInfoWithBackoff(ctx, s, clusterID, procID, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return info.OpenSSH(ctx, opts)
}

// getJobConnectInfoWithBackoff retries GET_JOB_CONNECT_INFO while the schedd
// returns one of the transient "retry_is_sensible" errors documented at
// schedd.cpp:18241/18224. Other failures (e.g. permission, malformed reply)
// short-circuit immediately.
func getJobConnectInfoWithBackoff(ctx context.Context, s *Schedd, clusterID, procID int, maxWait time.Duration) (*JobConnectInfo, error) {
	deadline := time.Now().Add(maxWait)
	var lastErr error
	for {
		callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		info, err := s.GetJobConnectInfo(callCtx, clusterID, procID)
		cancel()
		if err == nil {
			return info, nil
		}
		lastErr = err
		msg := err.Error()
		retryable := strings.Contains(msg, "Failed to read address of starter") ||
			strings.Contains(msg, "Failed to get address of starter") ||
			strings.Contains(msg, "is not running") ||
			strings.Contains(msg, "blocked fetching")
		if !retryable || time.Now().After(deadline) {
			return nil, lastErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// OpenSSH performs the START_SSHD step + crypto/ssh handshake against an
// already-located starter. This is the seam for tests and for advanced
// callers that want to look at the slot/version metadata first.
func (info *JobConnectInfo) OpenSSH(ctx context.Context, opts *JobShellOptions) (*ssh.Client, error) {
	if opts == nil {
		opts = &JobShellOptions{}
	}
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	rawConn, keys, err := info.startSSHDOnStarter(ctx)
	if err != nil {
		return nil, err
	}

	cfg := &ssh.ClientConfig{
		User:            keys.remoteUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(keys.clientIdentity)},
		HostKeyCallback: ssh.FixedHostKey(keys.hostPublicKey),
		Timeout:         timeout,
	}

	// Bound the SSH handshake with a deadline derived from the context, to
	// keep a flaky starter from blocking us forever.
	if dl, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(dl)
	} else {
		_ = rawConn.SetDeadline(time.Now().Add(timeout))
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, "condor-job."+info.RemoteHost, cfg)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("ssh handshake failed (peer %s, user %s): %w", info.StarterAddr, keys.remoteUser, err)
	}
	// Clear the handshake deadline; the SSH client manages its own keepalives.
	_ = rawConn.SetDeadline(time.Time{})

	return ssh.NewClient(sshConn, chans, reqs), nil
}

// buildAESStarterSession constructs a cedar SessionEntry from a claim ID
// returned by GET_JOB_CONNECT_INFO. The claim carries a non-negotiated
// (inherited) session the schedd minted for us; cedar re-derives the key and
// cipher from it exactly as HTCondor does — keying on the first method of the
// exported CryptoMethodsList (AES for any modern pool, since HTCondor uses the
// list head) and deriving the key with HKDF(salt="htcondor", info="keygen").
// cedar's stream layer implements only AES-GCM, so CreateNonNegotiatedSession
// rejects a session keyed on anything else.
//
// (This used to reimplement the derivation locally to force AES, because an
// older cedar read the legacy single CryptoMethods field — typically BLOWFISH
// — and used the wrong HKDF salt. Both are fixed in cedar now, so we just
// delegate.)
func buildAESStarterSession(claim *security.ClaimID, peerAddr string) (*security.SessionEntry, error) {
	return security.CreateNonNegotiatedSession(&security.InheritedSession{
		Type:        security.SessionTypeNormal,
		SessionID:   claim.SecSessionID(),
		SessionInfo: claim.SecSessionInfo(),
		SessionKey:  claim.SecSessionKey(),
	}, peerAddr)
}

// decodeCondorBase64 decodes a base64 blob produced by HTCondor's
// condor_base64_encode helper. By default (include_newline=true) HTCondor
// wraps base64 output at 64 characters with LF newlines, which Go's
// base64.StdEncoding.DecodeString does not tolerate. We strip ASCII
// whitespace before decoding to handle both wrapped and unwrapped variants.
func decodeCondorBase64(s string) ([]byte, error) {
	stripped := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(stripped)
}

// ParseJobID parses "cluster.proc" into a (cluster, proc) pair.
// Used by httpserver routes; lives here so it has a single owner.
func ParseJobID(s string) (int, int, error) {
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		return 0, 0, fmt.Errorf("expected cluster.proc, got %q", s)
	}
	var cluster, proc int
	if _, err := fmt.Sscanf(s, "%d.%d", &cluster, &proc); err != nil {
		return 0, 0, fmt.Errorf("invalid job id %q: %w", s, err)
	}
	return cluster, proc, nil
}
