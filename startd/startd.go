// Copyright 2025 Morgridge Institute for Research
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

// Package startd implements the schedd->startd claim protocol: the CEDAR
// command exchange a schedd uses to REQUEST_CLAIM a slot, RELEASE_CLAIM it, and
// DEACTIVATE_CLAIM a running job on it. Every command rides the claim-id-derived
// ("match password") security session embedded in the startd's claim id, so no
// fresh DC_AUTHENTICATE handshake is performed once the session is imported.
//
// The wire format is a faithful port of HTCondor's
// src/condor_daemon_client/dc_startd.cpp:
//
//   - ClaimStartdMsg::writeMsg / readMsg / putExtraClaims (REQUEST_CLAIM)
//   - DCStartd::deactivateClaim                            (DEACTIVATE_CLAIM*)
//   - DCClaimIdMsg::writeMsg + send_vacate                 (RELEASE_CLAIM)
//
// A claim id has the form <sinful>#startd_bday#seq#[session_info]key; the
// leading <sinful> is the startd's command address the schedd connects to.
package startd

import (
	"context"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// HTCondor command integers for the claim protocol. Values are SCHED_VERS(400)
// plus the offsets in src/condor_includes/condor_commands.h; we define them here
// (rather than lean on cedar's commands package) so the deactivate variants and
// their exact wire numbers are unambiguous and self-documenting.
const (
	schedVers = 400

	cmdDeactivateClaim          = schedVers + 3   // 403 DEACTIVATE_CLAIM (graceful)
	cmdDeactivateClaimForcibly  = schedVers + 4   // 404 DEACTIVATE_CLAIM_FORCIBLY
	cmdDeactivateClaimJobDone   = schedVers + 13  // 413 DEACTIVATE_CLAIM_JOB_DONE
	cmdAlive                    = schedVers + 41  // 441 ALIVE
	cmdRequestClaim             = schedVers + 42  // 442 REQUEST_CLAIM
	cmdReleaseClaim             = schedVers + 43  // 443 RELEASE_CLAIM
	cmdActivateClaim            = schedVers + 44  // 444 ACTIVATE_CLAIM
	cmdDeactivateClaimFinalXfer = schedVers + 161 // 561 DEACTIVATE_CLAIM_FINAL_XFER
)

// REQUEST_CLAIM reply codes (condor_commands.h; see ClaimStartdMsg::readMsg).
const (
	ReplyNotOK      = 0 // claim rejected
	ReplyOK         = 1 // claim accepted
	ReplyLeftovers  = 3 // pslot claimed; leftover slot ad + (plaintext) claim id follow
	ReplyLeftovers2 = 5 // like 3, but the leftover claim id is a secret (encrypted)
	ReplySlotAd     = 7 // claimed slot ad follows; loops, then OK / leftovers
)

// DeactivateType selects which DEACTIVATE_CLAIM command variant to send.
type DeactivateType int

const (
	// DeactivateGraceful asks the starter to shut the job down gracefully
	// (DEACTIVATE_CLAIM).
	DeactivateGraceful DeactivateType = iota
	// DeactivateForcibly kills the job immediately (DEACTIVATE_CLAIM_FORCIBLY).
	DeactivateForcibly
	// DeactivateJobDone signals the job exited on its own; only understood by
	// startds >= 24.7.0 (DEACTIVATE_CLAIM_JOB_DONE). Callers that cannot confirm
	// the peer version should prefer DeactivateGraceful.
	DeactivateJobDone
	// DeactivateFinalXfer deactivates and performs the final file transfer
	// (DEACTIVATE_CLAIM_FINAL_XFER).
	DeactivateFinalXfer
)

func (d DeactivateType) command() int {
	switch d {
	case DeactivateForcibly:
		return cmdDeactivateClaimForcibly
	case DeactivateJobDone:
		return cmdDeactivateClaimJobDone
	case DeactivateFinalXfer:
		return cmdDeactivateClaimFinalXfer
	default:
		return cmdDeactivateClaim
	}
}

// Client talks to a single startd slot identified by its claim id. Construct it
// with New, which imports the claim-derived session into a cedar SessionCache;
// every command method then resumes that session (no fresh authentication).
//
// A Client is bound to one claim id (one slot). It is safe to reuse across
// sequential commands but not for concurrent commands on the same connection
// (each method opens its own connection).
type Client struct {
	// addr is the startd's command sinful, taken from the claim id.
	addr string
	// claimID is the full secret claim id handed out by the startd.
	claimID string
	// sessionID is the security session id derived from the claim id.
	sessionID string
	// cache holds the imported claim session. The client resumes sessionID out
	// of it on every command.
	cache *security.SessionCache
}

// Options tunes how New imports the claim session.
type Options struct {
	// Cache is the session cache to import the claim session into. If nil, New
	// allocates a private cache (fine for a one-shot claim; share a cache when a
	// long-lived schedd manages many claims to one startd).
	Cache *security.SessionCache
	// PeerFQU overrides the identity attributed to the startd over the session.
	// Defaults to execute-side@matchsession (the schedd's view of a startd).
	PeerFQU string
}

// New builds a Client for a startd slot from its claim id. It parses the startd
// command address out of the claim id and imports the claim-derived security
// session (deriving the AES-256-GCM key from the claim secret) into the cache so
// subsequent commands resume it. The extra claim commands (REQUEST/RELEASE/
// DEACTIVATE/ACTIVATE) are mapped to the session so a command_map lookup would
// also find it, though the client always resumes by explicit session id.
func New(claimID string, opts *Options) (*Client, error) {
	if opts == nil {
		opts = &Options{}
	}
	cache := opts.Cache
	if cache == nil {
		cache = security.NewSessionCache()
	}

	addr := claimSinful(claimID)
	if addr == "" {
		return nil, fmt.Errorf("startd: claim id carries no startd address")
	}

	sesid, err := security.ImportClaimSession(cache, claimID, security.ClaimSessionOptions{
		PeerAddr: addr,
		PeerFQU:  opts.PeerFQU,
		ExtraValidCommands: []int{
			cmdRequestClaim, cmdReleaseClaim, cmdActivateClaim,
			cmdDeactivateClaim, cmdDeactivateClaimForcibly,
			cmdDeactivateClaimJobDone, cmdDeactivateClaimFinalXfer,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("startd: importing claim session: %w", err)
	}

	return &Client{
		addr:      addr,
		claimID:   claimID,
		sessionID: sesid,
		cache:     cache,
	}, nil
}

// Addr returns the startd command address parsed from the claim id.
func (c *Client) Addr() string { return c.addr }

// SessionID returns the security session id derived from the claim id.
func (c *Client) SessionID() string { return c.sessionID }

// connect dials the startd and resumes the claim session for the given command.
func (c *Client) connect(ctx context.Context, command int) (*client.HTCondorClient, error) {
	sec := &security.SecurityConfig{
		Command:      command,
		PeerName:     c.addr,
		SessionCache: c.cache,
		SessionID:    c.sessionID,
	}
	hc, err := client.ConnectAndAuthenticate(ctx, c.addr, sec)
	if err != nil {
		return nil, fmt.Errorf("startd: connect/resume session for command %d: %w", command, err)
	}
	return hc, nil
}

// ClaimRequest describes a REQUEST_CLAIM. RequestAd is the job/request ClassAd
// the startd matches against its slot (Requirements, RequestCpus/Memory/Disk,
// Owner, JobUniverse, ...); RequestClaim injects the capability and alive
// attributes the schedd's contactStartd adds before sending.
type ClaimRequest struct {
	// RequestAd is the caller's job/request ad. It is copied, not mutated.
	RequestAd *classad.ClassAd
	// SchedulerAddr is the sinful the startd sends ALIVE keepalives to (this
	// schedd's command address). Required.
	SchedulerAddr string
	// AliveInterval is the keepalive interval (seconds) proposed to the startd.
	AliveInterval int
	// ScheddName is advertised to the startd as ATTR_SCHEDD_NAME.
	ScheddName string
	// ExtraClaims are additional claim ids (for multi-slot / pslot splitting).
	// Sent only when non-empty, matching dc_startd's version-gated putExtraClaims
	// (over a match session the peer version is unknown, so the "no extra claims,
	// send nothing" branch applies).
	ExtraClaims []string
	// ClaimPSlot requests that a partitionable slot itself become Claimed.
	ClaimPSlot bool
	// PSlotClaimLease is the pslot claim lifetime (only when ClaimPSlot).
	PSlotClaimLease int
	// NumDynamicSlots is how many dslots to carve from a pslot for this request.
	// Defaults to 1 (dc_startd's default); ignored by a static slot.
	NumDynamicSlots int
	// SendLeftovers advertises the schedd understands the pslot-leftovers reply.
	// nil means true (dc_startd's CLAIM_PARTITIONABLE_LEFTOVERS default).
	SendLeftovers *bool
}

// ClaimedSlot is one (claim id, slot ad) pair returned via a ReplySlotAd loop.
type ClaimedSlot struct {
	ClaimID string
	SlotAd  *classad.ClassAd
}

// ClaimResult is the parsed REQUEST_CLAIM reply. OK is true for the accept codes
// (1, and 3/5/7 which are accept-with-extras); a caller that only wants the
// simple case can check OK and ignore the extras.
type ClaimResult struct {
	// Code is the final reply integer (after any ReplySlotAd loop): OK,
	// NotOK, Leftovers, or Leftovers2.
	Code int
	// OK reports whether the claim was accepted.
	OK bool
	// ClaimedSlots holds the slot ads sent under ReplySlotAd (SEND_CLAIMED_AD).
	ClaimedSlots []ClaimedSlot
	// HasLeftovers is set when the startd returned pslot leftovers (code 3/5).
	HasLeftovers bool
	// LeftoverClaimID / LeftoverSlotAd carry the leftover pslot info (code 3/5).
	LeftoverClaimID string
	LeftoverSlotAd  *classad.ClassAd
}

func boolPtrOrTrue(p *bool) bool {
	if p == nil {
		return true
	}
	return *p
}

// buildRequestAd copies the caller's request ad and injects the schedd-side
// attributes ClaimStartdMsg::writeMsg and Scheduler::contactStartd add.
func (r *ClaimRequest) buildRequestAd() *classad.ClassAd {
	ad := classad.New()
	if r.RequestAd != nil {
		// Shallow-copy every attribute so we do not mutate the caller's ad.
		for _, name := range r.RequestAd.GetAttributes() {
			if expr, ok := r.RequestAd.Lookup(name); ok {
				ad.InsertExpr(name, expr)
			}
		}
	}

	// From ClaimStartdMsg::writeMsg.
	_ = ad.Set("_condor_SEND_LEFTOVERS", boolPtrOrTrue(r.SendLeftovers))
	_ = ad.Set("_condor_SECURE_CLAIM_ID", true)
	_ = ad.Set("_condor_SEND_CLAIMED_AD", true)
	_ = ad.Set("_condor_CLAIM_PARTITIONABLE_SLOT", r.ClaimPSlot)
	if r.ClaimPSlot {
		_ = ad.Set("_condor_PARTITIONABLE_SLOT_CLAIM_TIME", int64(r.PSlotClaimLease))
		_ = ad.Set("_condor_WANT_MATCHING", true)
	}
	numDslots := r.NumDynamicSlots
	if numDslots == 0 {
		numDslots = 1
	}
	_ = ad.Set("_condor_NUM_DYNAMIC_SLOTS", int64(numDslots))

	// From Scheduler::contactStartd (schedd.cpp). Since 25.3 the startd assumes
	// true when absent, but we send them so older startds behave identically.
	_ = ad.Set("StartdSendsAlives", true)
	// ATTR_STARTER_HANDLES_ALIVES is literally "_condor_StartdHandlesAlives".
	_ = ad.Set("_condor_StartdHandlesAlives", true)
	if r.ScheddName != "" {
		_ = ad.Set("ScheddName", r.ScheddName)
	}
	return ad
}

// RequestClaim sends REQUEST_CLAIM and parses the reply. The message is:
//
//	put_secret(claim_id) + putClassAd(request) + put(scheduler_addr) +
//	put(alive_interval) [+ extra-claims block] + end_of_message
//
// On an encrypted claim session a "secret" is just an encrypted (length-prefixed)
// string, identical on the wire to a normal string put -- so we compose the whole
// message with the streaming message API rather than the stream-level PutSecret
// (which would frame the secret as its own end-of-message).
func (c *Client) RequestClaim(ctx context.Context, req *ClaimRequest) (*ClaimResult, error) {
	if req == nil || req.SchedulerAddr == "" {
		return nil, fmt.Errorf("startd: RequestClaim requires a scheduler address")
	}
	hc, err := c.connect(ctx, cmdRequestClaim)
	if err != nil {
		return nil, err
	}
	defer func() { _ = hc.Close() }()
	st := hc.GetStream()

	if err := requireEncrypted(st); err != nil {
		return nil, err
	}

	w := newWriter(st)
	w.putSecret(ctx, c.claimID)
	w.putClassAd(ctx, req.buildRequestAd())
	w.putString(ctx, req.SchedulerAddr)
	w.putInt(ctx, req.AliveInterval)
	// putExtraClaims: over a match session the peer version is unknown, so
	// dc_startd sends the block only when there are extra claims.
	if len(req.ExtraClaims) > 0 {
		w.putInt(ctx, len(req.ExtraClaims))
		for _, ec := range req.ExtraClaims {
			w.putSecret(ctx, ec)
		}
	}
	if err := w.finish(ctx); err != nil {
		return nil, fmt.Errorf("startd: sending REQUEST_CLAIM: %w", err)
	}

	return c.readClaimReply(ctx, st)
}

// readClaimReply parses the REQUEST_CLAIM response, mirroring
// ClaimStartdMsg::readMsg.
func (c *Client) readClaimReply(ctx context.Context, st *stream.Stream) (*ClaimResult, error) {
	r := newReader(st)
	reply, err := r.getInt(ctx)
	if err != nil {
		return nil, fmt.Errorf("startd: reading claim reply code: %w", err)
	}

	res := &ClaimResult{}

	// ReplySlotAd loops: (secret claim id, slot ad, next code)*.
	for reply == ReplySlotAd {
		cid, err := r.getString(ctx)
		if err != nil {
			return nil, fmt.Errorf("startd: reading claimed slot claim id: %w", err)
		}
		ad, err := r.getClassAd(ctx)
		if err != nil {
			return nil, fmt.Errorf("startd: reading claimed slot ad: %w", err)
		}
		reply, err = r.getInt(ctx)
		if err != nil {
			return nil, fmt.Errorf("startd: reading reply code after slot ad: %w", err)
		}
		res.ClaimedSlots = append(res.ClaimedSlots, ClaimedSlot{ClaimID: cid, SlotAd: ad})
	}

	res.Code = reply
	switch reply {
	case ReplyOK:
		res.OK = true
	case ReplyNotOK:
		res.OK = false
	case ReplyLeftovers, ReplyLeftovers2:
		// Code 3 reads a plaintext claim id; code 5 reads a secret. On an
		// encrypted session both are length-prefixed encrypted strings, so
		// getString handles both.
		cid, err := r.getString(ctx)
		if err != nil {
			return nil, fmt.Errorf("startd: reading leftover claim id: %w", err)
		}
		ad, err := r.getClassAd(ctx)
		if err != nil {
			return nil, fmt.Errorf("startd: reading leftover slot ad: %w", err)
		}
		res.HasLeftovers = true
		res.LeftoverClaimID = cid
		res.LeftoverSlotAd = ad
		res.OK = true
	default:
		return res, fmt.Errorf("startd: unknown REQUEST_CLAIM reply code %d", reply)
	}
	return res, nil
}

// ReleaseClaim sends RELEASE_CLAIM. Per DCClaimIdMsg/send_vacate this is
// fire-and-forget: put_secret(claim_id) + end_of_message, with no reply read
// (the startd's command_release_claim sends nothing on success).
func (c *Client) ReleaseClaim(ctx context.Context) error {
	hc, err := c.connect(ctx, cmdReleaseClaim)
	if err != nil {
		return err
	}
	defer func() { _ = hc.Close() }()
	st := hc.GetStream()
	if err := requireEncrypted(st); err != nil {
		return err
	}

	w := newWriter(st)
	w.putSecret(ctx, c.claimID)
	if err := w.finish(ctx); err != nil {
		return fmt.Errorf("startd: sending RELEASE_CLAIM: %w", err)
	}
	return w.err
}

// DeactivateClaim sends a DEACTIVATE_CLAIM variant: put_secret(claim_id) +
// end_of_message, then reads the response ClassAd (ATTR_START etc.). Mirrors
// DCStartd::deactivateClaim. Returns the response ad.
func (c *Client) DeactivateClaim(ctx context.Context, dt DeactivateType) (*classad.ClassAd, error) {
	hc, err := c.connect(ctx, dt.command())
	if err != nil {
		return nil, err
	}
	defer func() { _ = hc.Close() }()
	st := hc.GetStream()
	if err := requireEncrypted(st); err != nil {
		return nil, err
	}

	w := newWriter(st)
	w.putSecret(ctx, c.claimID)
	if err := w.finish(ctx); err != nil {
		return nil, fmt.Errorf("startd: sending DEACTIVATE_CLAIM: %w", err)
	}

	r := newReader(st)
	ad, err := r.getClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("startd: reading DEACTIVATE_CLAIM response ad: %w", err)
	}
	return ad, nil
}

// requireEncrypted guards the put_secret==put_string equivalence the claim wire
// relies on: it holds only when the stream is already encrypted (which a claim
// session always is: Encryption="YES" in the derived policy). If a session ever
// resumed without encryption, a bare string would leak the claim id and the
// startd (expecting an encrypted secret) would misread it, so fail loudly.
func requireEncrypted(st *stream.Stream) error {
	if !st.IsEncrypted() {
		return fmt.Errorf("startd: claim session stream is not encrypted; refusing to send claim secrets in the clear")
	}
	return nil
}
