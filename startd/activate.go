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

package startd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/stream"
)

// ACTIVATE_CLAIM reply codes. These are the generic daemon-core reply integers
// from src/condor_includes/condor_commands.h (OK/NOT_OK) plus the two extended
// codes DCStartd::activateClaim can surface.
const (
	ActivateNotOK    = 0 // startd refused the activation
	ActivateOK       = 1 // activation accepted; the socket becomes the syscall sock
	ActivateTryAgain = 2 // CONDOR_TRY_AGAIN: transient refusal, retry with backoff
	ActivateError    = 3 // CONDOR_ERROR
)

// ActivateOptions tunes ActivateClaim.
type ActivateOptions struct {
	// StarterVersion is the integer starter version sent on the wire. The C++
	// client sends 2 ("the vanilla starter") and modern startds ignore it.
	// Zero means 2.
	StarterVersion int
	// MaxRetries bounds how many times a CONDOR_TRY_AGAIN reply is retried.
	// Matches RemoteResource::activateClaim: 6 retries with 1,2,3,4,5,5s
	// backoff. Negative disables retries entirely.
	MaxRetries int
	// WantFailureAd asks the startd (25.x+) to send a reply ad describing an
	// activation failure. Implemented by injecting
	// _condor_send_activation_failure_ad=true into the job ad, exactly like
	// DCStartd::activateClaim.
	WantFailureAd bool
}

// ActivatedClaim is a successfully activated claim: the live connection whose
// stream, per the ACTIVATE_CLAIM protocol, has become the remote-syscall
// channel between this process (the "shadow") and the starter the startd
// spawns. The startd relays its end of this very TCP connection to the starter
// as an inherited fd, so the caller must keep it open and serve syscalls on it
// for the lifetime of the job.
type ActivatedClaim struct {
	hc *client.HTCondorClient
	// ReplyAd is the optional ClassAd the startd sent along with the reply
	// code (empty on most success paths; may carry VacateReason on failure).
	ReplyAd *classad.ClassAd
}

// Stream returns the syscall stream. Encryption state (the claim session's
// AES key and message counters) carries over from the activation exchange.
func (a *ActivatedClaim) Stream() *stream.Stream { return a.hc.GetStream() }

// Close tears down the syscall connection.
func (a *ActivatedClaim) Close() error { return a.hc.Close() }

// ActivateFailure describes a non-OK ACTIVATE_CLAIM reply.
type ActivateFailure struct {
	// Code is the reply integer (ActivateNotOK, ActivateTryAgain after retries
	// are exhausted, or ActivateError).
	Code int
	// ReplyAd is the failure ad, if the startd sent one (may carry
	// VacateReason).
	ReplyAd *classad.ClassAd
}

func (e *ActivateFailure) Error() string {
	reason := ""
	if e.ReplyAd != nil {
		if v, ok := e.ReplyAd.EvaluateAttrString("VacateReason"); ok && v != "" {
			reason = ": " + v
		}
	}
	switch e.Code {
	case ActivateNotOK:
		return "startd: ACTIVATE_CLAIM refused (NOT_OK)" + reason
	case ActivateTryAgain:
		return "startd: ACTIVATE_CLAIM kept replying CONDOR_TRY_AGAIN" + reason
	default:
		return fmt.Sprintf("startd: ACTIVATE_CLAIM failed with reply code %d%s", e.Code, reason)
	}
}

// ActivateClaim activates the claim with a job: it opens a fresh connection on
// the claim session, performs the DCStartd::activateClaim wire exchange
//
//	put_secret(claim_id) + code(starter_version) + putClassAd(job_ad) + EOM
//	reply: code(int) [+ optional reply ClassAd] + EOM
//
// and, on OK, returns the live connection: the same socket then becomes the
// remote-syscall socket (the startd hands its end to the starter it spawns).
// A CONDOR_TRY_AGAIN reply is retried with the shadow's 1..5s backoff; other
// replies return an *ActivateFailure.
//
// The caller's job ad is copied, not mutated.
func (c *Client) ActivateClaim(ctx context.Context, jobAd *classad.ClassAd, opts *ActivateOptions) (*ActivatedClaim, error) {
	if jobAd == nil {
		return nil, fmt.Errorf("startd: ActivateClaim requires a job ad")
	}
	if opts == nil {
		opts = &ActivateOptions{}
	}
	starterVersion := opts.StarterVersion
	if starterVersion == 0 {
		starterVersion = 2
	}
	maxRetries := opts.MaxRetries
	if maxRetries == 0 {
		maxRetries = 6
	} else if maxRetries < 0 {
		maxRetries = 0
	}

	// Copy the job ad so the failure-ad marker never leaks into the caller's ad.
	ad := classad.New()
	for _, name := range jobAd.GetAttributes() {
		if expr, ok := jobAd.Lookup(name); ok {
			ad.InsertExpr(name, expr)
		}
	}
	if opts.WantFailureAd {
		_ = ad.Set("_condor_send_activation_failure_ad", true)
	}

	retryDelay := 1 * time.Second
	for attempt := 0; ; attempt++ {
		claim, fail, err := c.activateOnce(ctx, ad, starterVersion)
		if err != nil {
			return nil, err
		}
		if fail == nil {
			return claim, nil
		}
		if fail.Code != ActivateTryAgain || attempt >= maxRetries {
			return nil, fail
		}
		// RemoteResource::activateClaim: sleep 1,2,3,4,5,5,... seconds.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryDelay):
		}
		if retryDelay < 5*time.Second {
			retryDelay += time.Second
		}
	}
}

// activateOnce performs a single ACTIVATE_CLAIM exchange. A protocol-level
// refusal comes back as a non-nil *ActivateFailure (retryable when TRY_AGAIN);
// transport problems come back in err.
func (c *Client) activateOnce(ctx context.Context, jobAd *classad.ClassAd, starterVersion int) (*ActivatedClaim, *ActivateFailure, error) {
	hc, err := c.connect(ctx, cmdActivateClaim)
	if err != nil {
		return nil, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = hc.Close()
		}
	}()
	st := hc.GetStream()
	if err := requireEncrypted(st); err != nil {
		return nil, nil, err
	}

	w := newWriter(st)
	w.putSecret(ctx, c.claimID)
	w.putInt(ctx, starterVersion)
	w.putClassAd(ctx, jobAd)
	if err := w.finish(ctx); err != nil {
		return nil, nil, fmt.Errorf("startd: sending ACTIVATE_CLAIM: %w", err)
	}

	r := newReader(st)
	reply, err := r.getInt(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("startd: reading ACTIVATE_CLAIM reply code: %w", err)
	}
	// The C++ side sends an optional reply ad: peek_end_of_message() ||
	// getClassAd(). Reading the ad and mapping a clean end-of-message (EOF)
	// to "no ad" is the equivalent peek.
	var replyAd *classad.ClassAd
	if ad, aerr := r.getClassAd(ctx); aerr == nil {
		replyAd = ad
	} else if !errors.Is(aerr, io.EOF) {
		return nil, nil, fmt.Errorf("startd: reading ACTIVATE_CLAIM reply ad: %w", aerr)
	}

	if reply == ActivateOK {
		ok = true
		return &ActivatedClaim{hc: hc, ReplyAd: replyAd}, nil, nil
	}
	return nil, &ActivateFailure{Code: reply, ReplyAd: replyAd}, nil
}
