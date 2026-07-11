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
	"fmt"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
)

// Alive is the HTCondor ALIVE command integer (SCHED_VERS+41). Unlike the other
// commands in this package it travels startd->schedd: the startd holding a claim
// sends it to the schedd (every lease/3) to renew the claim lease. The schedd
// registers it at READ authorization (see the golang-ap match package, which is
// the authoritative server peer of this wire).
const Alive = cmdAlive

// AliveScheddForgotClaim is the reply the schedd sends when it has no record of
// the claim ("schedd forgot the claim"). SendAlive returns it as a value with a
// nil error; the caller should relinquish/kill the claim. It mirrors the -1 the
// C++ schedd sends and Claim::sendAliveResponseHandler acts on
// (src/condor_startd.V6/claim.cpp).
const AliveScheddForgotClaim = -1

// SendAlive sends one ALIVE keepalive to the schedd to renew a claim's lease and
// returns the schedd's reply integer. It is the client half of the wire the
// golang-ap match package's RegisterALIVE handler serves, and a faithful port of
// Claim::sendAlive / sendAliveConnectHandler / sendAliveResponseHandler
// (src/condor_startd.V6/claim.cpp): connect to the schedd, startCommand(ALIVE)
// over the claim-id-derived match session (no fresh DC_AUTHENTICATE), then
// put_secret(claimID) + end_of_message, then read the int reply.
//
// The reply is either the schedd's alive_interval (>= 0), which the caller uses
// to reschedule the next keepalive, or AliveScheddForgotClaim (-1), meaning the
// schedd no longer recognizes the claim and the caller should kill it. Both are
// returned as a value with a nil error. A non-nil error means the exchange
// itself failed (dial, session resumption, encode, or read) -- distinct from the
// -1 "schedd forgot the claim" value, which is a successful exchange.
//
// scheddAddr is the schedd's command sinful (the address the claim was made to
// keepalive, i.e. the startd's stored client address). claimID is the full
// secret claim id handed out by the startd. cache holds the claim-derived
// security session: if the session is already present (the startd imported it
// when it minted/accepted the claim) it is resumed as-is; if absent it is
// imported here (PeerAddr=scheddAddr, submit-side identity -- the startd's view
// of the schedd) so a standalone caller still works. cache must be non-nil.
func SendAlive(ctx context.Context, scheddAddr, claimID string, cache *security.SessionCache) (int, error) {
	if cache == nil {
		return 0, fmt.Errorf("startd: SendAlive requires a session cache")
	}
	if scheddAddr == "" {
		return 0, fmt.Errorf("startd: SendAlive requires a schedd address")
	}

	sessionID := security.ParseClaimIDStrict(claimID).SecSessionID()
	if sessionID == "" {
		return 0, fmt.Errorf("startd: claim id carries no security session")
	}

	// Resume the pre-existing claim session if the startd already imported it;
	// otherwise import it now so a standalone caller (and the unit tests) works.
	if _, ok := cache.LookupNonExpired(sessionID); !ok {
		if _, err := security.ImportClaimSession(cache, claimID, security.ClaimSessionOptions{
			PeerAddr:           scheddAddr,
			PeerFQU:            security.SubmitSideMatchSessionFQU,
			ExtraValidCommands: []int{cmdAlive},
		}); err != nil {
			return 0, fmt.Errorf("startd: importing claim session for ALIVE: %w", err)
		}
	}

	sec := &security.SecurityConfig{
		Command:      cmdAlive,
		PeerName:     scheddAddr,
		SessionCache: cache,
		SessionID:    sessionID,
	}
	hc, err := client.ConnectAndAuthenticate(ctx, scheddAddr, sec)
	if err != nil {
		return 0, fmt.Errorf("startd: connect/resume session for ALIVE: %w", err)
	}
	defer func() { _ = hc.Close() }()

	st := hc.GetStream()
	if err := requireEncrypted(st); err != nil {
		return 0, err
	}

	// put_secret(claimID) + end_of_message. On the encrypted claim session a
	// secret is byte-identical to a string put (see writer.putSecret), and the
	// schedd's handler reads it back with a plain get_string.
	w := newWriter(st)
	w.putSecret(ctx, claimID)
	if err := w.finish(ctx); err != nil {
		return 0, fmt.Errorf("startd: sending ALIVE: %w", err)
	}

	// The schedd replies with a single int: its alive_interval, or -1.
	r := newReader(st)
	reply, err := r.getInt(ctx)
	if err != nil {
		return 0, fmt.Errorf("startd: reading ALIVE reply: %w", err)
	}
	return reply, nil
}
