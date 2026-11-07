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
	"slices"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// What an API key may do beyond its creator's own jobs, and how long
// that answer is trusted.
//
// An API key acts as the administrator who minted it. Its ordinary
// scopes say which endpoints it may reach; an ENTITLEMENT scope says
// whose records it may see once there. The two are different kinds of
// claim and they go stale differently, which is what this file is
// about.
//
// An endpoint scope is a fact about the key and never changes: a key
// minted for /metrics is a key for /metrics until it is revoked. An
// entitlement is a fact about a PERSON -- that they are entitled to
// read the pool -- and people lose entitlements. A key that froze one
// at mint and never looked again is the "refresh replayed grants
// forever" bug in a new place.
//
// So the entitlement is granted once, where it can be proven, and then
// held under one of two models:
//
//   - A SERVICE key belongs to an automation. Its entitlement is held
//     for the life of the key, bounded by a mandatory expiry. Nothing
//     re-proves it in between because nothing can: there is no
//     interactive login in an automation's future. Re-minting is the
//     re-attestation, and the expiry is what forces one.
//
//   - An ORDINARY key belongs to the person who minted it and tracks
//     them. Its entitlement is re-verified on use against whatever live
//     source the deployment has, and when no source can answer it is
//     honored only while the last successful verification is recent.
//
// The second model is why entitlementTTL exists. Silence from a
// verification source is not a denial -- an unreachable account
// database must not log everybody out -- but it cannot be consent
// forever either, or a deployment with no live source has simply
// reinvented the frozen grant. Silence expires.

// scopePoolRead is the entitlement to read every user's records,
// granted to an API key at mint.
//
// PROVISIONAL NAME. The entitlement vocabulary is being reworked (see
// design_notes/ENTITLEMENT_VOCABULARY.md); this is the name that
// document proposes. It is referenced through this constant everywhere
// so settling on a different one is a single edit, and it is safe to
// rename until the first release that ships it because no grant
// carrying it exists yet.
const scopePoolRead = "pool:read"

// scopePoolWrite is the entitlement to act on every user's records:
// remove, hold, release, edit. The mutate tier to scopePoolRead's read
// tier, and not a superset of it -- a key expected to both see and act
// across users needs both, the same way condor:/READ and condor:/WRITE
// are selected separately.
//
// PROVISIONAL NAME, on the same terms as scopePoolRead.
const scopePoolWrite = "pool:write"

// entitlementScopes are the scopes this file governs: the ones that
// are claims about a person rather than about a key, and so are
// re-verified on use for an ordinary key.
//
// A var rather than a const so the set is in one place when the
// vocabulary rework adds pool:write to it.
var entitlementScopes = []string{scopePoolRead, scopePoolWrite}

// defaultEntitlementTTL bounds how long an ordinary key's entitlement
// is honored with no successful live verification.
//
// One hour is short on purpose. It is the window in which a person who
// has just lost their group membership can still read the pool through
// a key they left behind, in a deployment that gave this server no way
// to notice. A deployment that wants an unattended credential to keep
// working past it is describing a service key, and should mint one --
// that is the choice this default is here to put in front of them,
// rather than quietly answering it for them.
const defaultEntitlementTTL = time.Hour

// defaultServiceKeyMaxLifetime caps how far out a service key's expiry
// may be set.
//
// A year, because the point of the cap is not that a year is
// dangerous -- it is that an expiry exists at all, so somebody is made
// to look at the key again on a schedule rather than never. Sites that
// rotate faster set the knob lower; nothing here encourages a year.
const defaultServiceKeyMaxLifetime = 365 * 24 * time.Hour

// isEntitlementScope reports whether scope is re-verified on use.
func isEntitlementScope(scope string) bool {
	return slices.Contains(entitlementScopes, scope)
}

// heldEntitlements returns the entitlement scopes present in scopes.
func heldEntitlements(scopes []string) []string {
	var out []string
	for _, s := range scopes {
		if isEntitlementScope(s) {
			out = append(out, s)
		}
	}
	return out
}

// entitlementVerdict is a live source's answer about one identity.
//
// Three-valued on purpose. "Not a member" and "could not look it up"
// are both false to a boolean group check, and collapsing them is how
// an outage becomes a mass revocation -- or, in the direction this file
// cares about, how a deployment with no group source at all reads as a
// deployment where nobody is entitled.
type entitlementVerdict int

const (
	// entitlementUnanswered means no source could speak to this
	// identity. The staleness window decides.
	entitlementUnanswered entitlementVerdict = iota
	// entitlementConfirmed means a live source vouched for the
	// identity just now.
	entitlementConfirmed
	// entitlementDenied means a live source affirmatively said this
	// identity is no longer entitled.
	entitlementDenied
)

// entitlementTTL is the configured staleness bound, or the default.
func (s *Handler) entitlementTTL() time.Duration {
	if s.apiKeyEntitlementTTL > 0 {
		return s.apiKeyEntitlementTTL
	}
	return defaultEntitlementTTL
}

// resolvedEntitlementsKey carries one request's already-computed answer.
type resolvedEntitlementsKey struct{}

// resolvedEntitlements is that answer, tagged with the key it was
// computed for so a context cannot hand one key's verdict to another.
type resolvedEntitlements struct {
	keyID  string
	scopes []string
}

// resolveAPIKeyEntitlements returns the scopes an API key actually
// carries on this request: its stored scopes, minus any entitlement it
// is no longer entitled to. The returned context carries the answer so
// the work happens once per request.
//
// Once per request matters because authenticateAPIKey runs twice for a
// request that passes through requireCondorScope -- once in the
// middleware to gate on scopes, once in createAuthenticatedContext to
// build the context the handler uses. Verifying twice would double the
// group lookups and the oracle calls, and would write the checked-at
// column twice for one request.
//
// It does no work at all for a key that holds no entitlement, which is
// every key minted before this existed and most keys after.
func (s *Handler) resolveAPIKeyEntitlements(ctx context.Context, row *apiKeyRow) (context.Context, []string) {
	held := heldEntitlements(row.Scopes)
	if len(held) == 0 {
		return ctx, row.Scopes
	}
	if prior, ok := ctx.Value(resolvedEntitlementsKey{}).(resolvedEntitlements); ok && prior.keyID == row.KeyID {
		return ctx, prior.scopes
	}

	scopes := s.entitlementsFor(ctx, row, held)
	return context.WithValue(ctx, resolvedEntitlementsKey{},
		resolvedEntitlements{keyID: row.KeyID, scopes: scopes}), scopes
}

// entitlementsFor is the uncached decision.
func (s *Handler) entitlementsFor(ctx context.Context, row *apiKeyRow, held []string) []string {
	// A service key's entitlement was granted at mint and is held for
	// the life of the key. The expiry is the bound, and LookupActive
	// has already enforced it: a key that reaches here has not expired.
	if row.Service {
		return row.Scopes
	}

	verdict, reason := s.verifyEntitlement(ctx, row)
	switch verdict {
	case entitlementConfirmed:
		s.apiKeyStore.MarkEntitlementsChecked(ctx, row.KeyID)
		return row.Scopes

	case entitlementDenied:
		// Guarded because the minimal Handler some unit tests build
		// carries no logger, and this sits on the authentication path
		// where a nil dereference would be a panic per request rather
		// than a missing log line.
		if s.logger != nil {
			s.logger.Info(logging.DestinationSecurity,
				"API key entitlement withdrawn: its creator is no longer entitled",
				"key_id", row.KeyID, "creator", row.Creator,
				"withheld", held, "reason", reason)
		}
		return withoutEntitlements(row.Scopes)

	default: // entitlementUnanswered
		if s.entitlementIsFresh(row) {
			return row.Scopes
		}
		if s.logger != nil {
			s.logger.Info(logging.DestinationSecurity,
				"API key entitlement withheld: nothing could confirm it within the staleness window",
				"key_id", row.KeyID, "creator", row.Creator,
				"withheld", held, "ttl", s.entitlementTTL(),
				"last_checked", row.EntitlementsCheckedAt,
				"hint", "a credential meant to run unattended should be minted as a service key")
		}
		return withoutEntitlements(row.Scopes)
	}
}

// entitlementIsFresh reports whether the last successful verification
// is recent enough to stand in for one now.
//
// A row with no timestamp at all is NOT fresh. That is a key minted
// before this column existed, which is to say one whose entitlement was
// never recorded as proven -- and such a key has no entitlement scope
// on it either, so this is belt and braces rather than a live path.
func (s *Handler) entitlementIsFresh(row *apiKeyRow) bool {
	if row.EntitlementsCheckedAt == nil {
		return false
	}
	return time.Since(*row.EntitlementsCheckedAt) <= s.entitlementTTL()
}

// withoutEntitlements copies scopes with the entitlement scopes
// removed, leaving the endpoint scopes intact.
//
// Withholding rather than failing the request: a key that has lost
// pool:read is still a perfectly good key for its creator's own jobs,
// and the caller should see their own records rather than a 403 they
// cannot act on. The log line above is where the difference is
// explained.
func withoutEntitlements(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		if !isEntitlementScope(sc) {
			out = append(out, sc)
		}
	}
	return out
}

// verifyEntitlement asks whatever live source this deployment has
// whether this key's creator is still entitled to read the pool.
//
// Two sources, and they cost very different amounts, which is why the
// order here is not simply "most authoritative first":
//
//   - Live group membership, where groups come from the system. A
//     cached NSS read, cheap enough to do on every request, and the
//     authority on this entitlement: group membership is what granted
//     it. Where it answers, it is the answer, and a creator who leaves
//     the group loses the entitlement on their very next request.
//
//   - The revocation oracles, which speak to whether the person still
//     exists at all -- a disabled schedd user record, a deleted
//     account. A stronger statement, but each one is an RPC to the
//     schedd. Running those per request would put a query on the
//     authentication path of every scripted caller, so they are asked
//     only when nothing cheaper could answer AND the stored answer has
//     gone stale: once per staleness window per key, not once per
//     request.
//
// Where groups come from the token and no oracle has an opinion, the
// answer is Unanswered and the staleness window decides. The token was
// presented at a login that is long over and this server holds nothing
// it can re-read. Asking the identity provider directly is possible
// where an upstream refresh token was stored (upstreamUserInfoOracle
// does exactly that for OAuth2 refreshes), but that oracle answers in
// the MCP scope vocabulary rather than in entitlements, so wiring it in
// belongs with the vocabulary rework rather than ahead of it.
func (s *Handler) verifyEntitlement(ctx context.Context, row *apiKeyRow) (entitlementVerdict, string) {
	actor := row.Creator
	if actor == "" {
		return entitlementUnanswered, "no authenticated identity"
	}

	if granted, answered := s.liveGroupEntitlement(ctx, actor); answered {
		if !granted {
			return entitlementDenied, "no longer in the entitled group"
		}
		return entitlementConfirmed, ""
	}

	// Nothing cheap could answer. Within the window the stored answer
	// stands and this costs nothing; outside it, pay for the oracles
	// once rather than let the entitlement lapse without asking.
	if s.entitlementIsFresh(row) {
		return entitlementUnanswered, "no live group source"
	}
	return s.askOracles(ctx, actor)
}

// askOracles is the expensive half of verifyEntitlement.
//
// Oracles fail open by contract, so only UserStatusRevoked is an
// answer: an unreachable schedd leaves the verdict Unanswered and the
// entitlement lapses on the staleness window instead of being revoked
// by an outage.
func (s *Handler) askOracles(ctx context.Context, actor string) (entitlementVerdict, string) {
	for _, oracle := range s.revocationOracles {
		decision, err := oracle.Check(ctx, actor, entitlementScopes)
		if err != nil {
			continue
		}
		if decision.Status == UserStatusRevoked {
			reason := decision.Reason
			if reason == "" {
				reason = oracle.Name() + " revoked this user"
			}
			return entitlementDenied, reason
		}
		if decision.Status == UserStatusActive && !slices.ContainsFunc(entitlementScopes, func(sc string) bool {
			return slices.Contains(decision.DeniedScopes, sc)
		}) {
			return entitlementConfirmed, ""
		}
	}
	return entitlementUnanswered, "no oracle had an opinion"
}
