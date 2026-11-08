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

package startd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
)

// This file is the administrative half of talking to a startd: changing
// its published machine ad and vacating its claims. Neither is part of
// the claim protocol the rest of the package implements -- there is no
// claim id involved -- but both are startd commands, and the session
// they ride is imported exactly the way a claim session is.

// Command integers for the administrative commands.
//
// CAAuthCmd is the one that goes on the wire for every ClassAd-protocol
// command. The verb -- CA_UPDATE_MACHINE_AD and friends -- travels as a
// *string* inside the request ad, under the Command attribute, and the
// startd maps it back to its own switch. Sending 1009 (the value of
// CA_UPDATE_MACHINE_AD) as the wire command instead is rejected as an
// unknown command: nothing is registered at that number.
const (
	// CAAuthCmd is CA_AUTH_CMD: read a ClassAd, do what its Command
	// attribute says, answer with a ClassAd. Registered by the startd at
	// WRITE.
	CAAuthCmd = 1000
	// CACmd is CA_CMD, the same thing without forcing authentication.
	// Unused here; an administrative command always authenticates.
	CACmd = 1200

	cmdVacateClaim     = schedVers + 65 // 465 VACATE_CLAIM (graceful)
	cmdVacateClaimFast = schedVers + 75 // 475 VACATE_CLAIM_FAST
)

// Verbs carried in the request ad's Command attribute.
const (
	// VerbUpdateMachineAd merges the request ad's attributes into every
	// slot ad the startd publishes, for the life of the startd.
	VerbUpdateMachineAd = "CA_UPDATE_MACHINE_AD"
)

// AdminCapabilityAttr is the attribute a DaemonCore daemon publishes to
// the collector carrying a session that administers it.
//
// It is minted by the daemon itself at ADMINISTRATOR level, lives for
// half an hour, and is re-minted on every collector update. The
// attribute name's _condor_Priv prefix is what makes the collector move
// it into the private ad, so a query only sees it with
// QueryOptions.PrivateAttributes and ADMINISTRATOR authorization to the
// collector. It is a bearer credential: anyone holding it can
// administer that daemon.
//
// Published only when the daemon has SEC_ENABLE_REMOTE_ADMINISTRATION
// (default true since the attribute was introduced).
const AdminCapabilityAttr = "_condor_PrivRemoteAdminCapability"

// collectorSideFQU is the identity a daemon records for whoever presents
// its admin capability. The daemon punches an ADMINISTRATOR hole for
// exactly this name when remote administration is enabled.
const collectorSideFQU = "collector-side@matchsession"

// ErrNoAdminCapability is returned when an ad carries no administrative
// capability. The usual causes are the daemon having remote
// administration turned off, and the query not having asked for private
// attributes (or not having been authorized to receive them), which look
// identical from here.
var ErrNoAdminCapability = errors.New("startd: ad carries no administrative capability")

// Admin administers one execute point.
//
// Construct it from the daemon's own ad with NewAdminFromAd, which
// prefers the capability the daemon published and falls back to this
// process's own credentials when there is none. The two differ in who
// has to be configured: with a capability, authorization lives in the
// collector and the execute point needs nothing; without one, this
// process's identity has to appear in the execute point's own
// ALLOW_WRITE and ALLOW_ADMINISTRATOR.
//
// An Admin is bound to one address and is safe for sequential use; each
// method opens its own connection.
type Admin struct {
	addr string
	// sessionID is the imported capability session, empty when
	// administering with this process's own credentials.
	sessionID string
	cache     *security.SessionCache
	// secConfig builds the security config for a command when there is
	// no capability session. Nil means the cedar default.
	secConfig func(ctx context.Context, command int, peer string) (*security.SecurityConfig, error)
}

// AdminOptions tunes how an Admin is built.
type AdminOptions struct {
	// Cache is the session cache the capability is imported into. Nil
	// allocates a private one, which is right for a short-lived Admin;
	// share a cache across the Admins of one pool so a controller that
	// touches a machine repeatedly reuses the session.
	Cache *security.SessionCache
	// SecurityConfig builds the config for a command when no capability
	// is available. Nil leaves it to cedar's defaults.
	SecurityConfig func(ctx context.Context, command int, peer string) (*security.SecurityConfig, error)
}

// NewAdmin builds an Admin that authenticates with this process's own
// credentials. The execute point must authorize this identity directly.
func NewAdmin(addr string, opts *AdminOptions) *Admin {
	a := &Admin{addr: addr}
	if opts != nil {
		a.secConfig = opts.SecurityConfig
	}
	return a
}

// NewAdminFromAd builds an Admin from a daemon ad -- a slot ad, or the
// startd's own daemon ad.
//
// The address comes from MyAddress. The capability, when the ad carries
// one, is imported as a security session and used for every command;
// when it does not, the Admin falls back to this process's credentials
// and requireCapability decides whether that is acceptable.
//
// A capability that is present but unusable is an error rather than a
// silent fallback. Quietly connecting as this process instead would
// turn a pool whose authorization lives in the collector into one that
// refuses every command, with nothing to say why.
func NewAdminFromAd(ad *classad.ClassAd, requireCapability bool, opts *AdminOptions) (*Admin, error) {
	if ad == nil {
		return nil, errors.New("startd: nil ad")
	}
	addr, _ := ad.EvaluateAttrString("MyAddress")
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("startd: ad carries no MyAddress")
	}

	capability, _ := ad.EvaluateAttrString(AdminCapabilityAttr)
	if strings.TrimSpace(capability) == "" {
		if requireCapability {
			return nil, ErrNoAdminCapability
		}
		return NewAdmin(addr, opts), nil
	}

	a := NewAdmin(addr, opts)
	if opts != nil && opts.Cache != nil {
		a.cache = opts.Cache
	} else {
		a.cache = security.NewSessionCache()
	}

	sesid, err := security.ImportClaimSession(a.cache, capability, security.ClaimSessionOptions{
		PeerAddr: addr,
		PeerFQU:  collectorSideFQU,
		ExtraValidCommands: []int{
			CAAuthCmd, CACmd, cmdVacateClaim, cmdVacateClaimFast,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("startd: importing the administrative capability: %w", err)
	}
	a.sessionID = sesid
	return a, nil
}

// Addr is the command address this Admin talks to.
func (a *Admin) Addr() string { return a.addr }

// HasCapability reports whether commands ride a capability session
// rather than this process's own credentials.
func (a *Admin) HasCapability() bool { return a.sessionID != "" }

// connect dials the execute point for one command.
func (a *Admin) connect(ctx context.Context, command int) (*client.HTCondorClient, error) {
	var sec *security.SecurityConfig
	if a.sessionID != "" {
		sec = &security.SecurityConfig{
			Command:      command,
			PeerName:     a.addr,
			SessionCache: a.cache,
			SessionID:    a.sessionID,
		}
	} else if a.secConfig != nil {
		var err error
		sec, err = a.secConfig(ctx, command, a.addr)
		if err != nil {
			return nil, fmt.Errorf("startd: building the security config: %w", err)
		}
	}
	hc, err := client.ConnectAndAuthenticate(ctx, a.addr, sec)
	if err != nil {
		return nil, fmt.Errorf("startd: connecting to %s for command %d: %w", a.addr, command, err)
	}
	return hc, nil
}

// UpdateMachineAd merges attrs into the machine ad every slot publishes.
//
// What the startd does with the ad is unconditional and unbounded: every
// attribute except MyType, TargetType and the offline-universe family is
// copied into an "extras" ad that is merged into each slot's ClassAd on
// every refresh. So the attributes become operands of that slot's own
// expressions -- START included -- and not merely decoration on what the
// collector shows.
//
// Three properties have no API surface and constrain every caller:
//
//   - The merge is per machine, not per slot. There is one extras ad.
//   - There is no delete and no expiry. An attribute written here lives
//     until the startd restarts, so a caller that may stop running
//     should write values that stop meaning anything on their own --
//     an absolute deadline rather than a flag.
//   - The Command attribute is merged too, because the startd's filter
//     does not exclude it. Every machine written to this way ends up
//     publishing Command = "CA_UPDATE_MACHINE_AD".
//
// attrs is copied, not modified.
func (a *Admin) UpdateMachineAd(ctx context.Context, attrs *classad.ClassAd) error {
	if attrs == nil {
		return errors.New("startd: nil update ad")
	}
	reply, err := a.sendCA(ctx, VerbUpdateMachineAd, copyAd(attrs))
	if err != nil {
		return err
	}
	return caResult(reply, VerbUpdateMachineAd)
}

// copyAd is a shallow copy: the expressions are shared, which is the
// library's own idiom for moving an attribute between ads, but the
// attribute set is the new ad's own. The caller's ad must not grow the
// three protocol attributes sendCA adds.
func copyAd(src *classad.ClassAd) *classad.ClassAd {
	out := classad.New()
	if src == nil {
		return out
	}
	for _, name := range src.GetAttributes() {
		if expr, ok := src.Lookup(name); ok && expr != nil {
			out.InsertExpr(name, expr)
		}
	}
	return out
}

// sendCA performs one ClassAd-protocol round trip: connect, send the
// request ad under CA_AUTH_CMD, read the reply ad.
func (a *Admin) sendCA(ctx context.Context, verb string, req *classad.ClassAd) (*classad.ClassAd, error) {
	// MyType/TargetType are what the startd's ad reader expects, and are
	// the two attributes it declines to merge.
	_ = req.Set("MyType", "Command")
	_ = req.Set("TargetType", "Reply")
	_ = req.Set("Command", verb)

	hc, err := a.connect(ctx, CAAuthCmd)
	if err != nil {
		return nil, err
	}
	defer func() { _ = hc.Close() }()
	st := hc.GetStream()

	w := newWriter(st)
	w.putClassAd(ctx, req)
	if err := w.finish(ctx); err != nil {
		return nil, fmt.Errorf("startd: sending %s: %w", verb, err)
	}

	r := newReader(st)
	reply, err := r.getClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("startd: reading the %s reply: %w", verb, err)
	}
	return reply, nil
}

// CAError is a ClassAd-protocol command the daemon refused.
type CAError struct {
	// Verb is the command that was refused.
	Verb string
	// Result is the daemon's Result attribute: "Failure",
	// "NotAuthorized", "NotAuthenticated", "InvalidRequest" and so on.
	Result string
	// Detail is the daemon's ErrorString, when it sent one.
	Detail string
}

func (e *CAError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("startd: %s refused (%s): %s", e.Verb, e.Result, e.Detail)
	}
	return fmt.Sprintf("startd: %s refused (%s)", e.Verb, e.Result)
}

// Denied reports whether the refusal was about authorization rather
// than the request. This is the one a caller has to surface: an access
// point that may no longer administer its execute points goes on
// planning correctly and changing nothing.
func (e *CAError) Denied() bool {
	switch e.Result {
	case "NotAuthorized", "NotAuthenticated":
		return true
	}
	return false
}

// caResult turns a reply ad into an error, or nil on success.
func caResult(reply *classad.ClassAd, verb string) error {
	if reply == nil {
		return fmt.Errorf("startd: %s got no reply ad", verb)
	}
	result, ok := reply.EvaluateAttrString("Result")
	if !ok || result == "" {
		// The daemon answers every ClassAd command with a Result. A
		// reply without one is not something to read optimistically:
		// it means we are not talking to what we think we are.
		return fmt.Errorf("startd: %s reply carries no Result attribute", verb)
	}
	if result == "Success" {
		return nil
	}
	detail, _ := reply.EvaluateAttrString("ErrorString")
	return &CAError{Verb: verb, Result: result, Detail: detail}
}

// VacateClaim vacates one slot by name ("slot1_3@host.example.com" --
// the slot ad's Name, not its Machine).
//
// Graceful vacate retires the claim, which lets the job take its
// soft-kill signal and, if it is checkpointing, write one. Fast kills
// it. Either requires ADMINISTRATOR, which is the level the published
// capability carries.
//
// The startd sends no reply, so this returns once the command is
// written. A slot that is not claimed, or whose name does not exist, is
// logged and ignored by the startd and is indistinguishable from
// success here.
func (a *Admin) VacateClaim(ctx context.Context, slotName string, fast bool) error {
	if strings.TrimSpace(slotName) == "" {
		return errors.New("startd: empty slot name")
	}
	command := cmdVacateClaim
	if fast {
		command = cmdVacateClaimFast
	}

	hc, err := a.connect(ctx, command)
	if err != nil {
		return err
	}
	defer func() { _ = hc.Close() }()

	w := newWriter(hc.GetStream())
	w.putString(ctx, slotName)
	if err := w.finish(ctx); err != nil {
		return fmt.Errorf("startd: sending VACATE_CLAIM for %s: %w", slotName, err)
	}
	return nil
}
