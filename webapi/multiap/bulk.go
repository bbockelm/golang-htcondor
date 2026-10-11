package multiap

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/ownerscope"
)

// Bulk constraint actions (hold, release, remove, edit by constraint)
// fan out to every member and report per AP.
//
// The hub may narrow the fan-out, but it only ever skips an AP that is
// PROVABLY empty: its source is fresh within the bulk tolerance and the
// hub holds no row matching the caller-scoped constraint there. Anything
// short of proof -- a stale or absent source, a hub that does not answer,
// a hub that has a match -- means the AP is contacted. "Remove all my
// idle jobs" silently missing the ones submitted thirty seconds ago on an
// AP whose hub copy is behind is the bug this rule exists to prevent.

// Per-AP outcomes of a bulk action.
const (
	// BulkActed: the AP was contacted and acted on at least one job.
	BulkActed = "acted"
	// BulkNoMatch: the AP was contacted and nothing there matched.
	BulkNoMatch = "no_match"
	// BulkSkipped: not contacted, because the hub proves nothing there
	// matches.
	BulkSkipped = "skipped"
	// BulkFailed: the AP was contacted and the action failed.
	BulkFailed = "failed"
	// BulkUnreachable: not contacted, because the AP is not advertised in
	// the collector now.
	BulkUnreachable = "unreachable"
	// BulkUntrusted: not contacted, because the AP failed its trust probe.
	BulkUntrusted = "untrusted"
)

// DefaultBulkConcurrency bounds how many APs a bulk action contacts at
// once.
const DefaultBulkConcurrency = 8

// DefaultBulkAPTimeout bounds one AP's leg of a bulk action, so one AP
// that hangs is reported rather than holding the response.
const DefaultBulkAPTimeout = 60 * time.Second

// DefaultBulkTimeout bounds a whole bulk action. The fan-out does not
// follow the caller's cancellation -- a client that disconnects must not
// leave an action applied to some APs and never reported -- so this is
// what ends it.
const DefaultBulkTimeout = 5 * time.Minute

// hubCheckTimeout bounds the hub query behind a skip. A hub that does not
// answer in time proves nothing, and the AP is contacted.
const hubCheckTimeout = 5 * time.Second

// sourceRowRefresh is how stale the hub lets a federation_sources row's
// StalenessSeconds get before rewriting it (htcondordb federate rewrites
// a row's volatile fields at most once a minute unless something else
// changed). A measured lag can be under-reported by up to this much.
const sourceRowRefresh = time.Minute

// BulkCounts is one AP's job-action counts (or the sum over APs).
type BulkCounts struct {
	Total            int `json:"total"`
	Success          int `json:"success"`
	NotFound         int `json:"not_found"`
	PermissionDenied int `json:"permission_denied"`
	BadStatus        int `json:"bad_status"`
	AlreadyDone      int `json:"already_done"`
	Error            int `json:"error"`
}

// CountsOf converts a schedd's answer.
func CountsOf(r *htcondor.JobActionResults) BulkCounts {
	if r == nil {
		return BulkCounts{}
	}
	return BulkCounts{Total: r.TotalJobs, Success: r.Success, NotFound: r.NotFound,
		PermissionDenied: r.PermissionDenied, BadStatus: r.BadStatus, AlreadyDone: r.AlreadyDone,
		Error: r.Error + r.LimitExceeded}
}

func (c *BulkCounts) add(o BulkCounts) {
	c.Total += o.Total
	c.Success += o.Success
	c.NotFound += o.NotFound
	c.PermissionDenied += o.PermissionDenied
	c.BadStatus += o.BadStatus
	c.AlreadyDone += o.AlreadyDone
	c.Error += o.Error
}

// BulkOutcome is what one AP's leg returns.
type BulkOutcome struct {
	// Counts is a job action's per-outcome counts.
	Counts BulkCounts
	// Edited is how many jobs an edit changed.
	Edited int
}

func (o BulkOutcome) matched() bool { return o.Counts.Total > 0 || o.Edited > 0 }

// BulkAPResult is one AP's line in a bulk action's report.
type BulkAPResult struct {
	Schedd string `json:"schedd"`
	Status string `json:"status"`
	// Reason says why an AP was skipped or not contacted.
	Reason string `json:"reason,omitempty"`
	// Error is a contacted AP's failure.
	Error  string      `json:"error,omitempty"`
	Counts *BulkCounts `json:"results,omitempty"`
	Edited *int        `json:"jobs_edited,omitempty"`
}

// BulkReport is a whole bulk action's outcome.
type BulkReport struct {
	APs []BulkAPResult `json:"aps"`
	// Totals sums Counts over the APs that acted.
	Totals BulkCounts `json:"results"`
	// Edited sums Edited.
	Edited int `json:"jobs_edited"`
	// Complete is true when every AP was either acted on or proven to
	// have nothing to act on: no AP failed, was unreachable or was
	// untrusted.
	Complete bool `json:"complete"`
}

// Matched reports whether any AP acted on, or edited, a job.
func (r BulkReport) Matched() bool { return r.Totals.Total > 0 || r.Edited > 0 }

// Contacted is how many APs were reached and answered.
func (r BulkReport) Contacted() (ok, failed int) {
	for _, a := range r.APs {
		switch a.Status {
		case BulkActed, BulkNoMatch:
			ok++
		case BulkFailed:
			failed++
		}
	}
	return ok, failed
}

// BulkRequest describes a bulk action's fan-out.
type BulkRequest struct {
	// User is the caller's User value (UserFor), Owner their bare Owner:
	// the hub check is confined to rows matching either, so a job whose
	// User and Owner disagree is never counted out.
	User, Owner string
	// Constraint is the caller's constraint, unscoped. It is parsed and
	// re-serialized before any use; one that does not parse is an error.
	Constraint string
	// AllUsers reports whether the caller acts on every user's jobs on
	// an AP (a queue superuser there, by this server's policy and the
	// AP's). The hub check for that AP is then not confined to the
	// caller -- it must look where the action will.
	AllUsers func(ap string) bool
	// FreshWithin is how fresh the hub's copy of an AP must be for its
	// "no match" to count. Zero or negative -- the default -- disables
	// skipping: every usable AP is contacted.
	FreshWithin time.Duration
	// Members, when set, is the AP set to fan out over, instead of the
	// registry's current one: a caller that vetted the set (for a
	// permission that must hold on every AP acted on) passes exactly the
	// set it vetted.
	Members []apregistry.Member
	// Timeout bounds the whole action; zero selects DefaultBulkTimeout.
	// Concurrency and APTimeout; zero selects the defaults.
	Timeout     time.Duration
	Concurrency int
	APTimeout   time.Duration
}

// BulkAction performs one AP's leg. It is handed the AP and a context
// bounded by the request's APTimeout.
type BulkAction func(ctx context.Context, m apregistry.Member) (BulkOutcome, error)

// FanOut runs act on every member that needs it and reports per AP.
func (s *Service) FanOut(ctx context.Context, req BulkRequest, act BulkAction) (*BulkReport, error) {
	balanced, err := ownerscope.Balanced(req.Constraint)
	if err != nil {
		return nil, errorf(http.StatusBadRequest, "constraint is not a valid ClassAd expression: %v", err)
	}
	conc := req.Concurrency
	if conc <= 0 {
		conc = DefaultBulkConcurrency
	}
	apTimeout := req.APTimeout
	if apTimeout <= 0 {
		apTimeout = DefaultBulkAPTimeout
	}
	total := req.Timeout
	if total <= 0 {
		total = DefaultBulkTimeout
	}
	// Detached from the caller's cancellation, bounded on its own: an
	// action half-applied because the client went away would otherwise
	// never be reported to anyone.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), total)
	defer cancel()

	members := req.Members
	if members == nil {
		members = s.Registry.Members()
	}
	if len(members) == 0 {
		// Before the first collector poll, or with nothing matching the
		// constraint: "nothing matched anywhere" would be a lie.
		return nil, errorf(http.StatusServiceUnavailable,
			"no access point is known yet; the collector has not been read or nothing matches HTTP_API_SCHEDD_CONSTRAINT")
	}
	results := make([]BulkAPResult, len(members))
	var wg sync.WaitGroup
	slots := make(chan struct{}, conc)
	for i, m := range members {
		results[i] = BulkAPResult{Schedd: m.Name}
		switch {
		case !m.Present:
			results[i].Status, results[i].Reason = BulkUnreachable, "not advertised in the collector right now"
			continue
		case m.Untrusted():
			results[i].Status, results[i].Reason = BulkUntrusted, untrustedReason(m)
			continue
		case m.Schedd == nil:
			results[i].Status, results[i].Reason = BulkUnreachable, "no known address"
			continue
		}
		wg.Add(1)
		go func(i int, m apregistry.Member) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				results[i].Status, results[i].Error = BulkFailed, ctx.Err().Error()
				return
			}
			defer func() { <-slots }()
			if why, empty := s.provablyEmpty(ctx, req, balanced, m.Name); empty {
				results[i].Status, results[i].Reason = BulkSkipped, why
				return
			}
			legCtx, cancel := context.WithTimeout(ctx, apTimeout)
			defer cancel()
			out, err := act(legCtx, m)
			if err != nil {
				// A leg that failed -- or timed out -- may still have
				// been applied by the schedd.
				s.NoteWrite(m.Name)
				results[i].Status, results[i].Error = BulkFailed, err.Error()
				return
			}
			counts, edited := out.Counts, out.Edited
			results[i].Counts, results[i].Edited = &counts, &edited
			results[i].Status = BulkNoMatch
			if out.matched() {
				results[i].Status = BulkActed
				s.NoteWrite(m.Name)
			}
		}(i, m)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Schedd < results[j].Schedd })
	rep := &BulkReport{APs: results, Complete: true}
	for _, r := range results {
		switch r.Status {
		case BulkActed, BulkNoMatch:
			rep.Totals.add(*r.Counts)
			rep.Edited += *r.Edited
		case BulkSkipped:
		default:
			rep.Complete = false
		}
	}
	return rep, nil
}

// provablyEmpty reports whether the hub proves that nothing the action
// would touch is on ap: the source is fresh within req.FreshWithin, and
// the hub holds no matching row. Any doubt is "not proven".
func (s *Service) provablyEmpty(ctx context.Context, req BulkRequest, balanced, ap string) (string, bool) {
	if req.FreshWithin <= 0 || s.Hub == nil {
		return "", false
	}
	age, ok := s.Hub.Freshness(ap)
	if !ok || age > req.FreshWithin {
		return "", false
	}
	// This server changed something on ap recently: "nothing matches
	// there" may describe the queue from before that change (a bulk
	// release right after a bulk hold is the case that shows it). The
	// window does not trust the measured lag, which the hub may report up
	// to sourceRowRefresh late.
	if s.wroteSince(ap, req.FreshWithin+sourceRowRefresh+writeMargin) {
		return "", false
	}
	// Only a definite "false" rules a row out: a row the hub cannot
	// evaluate -- one the spoke never chained to its cluster (no Owner,
	// User or JobStatus), or a function this evaluator lacks -- may well
	// match on the schedd, which evaluates the whole ad.
	scope := fmt.Sprintf("(User == %s || Owner == %s)", ownerscope.StringLit(req.User), ownerscope.StringLit(req.Owner))
	if req.AllUsers != nil && req.AllUsers(ap) {
		scope = "true"
	} else if req.User == "" || req.Owner == "" {
		return "", false
	}
	constraint := fmt.Sprintf("((%s) isnt false) && ((%s) isnt false) && (%s)", scope, balanced, scheddIn([]string{ap}))
	check := hubCheckTimeout
	if req.APTimeout > 0 && req.APTimeout < check {
		check = req.APTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, check)
	defer cancel()
	dbc, closer, err := s.Hub.Client(ctx)
	if err != nil {
		return "", false
	}
	defer closer()
	found, err := findOne(ctx, dbc, TableJobs, constraint, keyAttrs, ap)
	if err != nil || found != nil {
		return "", false
	}
	return fmt.Sprintf("the federation hub's copy of this access point is %ds behind (within %ds) and holds no matching job",
		int64(age/time.Second), int64(req.FreshWithin/time.Second)), true
}

// writeMargin widens the window in which a write by this server
// disqualifies the hub's word, for the time between the schedd applying
// it and this server noting it.
const writeMargin = 2 * time.Second

// NoteWrite records that this server just changed something on ap (an
// action, an edit, a spool). Until the hub's copy of ap is known to be
// newer than that, a bulk action does not skip ap on the hub's word.
// Callers note a write when it starts and again when it finishes.
//
// The record is this process's own: it does not survive a restart, and
// replicas of the API server do not share it. A replica therefore trusts
// the hub about another replica's recent writes -- one reason skipping
// is off unless HTTP_API_BULK_FRESH_SECONDS asks for it.
func (s *Service) NoteWrite(ap string) {
	s.writesMu.Lock()
	defer s.writesMu.Unlock()
	if s.writes == nil {
		s.writes = map[string]time.Time{}
	}
	s.writes[strings.ToLower(ap)] = s.clock()
}

// wroteSince reports whether this server wrote to ap within the last d.
func (s *Service) wroteSince(ap string, d time.Duration) bool {
	s.writesMu.Lock()
	defer s.writesMu.Unlock()
	t, ok := s.writes[strings.ToLower(ap)]
	return ok && s.clock().Sub(t) < d
}

func (s *Service) clock() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Freshness is how far behind its AP the hub's copy of schedd is, bounded
// from above: the hub's own staleness measure plus the age of the
// snapshot this server holds of it. ok is false unless the hub reports
// the source fresh with a measured staleness -- an unknown lag is never
// fresh enough.
//
// The jobs stream must also be connected with no error: freshness is
// measured on the syncstatus stream, which says nothing about whether
// the jobs stream is flowing.
func (h *Hub) Freshness(schedd string) (time.Duration, bool) {
	src, ok := h.Source(schedd)
	if !ok || src.State != StateFresh || !src.StalenessKnown || src.Staleness < 0 {
		return 0, false
	}
	if !src.JobsConnected || src.JobsLastError != "" {
		return 0, false
	}
	h.mu.RLock()
	snapshotAge := h.now().Sub(h.sourcesAt)
	h.mu.RUnlock()
	if snapshotAge < 0 {
		snapshotAge = 0
	}
	return time.Duration(src.Staleness)*time.Second + snapshotAge, true
}

// BulkSummary is a one-line description of a report, for logs and tool
// text.
func (r BulkReport) BulkSummary() string {
	var parts []string
	for _, a := range r.APs {
		p := a.Schedd + ": " + a.Status
		switch {
		case a.Counts != nil && a.Status == BulkActed && a.Counts.Total > 0:
			p += fmt.Sprintf(" (%d of %d)", a.Counts.Success, a.Counts.Total)
		case a.Edited != nil && a.Status == BulkActed && *a.Edited > 0:
			p += fmt.Sprintf(" (%d edited)", *a.Edited)
		case a.Error != "":
			p += " (" + a.Error + ")"
		case a.Reason != "" && a.Status != BulkSkipped:
			p += " (" + a.Reason + ")"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}
