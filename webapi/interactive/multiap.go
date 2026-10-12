package interactive

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Sessions on a server that fronts several access points.
//
// A session's access point is part of its record. It is chosen once, by
// APs.Assign, when the session is created; it is stored on the session;
// and every later call that names the session -- exec, stop, the
// heartbeat, lease expiry -- goes to that access point and no other.
// Nothing asks Assign again for a session that exists: a user whose
// assignment moves keeps the session they have where it is, and only a
// new one goes to the new access point.
//
// A session name is unique per owner across the whole server, not per
// access point. The name is the only handle a caller has -- `ssh
// +name@gateway`, interactive_session_exec -- so it has to resolve to
// exactly one job. Create therefore checks every access point that holds
// one of the caller's sessions, and a lookup that finds the name on two
// access points refuses rather than picking one.
//
// Where the sessions are comes from two places. The in-process record is
// authoritative for the sessions this process created or has reached
// since it started. Beyond those, the federated catalog (the hub) says
// which access points hold the caller's live session jobs; each of
// those is then asked directly, so what is acted on is the access
// point's own answer, never the catalog's possibly lagging copy.

// APs lets a Manager front several access points (multi-AP mode). Every
// method is called with the caller's request context, or for background
// work (lease expiry) with one carrying the caller's stored credential.
type APs interface {
	// Assign picks the access point a NEW session for caller goes to
	// (AP assignment, asked once per Create) and returns its name and
	// ctx routed to it, ready for a submission there. explicit is the
	// access point the caller asked for, or ""; the host honors it only
	// as AP assignment allows (the home access point or an alternate).
	Assign(ctx context.Context, caller Caller, explicit string) (ap string, routed context.Context, err error)
	// Route returns ctx routed to ap -- the access point an existing
	// session's record names -- for a call on caller's behalf. It fails
	// when ap cannot be acted on now (absent, untrusted, or refusing
	// the caller); it never substitutes another access point.
	Route(ctx context.Context, caller Caller, ap string) (context.Context, error)
	// Locate returns the caller's live jobs matching constraint on
	// every access point, as the federated catalog holds them, with at
	// least projection. The catalog confines the answer to the caller;
	// the constraint need not.
	Locate(ctx context.Context, caller Caller, constraint string, projection []string) ([]LocatedAd, error)
	// JobID renders a job's complete id, the form every other tool and
	// URL on the server accepts.
	JobID(ap string, cluster, proc int) string
	// Wrote records that this manager changed something on ap (a
	// submit, a removal), before and after it does.
	Wrote(ap string)
}

// LocatedAd is one job ad and the access point it is on.
type LocatedAd struct {
	AP string
	Ad *classad.ClassAd
}

// AmbiguousSessionError reports a session name that answers to jobs on
// more than one access point. It is refused rather than resolved: an
// exec or a stop on the wrong one cannot be taken back.
type AmbiguousSessionError struct {
	Name string
	Jobs []string // complete job ids
}

func (e *AmbiguousSessionError) Error() string {
	return fmt.Sprintf("session name %q answers to more than one job (%s), on different access points; "+
		"refusing to guess which -- remove the one you do not want by its job id (remove_job), then use the name again",
		e.Name, strings.Join(e.Jobs, ", "))
}

func (m *Manager) multi() bool { return m.opts.APs != nil }

// on returns the context and schedd a call on ap's sessions uses: the
// one schedd with a single access point; otherwise ap's, routed through
// APs.Route. ap is a session's stored access point, or the one Create
// was assigned.
func (m *Manager) on(ctx context.Context, caller Caller, ap string) (context.Context, ScheddClient, error) {
	if !m.multi() {
		schedd := m.opts.Schedd()
		if schedd == nil {
			return nil, nil, fmt.Errorf("no schedd configured")
		}
		return ctx, schedd, nil
	}
	if ap == "" {
		// Every session found in multi-AP mode carries its access
		// point; one without is a bug, and guessing would act on
		// another access point's job.
		return nil, nil, errors.New("internal error: the session has no access point recorded")
	}
	routed, err := m.opts.APs.Route(ctx, caller, ap)
	if err != nil {
		return nil, nil, err
	}
	schedd := m.opts.ScheddFor(routed)
	if schedd == nil {
		return nil, nil, fmt.Errorf("access point %s has no schedd to reach", ap)
	}
	return routed, schedd, nil
}

// jobID is how a session's job is named to callers: cluster.proc with
// one schedd, the complete id with several.
func (m *Manager) jobID(ap string, cluster, proc int) string {
	if m.multi() && ap != "" {
		return m.opts.APs.JobID(ap, cluster, proc)
	}
	return jobIDOf(cluster, proc)
}

// wrote tells the host this manager changed something on ap.
func (m *Manager) wrote(ap string) {
	if m.multi() && ap != "" {
		m.opts.APs.Wrote(ap)
	}
}

// sessionConstraint is the catalog's question for the caller's live
// sessions: name's, or all of them.
func sessionConstraint(name string) string {
	if name != "" {
		return fmt.Sprintf("%s && JobBatchName == %q", liveSessionClause, BatchNameForSession(name))
	}
	return fmt.Sprintf("%s && regexp(%q, JobBatchName)", liveSessionClause, "^"+SessionBatchPrefix)
}

// knownAPs is where this process's own records put owner's sessions --
// name's, or all of them.
func (m *Manager) knownAPs(owner, name string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, sess := range m.sessions {
		if sess.owner == owner && sess.ap != "" && (name == "" || sess.name == name) {
			out = append(out, sess.ap)
		}
	}
	return out
}

// located is the catalog's answer for the caller's sessions, grouped by
// access point.
func (m *Manager) located(ctx context.Context, caller Caller, name string) (map[string][]Info, error) {
	ads, err := m.opts.APs.Locate(ctx, caller, sessionConstraint(name), sessionAdAttrs)
	if err != nil {
		return nil, fmt.Errorf("finding your interactive sessions: %w", err)
	}
	out := map[string][]Info{}
	for _, la := range ads {
		info, ok := m.infoFromAd(la.Ad, caller, name, la.AP)
		if !ok {
			continue
		}
		info.Unverified = true
		out[la.AP] = append(out[la.AP], info)
	}
	return out, nil
}

// apSet merges access point names, as schedd names compare: without
// regard to case. The first spelling seen wins.
func apSet(groups ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, ap := range g {
			k := strings.ToLower(ap)
			if ap == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, ap)
		}
	}
	sort.Strings(out)
	return out
}

// DefaultAPTimeout bounds one access point's answer to a session
// listing, so one that hangs is treated as unreachable instead of
// holding up every other access point -- and, inside Create, the
// per-name lock.
const DefaultAPTimeout = 15 * time.Second

// apConcurrency bounds how many access points a listing asks at once.
const apConcurrency = 8

// apAnswer is one access point's answer to a session listing.
type apAnswer struct {
	ap    string
	infos []Info
	err   error
}

// askAPs asks each access point for the caller's live sessions (name's,
// or all of them), in parallel and each within APTimeout. A timeout is
// an error like any other: the caller falls back to what it knows.
func (m *Manager) askAPs(ctx context.Context, caller Caller, aps []string, name string) []apAnswer {
	out := make([]apAnswer, len(aps))
	timeout := m.opts.APTimeout
	if timeout <= 0 {
		timeout = DefaultAPTimeout
	}
	slots := make(chan struct{}, apConcurrency)
	var wg sync.WaitGroup
	for i, ap := range aps {
		wg.Add(1)
		go func(i int, ap string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			apCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			infos, err := m.listAdsOn(apCtx, caller, ap, name)
			if err == nil && apCtx.Err() != nil {
				err = apCtx.Err()
			}
			out[i] = apAnswer{ap: ap, infos: infos, err: err}
		}(i, ap)
	}
	wg.Wait()
	return out
}

// recordedOn is what this process's own records say of owner's sessions
// on ap -- name's, or all of them -- as Info marked with apErr, for an
// access point that cannot be asked. They are sessions this process
// placed or reached there, and the catalog may not have seen them yet.
func (m *Manager) recordedOn(owner, ap, name string, apErr error) []Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Info
	for _, sess := range m.sessions {
		if sess.owner != owner || !strings.EqualFold(sess.ap, ap) || (name != "" && sess.name != name) {
			continue
		}
		out = append(out, Info{
			Name:         sess.name,
			JobID:        m.jobID(sess.ap, sess.cluster, sess.proc),
			Schedd:       sess.ap,
			ClusterID:    sess.cluster,
			ProcID:       sess.proc,
			Status:       "unknown",
			LeaseExpires: sess.leaseExpires,
			Attached:     sess.shell != nil,
			Unverified:   true,
			APError:      apErr.Error(),
		})
	}
	return out
}

// unreachableRows is what is known of the sessions on an access point
// that could not be asked: the catalog's rows and this process's own
// records, once each.
func (m *Manager) unreachableRows(caller Caller, byAP map[string][]Info, ap, name string, apErr error) []Info {
	var out []Info
	seen := map[string]bool{}
	for _, info := range catalogRows(byAP, ap) {
		info.APError = apErr.Error()
		seen[info.JobID] = true
		out = append(out, info)
	}
	for _, info := range m.recordedOn(caller.Owner, ap, name, apErr) {
		if !seen[info.JobID] {
			out = append(out, info)
		}
	}
	return out
}

// listAll lists the caller's live sessions -- name's, or all of them --
// on every access point that may hold one: the ones the catalog names,
// the ones this process's records name, and also. Each is asked
// directly. An access point that cannot be asked contributes the
// catalog's copy of its sessions and this process's own records of
// them, marked with APError, so a session there is reported (and still
// counts against the name and the limit) rather than silently missing.
func (m *Manager) listAll(ctx context.Context, caller Caller, name string, also ...string) ([]Info, error) {
	infos, _, err := m.listAllAnswered(ctx, caller, name, also...)
	return infos, err
}

// listAllAnswered is listAll, and which access points answered (by
// lower-cased name): those whose sessions are known first-hand.
func (m *Manager) listAllAnswered(ctx context.Context, caller Caller, name string, also ...string) ([]Info, map[string]bool, error) {
	if !m.multi() {
		infos, err := m.listAdsOn(ctx, caller, "", name)
		return infos, nil, err
	}
	byAP, err := m.located(ctx, caller, name)
	if err != nil {
		return nil, nil, err
	}
	answered := map[string]bool{}
	var out []Info
	for _, a := range m.askAPs(ctx, caller, apSet(keysOf(byAP), m.knownAPs(caller.Owner, name), also), name) {
		if a.err != nil {
			m.log().Warn(m.opts.LogDest, "could not ask an access point for interactive sessions; using what is known of it",
				"access_point", a.ap, "owner", caller.Owner, "error", a.err)
			out = append(out, m.unreachableRows(caller, byAP, a.ap, name, a.err)...)
			continue
		}
		answered[strings.ToLower(a.ap)] = true
		out = append(out, a.infos...)
	}
	return out, answered, nil
}

// catalogRows is the catalog's rows for ap, whatever its spelling.
func catalogRows(byAP map[string][]Info, ap string) []Info {
	for k, v := range byAP {
		if strings.EqualFold(k, ap) {
			return v
		}
	}
	return nil
}

// lookupMulti resolves a session name to exactly one job on exactly one
// access point, or none.
//
// The in-process record comes first: a session this process created or
// reached is on the access point it recorded, and that access point is
// asked -- a failure to reach it is the answer, not a reason to look
// elsewhere. Only a name this process has no live record of goes to the
// catalog, and every access point the catalog names for it is asked; a
// name confirmed on two is ambiguous and refused.
func (m *Manager) lookupMulti(ctx context.Context, caller Caller, name string) (*Info, error) {
	if sess := m.sessionFor(caller.Owner, name); sess != nil && sess.ap != "" {
		a := m.askAPs(ctx, caller, []string{sess.ap}, name)[0]
		if a.err != nil {
			return nil, fmt.Errorf("session %q is on access point %s, which cannot be reached now: %w", name, sess.ap, a.err)
		}
		if info := firstNamed(a.infos, name); info != nil {
			return info, nil
		}
		// Gone from the access point it was on: drop the record, and
		// ask the catalog in case another server made one since.
		m.forget(sess, "no live job answers to this name on its access point")
	}
	byAP, err := m.located(ctx, caller, name)
	if err != nil {
		return nil, err
	}
	var found []Info
	for _, a := range m.askAPs(ctx, caller, apSet(keysOf(byAP)), name) {
		if a.err != nil {
			// Cannot be asked: the catalog says a session of that name
			// is there, so it still counts -- a name that might be on
			// two access points is not resolved to one of them.
			found = append(found, m.unreachableRows(caller, byAP, a.ap, name, a.err)...)
			continue
		}
		if info := firstNamed(a.infos, name); info != nil {
			found = append(found, *info)
		}
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
		if found[0].APError != "" {
			return nil, fmt.Errorf("session %q is on access point %s, which cannot be reached now: %s",
				name, found[0].Schedd, found[0].APError)
		}
		return &found[0], nil
	}
	jobs := make([]string, len(found))
	for i := range found {
		jobs[i] = found[i].JobID
	}
	sort.Strings(jobs)
	return nil, &AmbiguousSessionError{Name: name, Jobs: jobs}
}

// Find resolves a session name to the caller's one live session, or nil
// when they have none by that name. It does not adopt the session into
// this process's records (a caller that only attaches to it -- the SSH
// gateway -- must not start its lease).
//
// With several access points it is lookupMulti: a session this process
// knows is asked of its own access point only (no catalog needed), and
// a name on two access points is an AmbiguousSessionError.
func (m *Manager) Find(ctx context.Context, caller Caller, name string) (*Info, error) {
	if !caller.valid() {
		return nil, fmt.Errorf("authentication required")
	}
	if err := ValidateSessionName(name); err != nil {
		return nil, err
	}
	if m.multi() {
		return m.lookupMulti(ctx, caller, name)
	}
	infos, err := m.listAdsOn(ctx, caller, "", name)
	if err != nil {
		return nil, err
	}
	return firstNamed(infos, name), nil
}

// FindOn re-reads a known session on the access point it is on (ap; ""
// with one schedd), for a caller polling it: no catalog, no other access
// point. Nil when it is no longer live there.
func (m *Manager) FindOn(ctx context.Context, caller Caller, ap, name string) (*Info, error) {
	if !caller.valid() {
		return nil, fmt.Errorf("authentication required")
	}
	a := m.askAPs(ctx, caller, []string{ap}, name)[0]
	if a.err != nil {
		return nil, a.err
	}
	return firstNamed(a.infos, name), nil
}

func keysOf(m map[string][]Info) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func firstNamed(infos []Info, name string) *Info {
	for i := range infos {
		if infos[i].Name == name {
			info := infos[i]
			return &info
		}
	}
	return nil
}
