package interactive

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

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
	// ctx routed to it, ready for a submission there.
	Assign(ctx context.Context, caller Caller) (ap string, routed context.Context, err error)
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

// listAll lists the caller's live sessions -- name's, or all of them --
// on every access point that may hold one: the ones the catalog names,
// the ones this process's records name, and also. Each is asked
// directly. An access point that cannot be asked contributes the
// catalog's copy of its sessions, marked Unverified, so a session there
// is reported (and still counts against the name and the limit) rather
// than silently missing.
func (m *Manager) listAll(ctx context.Context, caller Caller, name string, also ...string) ([]Info, error) {
	if !m.multi() {
		return m.listAdsOn(ctx, caller, "", name)
	}
	byAP, err := m.located(ctx, caller, name)
	if err != nil {
		return nil, err
	}
	var fromCatalog []string
	for ap := range byAP {
		fromCatalog = append(fromCatalog, ap)
	}
	var out []Info
	for _, ap := range apSet(fromCatalog, m.knownAPs(caller.Owner, name), also) {
		infos, err := m.listAdsOn(ctx, caller, ap, name)
		if err != nil {
			m.log().Warn(m.opts.LogDest, "could not ask an access point for interactive sessions; using the catalog's copy",
				"access_point", ap, "owner", caller.Owner, "error", err)
			for _, info := range catalogRows(byAP, ap) {
				info.APError = err.Error()
				out = append(out, info)
			}
			continue
		}
		out = append(out, infos...)
	}
	return out, nil
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
// access point.
//
// The in-process record comes first: a session this process created or
// reached is on the access point it recorded, and that access point is
// asked -- a failure to reach it is the answer, not a reason to look
// elsewhere. Only a name this process has no live record of goes to the
// catalog, and every access point the catalog names for it is asked; a
// name confirmed on two is ambiguous and refused.
func (m *Manager) lookupMulti(ctx context.Context, caller Caller, name string) (*Info, error) {
	if sess := m.sessionFor(caller.Owner, name); sess != nil && sess.ap != "" {
		infos, err := m.listAdsOn(ctx, caller, sess.ap, name)
		if err != nil {
			return nil, err
		}
		if info := firstNamed(infos, name); info != nil {
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
	for _, ap := range apSet(keysOf(byAP)) {
		infos, err := m.listAdsOn(ctx, caller, ap, name)
		if err != nil {
			// Cannot be asked: the catalog says a session of that name
			// is there, so it still counts -- a name that might be on
			// two access points is not resolved to one of them.
			for _, info := range catalogRows(byAP, ap) {
				info.APError = err.Error()
				found = append(found, info)
			}
			continue
		}
		if info := firstNamed(infos, name); info != nil {
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
