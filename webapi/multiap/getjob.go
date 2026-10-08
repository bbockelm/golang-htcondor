package multiap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/ownerscope"
)

// Where a single-job read was answered.
const (
	SourceHub    = "hub"
	SourceSpoke  = "spoke"
	SourceSchedd = "schedd"
)

// maxCandidates bounds how many matches an incomplete id is resolved
// against; more than one is already a 409.
const maxCandidates = 50

// JobResult is a single-job read.
type JobResult struct {
	Row Row
	// Source is which tier answered: SourceHub, SourceSpoke or
	// SourceSchedd.
	Source string
	// Degraded is the AP's entry when the hub does not hold it fresh.
	Degraded *Degraded
}

// GetJob reads one of the caller's jobs.
//
// A complete id is read from its own AP: from the hub when the hub holds
// that AP fresh, else from the AP's spoke through the dbmirror freshness
// gates, else from the AP's schedd as the caller. A job no longer in the
// queue is answered from history, marked archived.
//
// An incomplete id ("123.0") is resolved among the caller's jobs across
// the hub's live queue and history: exactly one match is served (the
// result carries its complete id); several are a 409 listing them; none
// is a 404.
func (s *Service) GetJob(ctx context.Context, user string, id jobid.ID, projection []string) (*JobResult, error) {
	if user == "" {
		return nil, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	if err := jobid.Valid(id); err != nil {
		return nil, errorf(http.StatusBadRequest, "invalid job id: %v", err)
	}
	v := s.snapshot()
	if !id.Complete() {
		resolved, err := s.resolve(ctx, v, user, id)
		if err != nil {
			return nil, err
		}
		id = resolved
	}
	m, ok := v.members[strings.ToLower(id.Schedd)]
	if !ok {
		return nil, errorf(http.StatusNotFound, "%q is not an access point this server serves", id.Schedd)
	}
	id.Schedd = m.Name
	var degraded *Degraded
	for i := range v.sources.Degraded {
		if strings.EqualFold(v.sources.Degraded[i].Schedd, m.Name) {
			degraded = &v.sources.Degraded[i]
		}
	}
	res, err := s.getComplete(ctx, v, m, user, id, projection)
	if res != nil {
		res.Degraded = degraded
	}
	return res, err
}

func (s *Service) getComplete(ctx context.Context, v view, m apregistry.Member, user string, id jobid.ID, projection []string) (*JobResult, error) {
	match := fmt.Sprintf("ClusterId == %d && ProcId == %d", id.Cluster, id.Proc)
	constraint, err := ownerscope.Constrain("User", user, match)
	if err != nil {
		return nil, errorf(http.StatusBadRequest, "%v", err)
	}
	proj := projectionWith(projection, keyAttrs...)
	notFound := errorf(http.StatusNotFound, "job %s not found", s.Codec.Format(id))

	// Tier 1: the hub, when it holds this AP fresh.
	if v.fresh[strings.ToLower(m.Name)] {
		if row, err := s.hubFind(ctx, m.Name, constraint, proj); err == nil {
			if row == nil {
				return nil, notFound
			}
			return &JobResult{Row: *row, Source: SourceHub}, nil
		}
	}

	// Tier 2: the AP's own spoke, through the single-AP freshness gates.
	if row, served := s.spokeFind(ctx, m.Name, constraint, proj); served {
		if row != nil {
			return &JobResult{Row: *row, Source: SourceSpoke}, nil
		}
		return s.fromHubHistory(ctx, m.Name, constraint, proj, notFound)
	}

	// Tier 3: the schedd, as the caller. Authoritative for the live
	// queue; a job that has left it is looked for in the hub's history,
	// which is append-only and so still right if late.
	q := s.scheddFor(m)
	if q != nil {
		ads, _, err := q.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
			Limit: 1, Projection: proj, FetchOpts: htcondor.FetchMyJobs,
		})
		if err == nil {
			if len(ads) > 0 {
				return &JobResult{Row: Row{ID: id, Ad: ads[0]}, Source: SourceSchedd}, nil
			}
			return s.fromHubHistory(ctx, m.Name, constraint, proj, notFound)
		}
	}

	// Nothing better is reachable: the hub's copy, flagged degraded.
	row, err := s.hubFind(ctx, m.Name, constraint, proj)
	if err != nil {
		return nil, errorf(http.StatusServiceUnavailable,
			"access point %s is unreachable and the federation hub could not answer: %v", m.Name, err)
	}
	if row == nil {
		return nil, notFound
	}
	return &JobResult{Row: *row, Source: SourceHub}, nil
}

// fromHubHistory answers from the hub's history after a fresher tier
// said the job is not in the queue. History is append-only, so a late
// hub copy is still right about a job it holds.
func (s *Service) fromHubHistory(ctx context.Context, schedd, constraint string, proj []string, notFound error) (*JobResult, error) {
	row, err := s.hubFindTable(ctx, TableHistory, schedd, constraint, proj)
	if err == nil && row != nil {
		return &JobResult{Row: *row, Source: SourceHub}, nil
	}
	return nil, notFound
}

func (s *Service) scheddFor(m apregistry.Member) ScheddQuerier {
	if s.Schedd != nil {
		return s.Schedd(m)
	}
	if m.Schedd == nil {
		return nil
	}
	return m.Schedd
}

// hubFind reads the job from the hub's live queue, then its history.
func (s *Service) hubFind(ctx context.Context, schedd, constraint string, proj []string) (*Row, error) {
	row, err := s.hubFindTable(ctx, TableJobs, schedd, constraint, proj)
	if err != nil || row != nil {
		return row, err
	}
	return s.hubFindTable(ctx, TableHistory, schedd, constraint, proj)
}

func (s *Service) hubFindTable(ctx context.Context, table, schedd, constraint string, proj []string) (*Row, error) {
	dbc, closer, err := s.Hub.Client(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()
	return findOne(ctx, dbc, table, fmt.Sprintf("(%s) && (%s)", constraint, scheddIn([]string{schedd})), proj, "")
}

// spokeFind reads the job from the AP's spoke. served is false when the
// spoke could not be used (none, not current, unreachable), which sends
// the read on to the schedd.
func (s *Service) spokeFind(ctx context.Context, schedd, constraint string, proj []string) (*Row, bool) {
	if s.Spokes == nil {
		return nil, false
	}
	set, err := s.Spokes.Spokes(ctx)
	if err != nil {
		return nil, false
	}
	info := set.For(schedd)
	if info == nil || !dbmirror.JobsDecision(info, "").Use {
		return nil, false
	}
	dbc, closer, err := s.Spokes.ClientFor(ctx, info)
	if err != nil {
		return nil, false
	}
	defer closer()
	// A spoke's rows carry no ScheddName; the AP is the one it mirrors.
	row, err := findOne(ctx, dbc, TableJobs, constraint, proj, schedd)
	if err != nil {
		return nil, false
	}
	if row != nil || !dbmirror.HistoryDecision(info, nil).Use {
		return row, true
	}
	if row, err = findOne(ctx, dbc, TableHistory, constraint, proj, schedd); err != nil {
		return nil, true
	}
	return row, true
}

func findOne(ctx context.Context, dbc *dbrpc.Client, table, constraint string, proj []string, schedd string) (*Row, error) {
	var found *Row
	var perr error
	err := dbc.QueryRawProjectStream(ctx, table, constraint, proj, 1, func(text string) bool {
		row, err := rowFromText(text, schedd)
		if err != nil {
			perr = err
			return false
		}
		row.Archived = table == TableHistory
		found = &row
		return false
	})
	if err == nil {
		err = perr
	}
	return found, err
}

// resolve completes an id among the caller's jobs on every AP.
func (s *Service) resolve(ctx context.Context, v view, user string, id jobid.ID) (jobid.ID, error) {
	var names []string
	for _, m := range v.members {
		names = append(names, m.Name)
	}
	constraint, err := scoped(user, fmt.Sprintf("ClusterId == %d && ProcId == %d", id.Cluster, id.Proc), names)
	if err != nil {
		return jobid.ID{}, err
	}
	dbc, closer, err := s.Hub.Client(ctx)
	if err != nil {
		return jobid.ID{}, errorf(http.StatusServiceUnavailable, "the federation hub is unavailable: %v", err)
	}
	defer closer()

	found := map[string]JobRef{}
	for _, table := range []string{TableJobs, TableHistory} {
		var perr error
		err := dbc.QueryRawProjectStream(ctx, table, constraint, keyAttrs, maxCandidates, func(text string) bool {
			row, err := rowFromText(text, "")
			if err != nil {
				perr = err
				return false
			}
			key := strings.ToLower(row.ID.Schedd)
			if _, dup := found[key]; !dup {
				row.Archived = table == TableHistory
				found[key] = s.Ref(row)
			}
			return true
		})
		if err == nil {
			err = perr
		}
		if err != nil {
			return jobid.ID{}, errorf(http.StatusServiceUnavailable, "reading the federation hub: %v", err)
		}
	}
	switch len(found) {
	case 0:
		return jobid.ID{}, errorf(http.StatusNotFound, "job %s not found on any access point", s.Codec.Format(id))
	case 1:
		for _, ref := range found {
			return id.WithSchedd(ref.Schedd), nil
		}
	}
	cands := make([]JobRef, 0, len(found))
	for _, ref := range found {
		cands = append(cands, ref)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].Schedd < cands[j].Schedd })
	return jobid.ID{}, &Error{
		Status:     http.StatusConflict,
		Msg:        fmt.Sprintf("job %s exists on %d access points; name one", s.Codec.Format(id), len(cands)),
		Candidates: cands,
	}
}

// IsAmbiguous returns the candidates of a 409.
func IsAmbiguous(err error) ([]JobRef, bool) {
	var e *Error
	if errors.As(err, &e) && e.Status == http.StatusConflict {
		return e.Candidates, true
	}
	return nil, false
}
