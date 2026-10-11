package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// GET /api/v1/utilization/jobs: the individual jobs of one workflow from
// the Utilization page, a page at a time.
//
// The workflow is named by the key /api/v1/utilization gave it, and the
// caller passes the same window, scope and filters, so the jobs listed
// are the jobs that were analysed. The key is resolved by
// utilization.WorkflowJobs -- Analyze's own filter and grouping -- not by
// a second account of what a workflow is.
//
// Where the jobs come from is a trade-off against memory. The analysis
// cache keeps answers, not jobs: holding the job set of every cached
// analysis would cost up to a quarter of a gigabyte per entry at the
// million-job ceiling. So the first page of a workflow re-reads the
// window -- narrowed to the workflow's owner when the cached analysis
// says it saw everything, because that cannot change which jobs are in
// it -- and keeps only that one workflow's jobs, in a small cache of its
// own, for the pages that follow. Scrolling a workflow costs one read;
// the analysis itself costs nothing more.
//
// That cache is bounded by the total jobs it holds, not just by its
// entries: at most HTTP_API_UTILIZATION_MAX_JOBS jobs (a million, ~250 MB,
// by default) across every cached workflow, evicting the least recently
// paged ones to fit a new one. A single workflow larger than that bound is
// not cached at all, and every page of it re-reads the window -- slow, but
// the alternative is holding more than the operator allowed.

// Page sizes.
const (
	utilizationJobsPageDefault = 100
	utilizationJobsPageMax     = 500
)

// utilizationJobSetEntries bounds how many workflows' jobs are held for
// paging at once. Memory is bounded separately, by total jobs (see the
// file comment).
const utilizationJobSetEntries = 4

// utilizationJobSet is one workflow's jobs, as read for paging.
type utilizationJobSet struct {
	jobs      []utilization.Job
	truncated bool
}

// UtilizationJobsResponse is one page of a workflow's jobs.
type UtilizationJobsResponse struct {
	Key        string               `json:"key"`
	Total      int                  `json:"total"`
	Offset     int                  `json:"offset"`
	NextOffset *int                 `json:"next_offset"`
	Sort       string               `json:"sort"`
	Order      string               `json:"order"`
	Truncated  bool                 `json:"truncated"`
	Jobs       []utilization.JobRow `json:"jobs"`
}

// jobsPage is the paging parameters.
type jobsPage struct {
	key, sort, order string
	offset, size     int
}

func parseJobsPage(r *http.Request) (jobsPage, error) {
	q := r.URL.Query()
	p := jobsPage{key: q.Get("w"), sort: utilization.SortCompleted, order: "desc", size: utilizationJobsPageDefault}
	if p.key == "" {
		return p, errors.New("missing w: the workflow key from /api/v1/utilization")
	}
	if v := q.Get("sort"); v != "" {
		if !utilization.ValidSort(v) {
			return p, fmt.Errorf("invalid sort %q: must be completed, submitted, wall, memory, cores, efficiency, disk or gpu", v)
		}
		p.sort = v
	}
	if v := q.Get("order"); v != "" {
		if v != "asc" && v != "desc" {
			return p, fmt.Errorf("invalid order %q: must be asc or desc", v)
		}
		p.order = v
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return p, errors.New("invalid offset: must be a non-negative number")
		}
		p.offset = n
	}
	if v := q.Get("page_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return p, errors.New("invalid page_size: must be a positive number")
		}
		p.size = min(n, utilizationJobsPageMax)
	}
	return p, nil
}

// handleUtilizationJobs handles GET /api/v1/utilization/jobs.
func (s *Handler) handleUtilizationJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	uq, err := s.parseUtilizationQuery(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	page, err := parseJobsPage(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The same scope as the analysis, settled the same way.
	c, ok := s.utilizationCall(w, r, uq)
	if !ok {
		return
	}
	ctx, user, mirror, analysisKey := c.ctx, c.user, c.mirror, c.key
	selection := uq.narrow(c.scope)
	if s.multi != nil {
		selection = uq.narrow("true")
	}

	set, err := s.utilizationJobSets().getWithin(ctx, analysisKey+"|w="+page.key, utilizationComputeTimeout(uq.limit),
		func(computeCtx context.Context) (utilizationJobSet, error) {
			sel, schedd := selection, uq.accessPoint
			// When the cached analysis read the whole window, narrowing
			// the read to this workflow's owner (and access point)
			// cannot change which of its jobs come back -- only how many
			// of everyone else's are read and thrown away. When it hit
			// its limit, the cut is "most recent N of everyone", and
			// only the same read reproduces it.
			if res, ok := s.utilizationResults().peek(analysisKey); ok && !res.summary.Truncated {
				if wf, ok := res.workflowSummary(page.key); ok {
					if wf.Owner != "" {
						sel = "(" + sel + ") && Owner == " + classadStringLit(wf.Owner)
					}
					if wf.Schedd != "" {
						schedd = wf.Schedd
					}
				}
			}
			since := time.Now().Unix() - int64(uq.days)*24*3600
			var jobs []utilization.Job
			var truncated bool
			var rerr error
			if s.multi != nil {
				jobs, truncated, rerr = s.multiUtilizationJobs(computeCtx, user, sel, schedd, since, uq.limit)
			} else {
				jobs, truncated, _, rerr = s.utilizationJobs(computeCtx, sel, since, uq.limit, mirror)
			}
			if rerr != nil {
				return utilizationJobSet{}, rerr
			}
			return utilizationJobSet{jobs: utilization.WorkflowJobs(jobs, page.key), truncated: truncated}, nil
		})
	if err != nil {
		var hubErr *multiap.Error
		if errors.As(err, &hubErr) {
			s.multiAPError(w, err)
			return
		}
		s.writeUtilizationError(w, err)
		return
	}
	if len(set.jobs) == 0 {
		s.writeError(w, http.StatusNotFound, "No workflow with that key in this analysis")
		return
	}
	rows, err := utilization.PageJobs(set.jobs, page.sort, page.order == "desc", page.offset, page.size)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := UtilizationJobsResponse{
		Key:       page.key,
		Total:     len(set.jobs),
		Offset:    page.offset,
		Sort:      page.sort,
		Order:     page.order,
		Truncated: set.truncated,
		Jobs:      rows,
	}
	if next := page.offset + len(rows); next < len(set.jobs) {
		resp.NextOffset = &next
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Handler) utilizationJobSets() *jobSetCache {
	s.jobSetCacheOnce.Do(func() {
		c := newSharedCache[utilizationJobSet](utilizationRefresh, utilizationComputeTimeout(utilizationDefaultLimit))
		c.maxEntries = utilizationJobSetEntries
		c.sizeOf = func(set utilizationJobSet) int { return len(set.jobs) }
		c.maxSize = s.utilizationMaxLimit()
		s.jobSetCacheVal = c
	})
	return s.jobSetCacheVal
}

// jobSetCache holds workflows' jobs for paging.
type jobSetCache = sharedCache[utilizationJobSet]
