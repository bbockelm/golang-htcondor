package httpserver

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/issues"
)

// The issues page's endpoint: what is going wrong on this access point,
// grouped so that a person can read it.
//
// The grouping is the whole point and it lives in webapi/issues; this
// file is the part that decides what to read, keeps it for a minute, and
// re-clusters it whenever the caller asks a differently-shaped question
// of the same records.

// IssuesResponse is the whole page.
type IssuesResponse struct {
	WindowSeconds int64 `json:"window_seconds"`
	ComputedAt    int64 `json:"computed_at"`
	// Granularity as applied, which may be the clamped form of what was
	// asked for.
	Granularity float64 `json:"granularity"`
	// IncludeEnded says whether run-attempt history was read: without
	// it the page describes what is stuck now, with it what has gone
	// wrong over the window.
	IncludeEnded bool `json:"include_ended"`
	// BucketSeconds is how much time one slice of a cluster's timeline
	// covers, so a caller can label it without re-deriving the window.
	BucketSeconds int64          `json:"bucket_seconds,omitempty"`
	Source        string         `json:"source,omitempty"`
	Truncated     bool           `json:"truncated,omitempty"`
	Notes         []string       `json:"notes,omitempty"`
	Sections      []IssueSection `json:"sections"`
	// Timings is what the answer cost to produce. Returned rather than
	// only logged: this page reads two large tables and then does real
	// work on what comes back, so "it is slow" has three possible
	// answers, and the person who can see the slowness is usually not
	// the person who can read the server's log.
	Timings *IssueTimings `json:"timings,omitempty"`
}

// IssueTimings splits the cost of one answer.
type IssueTimings struct {
	// HoldsMs and RunAttemptsMs are the two reads, with what they
	// returned beside them -- a slow read of forty rows and a slow read
	// of forty thousand are different problems.
	HoldsMs       int64 `json:"holds_query_ms"`
	Holds         int   `json:"holds"`
	RunAttemptsMs int64 `json:"run_attempts_query_ms"`
	RunAttempts   int   `json:"run_attempts"`
	// ClusterMs is the grouping: masking, the parse tree, the merge pass
	// and the per-cluster summaries.
	ClusterMs int64 `json:"cluster_ms"`
	// Cached says the reads were not done for this request. Without it a
	// second page load looks fast and hides what the first one cost.
	Cached bool `json:"cached"`
	// AgeSeconds is how old the cached reads are.
	AgeSeconds int64 `json:"age_seconds,omitempty"`
}

// IssueSection is one kind of problem: holds, or run attempts that
// failed.
type IssueSection struct {
	Kind  string `json:"kind"`
	Title string `json:"title"`
	// Total and Users are over the whole section, so a section header
	// can say "4,812 jobs, 11 users" without the reader adding up rows
	// -- and so the numbers do not change when the slider does.
	Total    int              `json:"total"`
	Users    int              `json:"users"`
	Clusters []issues.Cluster `json:"clusters"`
}

// Window bounds. An hour is the shortest that says anything on a quiet
// access point; a week is where the read stops being cheap enough to do
// on a page load.
const (
	minIssueWindow     = time.Hour
	maxIssueWindow     = 7 * 24 * time.Hour
	defaultIssueWindow = 24 * time.Hour
)

// issueBuckets is how many slices a cluster's timeline is cut into.
//
// Enough that a burst is distinguishable from a steady drip, few enough
// that each slice is a few pixels wide in a row of a list rather than a
// chart in its own right.
const issueBuckets = 24

// handleIssues handles GET /api/v1/issues.
func (s *Handler) handleIssues(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	owner := htcondor.GetAuthenticatedUserFromContext(ctx)
	// Same rule as every other listing: a non-admin browser session is
	// confined to its own jobs whatever it asks for.
	ownedByMe := true
	if v := r.URL.Query().Get("owned_by_me"); v != "" {
		if parsed, perr := strconv.ParseBool(v); perr == nil {
			ownedByMe = parsed
		}
	}
	if !ownedByMe && !s.isWebUIAdmin(r) {
		ownedByMe = true
	}

	window := defaultIssueWindow
	if v := r.URL.Query().Get("window_seconds"); v != "" {
		n, perr := strconv.ParseInt(v, 10, 64)
		if perr != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid window_seconds: %v", perr))
			return
		}
		window = time.Duration(n) * time.Second
	}
	if window < minIssueWindow {
		window = minIssueWindow
	}
	if window > maxIssueWindow {
		window = maxIssueWindow
	}

	granularity := 0.5
	if v := r.URL.Query().Get("granularity"); v != "" {
		g, perr := strconv.ParseFloat(v, 64)
		if perr != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid granularity: %v", perr))
			return
		}
		granularity = g
	}
	if granularity < 0 {
		granularity = 0
	}
	if granularity > 1 {
		granularity = 1
	}

	// Reading run-attempt history is the expensive half, so it is opt-in
	// -- and it is also the only half that can answer "what went wrong
	// and then stopped being wrong", so the page offers it prominently.
	includeEnded := true
	if v := r.URL.Query().Get("include_ended"); v != "" {
		if parsed, perr := strconv.ParseBool(v); perr == nil {
			includeEnded = parsed
		}
	}

	scope := "true"
	if ownedByMe {
		scope = fmt.Sprintf("Owner == %s", classadStringLit(owner))
	}
	key := fmt.Sprintf("%s|%t|%d|%t", owner, ownedByMe, int64(window/time.Second), includeEnded)
	set, cached, err := s.issueSets().get(key, func() (*issues.Set, error) {
		return issues.Collect(ctx, handlerIssueSource{s}, issues.Options{
			Scope:        scope,
			Window:       window,
			IncludeEnded: includeEnded,
		})
	})
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Could not read what is going wrong: %v", err))
		return
	}

	clusterStart := time.Now()
	resp := buildIssuesResponse(set, window, granularity, includeEnded)
	resp.Timings = &IssueTimings{
		HoldsMs:       set.HoldDuration.Milliseconds(),
		Holds:         set.HoldCount,
		RunAttemptsMs: set.EpochDuration.Milliseconds(),
		RunAttempts:   set.EpochCount,
		ClusterMs:     time.Since(clusterStart).Milliseconds(),
		Cached:        cached,
	}
	if cached {
		resp.Timings.AgeSeconds = int64(time.Since(set.ComputedAt).Seconds())
	}
	// Logged as well, so a slow page leaves a trace even when nobody was
	// looking at the response.
	if !cached {
		s.logger.Info(logging.DestinationHTTP, "issues answered",
			"holds_ms", resp.Timings.HoldsMs, "holds", resp.Timings.Holds,
			"run_attempts_ms", resp.Timings.RunAttemptsMs, "run_attempts", resp.Timings.RunAttempts,
			"cluster_ms", resp.Timings.ClusterMs,
			"window_seconds", resp.WindowSeconds, "owned_by_me", ownedByMe)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// buildIssuesResponse clusters a collected set at one granularity.
//
// Separate from the collection so it can be tested without a schedd, and
// because it is the half that runs again when somebody moves the slider.
func buildIssuesResponse(set *issues.Set, window time.Duration, granularity float64, includeEnded bool) IssuesResponse {
	end := set.ComputedAt.Unix()
	start := end - int64(window/time.Second)
	resp := IssuesResponse{
		WindowSeconds: int64(window / time.Second),
		ComputedAt:    end,
		Granularity:   granularity,
		IncludeEnded:  includeEnded,
		BucketSeconds: int64(window/time.Second) / issueBuckets,
		Source:        set.Source,
		Truncated:     set.Truncated,
		Notes:         set.Notes,
	}

	// One clusterer per kind rather than one for everything: the page
	// renders them as separate sections, and a section's own totals
	// should not depend on what the other section contains.
	for _, section := range []struct{ kind, title string }{
		{issues.KindHold, "Holds"},
		{issues.KindRunFailure, "Jobs that could not keep running"},
	} {
		c := issues.NewClusterer()
		users := map[string]bool{}
		total := 0
		for _, rec := range set.Records {
			if rec.Kind != section.kind {
				continue
			}
			c.Add(rec)
			total++
			if rec.Owner != "" {
				users[rec.Owner] = true
			}
		}
		if total == 0 {
			continue
		}
		resp.Sections = append(resp.Sections, IssueSection{
			Kind:  section.kind,
			Title: section.title,
			Total: total,
			Users: len(users),
			Clusters: c.Clusters(issues.RenderOptions{
				Granularity: granularity,
				LabelCode:   holdReasonLabel,
				Start:       start,
				End:         end,
				Buckets:     issueBuckets,
			}),
		})
	}
	if resp.Sections == nil {
		resp.Sections = []IssueSection{}
	}
	return resp
}
