package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
)

// The watch tools exist because an agent has no way to be woken. Between
// turns nothing of it is running, so a notification has nowhere to
// arrive; the only thing it can reliably do is ask a cheap question when
// it next runs. So watch_jobs registers a durable question and
// check_watches collects the answers -- "what happened while I was gone"
// in one call, however long "gone" was.
//
// Registration evaluates immediately, which matters more than it looks.
// The condition may already be true (a cluster that finished before the
// agent thought to wait), and a watch that only fires on a FUTURE change
// would wait forever for something that already happened. It also makes
// the common case a genuine one-shot: ask, and if the answer exists, get
// it now.

// MaxWaitSeconds caps the in-call wait when nothing else is configured.
// It is deliberately short: this blocks an MCP request, and a remote
// connector's or gateway's own timeout is the real ceiling and is not
// something this server knows. A block that outlives that timeout is
// worse than not blocking at all -- the gateway severs the connection,
// so the client gets an error and never receives the watch id, even
// though the watch was registered. 20s comfortably fits a 30s gateway;
// deployments behind a tighter (or looser) one tune it with
// HTTP_API_MCP_WATCH_MAX_WAIT.
//
// It is a ceiling on one call, not on the wait. A watch outlives every
// call made about it, so a wait longer than the cap is any number of
// bounded check_watches calls -- which is why the tools recommend
// RecommendedWaitSeconds rather than the cap, and why a wait that runs
// out answers "not yet" instead of holding the connection open.
const MaxWaitSeconds = 20

func (s *Server) jobWatchEnabled() bool {
	return s != nil && s.jobWatch != nil && s.jobWatchEval != nil
}

// maxWaitSeconds is the effective in-call blocking cap: the configured
// override (Config.WatchMaxWait) when positive, else the MaxWaitSeconds
// default. A sub-second override still yields at least one second so the
// cap never silently becomes "never block".
func (s *Server) maxWaitSeconds() int {
	if s.watchMaxWait > 0 {
		if secs := int(s.watchMaxWait / time.Second); secs > 0 {
			return secs
		}
		return 1
	}
	return MaxWaitSeconds
}

// watchPollInterval is how often a blocking call re-evaluates the
// owner's watches. There is nothing to be woken by: the evaluator is a
// sweep over the queue and the history, so a wait is that sweep run
// again until it has an answer. Two seconds is short enough that the
// answer is fresh and long enough that a held-open call is not a load
// source. A var so a test can shorten it; nothing else writes it.
var watchPollInterval = 2 * time.Second

// awaitAnswer is the one blocking primitive behind both watch_jobs and
// check_watches: evaluate this owner's watches, ask the caller whether
// that produced an answer, and if not, sleep and go round until the
// deadline. A deadline in the past means one evaluation and no sleep,
// which is the non-blocking call -- so both tools take the same path and
// "fires straight away if it is already satisfied" cannot hold for one
// of them and not the other.
//
// The last sleep is trimmed to the deadline: a caller that asked for 30
// seconds gets 30, not 30 rounded up to the next poll.
func (s *Server) awaitAnswer(ctx context.Context, owner string, deadline time.Time, answered func() (bool, error)) error {
	return jobwatch.Await(ctx, s.jobWatchEval, owner, deadline, watchPollInterval,
		func(err error) {
			s.logger.Warn(logging.DestinationGeneral, "evaluating job watches failed", "error", err)
		}, answered)
}

// jobWatchTools returns the tool definitions, with the event vocabulary
// rendered from jobwatch.Events so what the agent is told and what the
// evaluator implements cannot drift.
func jobWatchTools(maxWait int) []Tool {
	// Rendered from the cap, so what the agent is told to do and how long it
	// is allowed to do it cannot drift apart. See watch_advice.go.
	advice := waitAdvice(maxWait)
	checking := checkAdvice(maxWait)

	events := make([]interface{}, 0, len(jobwatch.Events))
	for _, spec := range jobwatch.Events {
		events = append(events, string(spec.Event))
	}
	return []Tool{
		{
			Name: "watch_jobs",
			Description: "Register a question about your jobs, to be answered WITHOUT polling. " + advice.Strategy + "\n\n" +
				"CALL THIS ONCE PER QUESTION, to register it. Everything after that is check_watches: it reports the answer, " +
				"and it is the tool that can wait for it. Calling watch_jobs again resolves back to the same watch, does not " +
				"check it, and does not wait.\n\n" +
				"Use this instead of repeatedly calling query_jobs in a loop; query_jobs is for a one-off " +
				"status snapshot.\n\n" +
				"IMPORTANT: do not write a constraint like 'JobStatus == 4' to wait for completion. A finished job is removed from " +
				"the queue by the schedd, so that condition is never observed. Use event=\"done\" instead, which is resolved across " +
				"the queue and the history archive.\n\nEvents:\n" + jobwatch.DescribeEvents() +
				"\nIf the condition is ALREADY satisfied when you call this, it fires straight away and the answer is in this response — " +
				"so it is safe to register a watch after submitting, or after the jobs have already finished.\n\n" +
				"\"succeeded\" and \"failed\" need the history archive to say how a job ended. If the jobs leave the queue and no " +
				"history record arrives, the watch still fires after a few minutes and tells you the outcome could not be " +
				"determined, so you can go and check — it will not leave you waiting silently.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"constraint": map[string]interface{}{
						"type": "string",
						"description": "ClassAd expression selecting which of YOUR jobs this is about, e.g. 'ClusterId == 42'. Always scoped to you. " +
							"A constraint matching no job is accepted, not rejected -- it will fire if matching jobs appear later -- " +
							"and the response says so explicitly, because far more often it means a wrong ClusterId or a typo.",
					},
					"event": map[string]interface{}{
						"type": "string", "enum": events,
						"description": "What to wait for. Default \"done\".",
					},
					"mode": map[string]interface{}{
						"type": "string", "enum": []interface{}{"all", "any"},
						"description": "Whether every selected job must have the event or just one. Defaults to \"all\" for done/succeeded " +
							"and \"any\" for failed/held/running, which is what the plain reading of each means. The mode actually used is echoed back.",
					},
					"condition": map[string]interface{}{
						"type":        "string",
						"description": "Only with event=\"custom\": a ClassAd expression over the job ad, evaluated while the job is in the queue.",
					},
					"label": map[string]interface{}{
						"type":        "string",
						"description": "A short name for this watch, echoed back so you can tell several apart.",
					},
					"wait_seconds": map[string]interface{}{
						"type":        "integer",
						"description": advice.WaitParam,
					},
					"ttl_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "How long the watch stays active. Default 24 hours, maximum 7 days.",
					},
				},
				"required": []string{"constraint"},
			},
		},
		{
			Name: "check_watches",
			Description: "Collect the answers to watches you registered with watch_jobs — 'what happened while I was gone'. " +
				"THIS is the tool to call every time you want to know whether a watch has been answered, and to call again " +
				"until it has been; watch_jobs only registers the question. Returns watches that have fired since you last " +
				"looked, plus the progress of those still waiting.\n\n" + checking.Waiting + "\n\n" +
				"Reading does not consume an answer; pass include_delivered to see ones you have already been shown.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"watch_id":          map[string]interface{}{"type": "string", "description": "Only report this watch. With wait_seconds, wait for this one specifically."},
					"include_delivered": map[string]interface{}{"type": "boolean", "description": "Also report answers you have already been shown (default false)."},
					"wait_seconds": map[string]interface{}{
						"type":        "integer",
						"description": checking.WaitParam,
					},
				},
			},
		},
		{
			Name: "create_watch_url",
			Description: "Hand the waiting to something that runs while you do not. Returns a URL that " +
				"reports whether ONE watch has fired, and blocks until it does.\n\n" +
				"check_watches waits inside your turn; this waits outside it. Give the URL to an agent " +
				"framework, a poller, a CI step or a colleague: a GET blocks until the watch fires, then " +
				"answers, so the waiting costs you nothing and the wake-up is not late. The URL needs no " +
				"credentials -- possession is the authorization -- and it reports that one watch and " +
				"nothing else.\n\n" +
				"Register the watch with watch_jobs first; this tool takes its id. Do NOT poll the URL " +
				"yourself in a loop; inside a turn, check_watches is the cheaper way to wait.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"watch_id": map[string]interface{}{"type": "string", "description": "The id returned by watch_jobs."},
					"ttl_seconds": map[string]interface{}{
						"type": "integer",
						// Built from the constants rather than restated, so the
						// documented numbers cannot drift from the enforced ones.
						"description": fmt.Sprintf("How long the URL stays valid, in seconds. Default %d, "+
							"maximum %d. The watch's own lifetime is the real limit: once it expires the "+
							"URL answers \"gone\".",
							int(shareurl.DefaultWatchTTL.Seconds()), int(shareurl.MaxWatchTTL.Seconds())),
					},
				},
				"required": []string{"watch_id"},
			},
		},
		{
			Name:        "cancel_watch",
			Description: "Stop a watch you registered with watch_jobs and discard its answer.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"watch_id": map[string]interface{}{"type": "string", "description": "The id returned by watch_jobs."},
				},
				"required": []string{"watch_id"},
			},
		},
	}
}

// watchActor resolves who this call is for. A watch is stored against
// this identity and every readback filters on it, so an unidentified
// caller must be refused rather than defaulted -- the evaluator reads
// job ads as the daemon, and the owner recorded here is the only thing
// confining a watch to its registrant.
func (s *Server) watchActor(ctx context.Context) (string, error) {
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		return "", fmt.Errorf("authentication required: a watch is registered against your identity, and the caller's could not be established")
	}
	return ownerFromActor(actor), nil
}

func (s *Server) toolWatchJobs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if !s.jobWatchEnabled() {
		return nil, fmt.Errorf("job watches are not configured on this server")
	}
	owner, err := s.watchActor(ctx)
	if err != nil {
		return nil, err
	}

	constraint, _ := args["constraint"].(string)
	label, _ := args["label"].(string)
	condition, _ := args["condition"].(string)
	event := jobwatch.Event(strings.TrimSpace(stringArg(args, "event")))
	if event == "" {
		event = jobwatch.EventDone
	}
	mode := jobwatch.Mode(strings.TrimSpace(stringArg(args, "mode")))
	if mode == "" {
		mode = jobwatch.DefaultMode(event)
	}

	w, err := jobwatch.New(owner, label, constraint, event, condition, mode)
	if err != nil {
		return nil, err
	}
	ttl := time.Duration(intArg(args, "ttl_seconds", 0)) * time.Second
	if w, err = s.jobWatch.Register(ctx, w, ttl); err != nil {
		return nil, err
	}

	// A caller re-asking a question it already registered is not asking
	// for another wait. Registration coalesces onto the existing watch,
	// so without this the second call blocks all over again -- which is
	// exactly the polling loop watches exist to replace, and it is what
	// an agent does when it reads watch_jobs as "get me the state now".
	// Waiting on a watch that exists is check_watches' job, and it can
	// do it without this tool's "call me once" rule getting in the way,
	// so answer from what is already known and name that tool.
	callStart := time.Now()
	deadline := callStart.Add(time.Duration(s.clampWait(intArg(args, "wait_seconds", 0))) * time.Second)
	if w.Coalesced {
		deadline = callStart
	}
	var got *jobwatch.Watch
	err = s.awaitAnswer(ctx, owner, deadline, func() (bool, error) {
		found, err := s.oneWatch(ctx, owner, w.ID)
		if err != nil {
			return false, err
		}
		got = found
		return found == nil || !found.FiredAt.IsZero(), nil
	})
	if err != nil {
		return nil, err
	}
	// How long this CALL blocked -- not how long the watch has been
	// open, which is watch_age_seconds. An agent that cannot see the
	// clock has no other way to tell a watch that fired at once from one
	// that came back after ten minutes of waiting, and the two mean very
	// different things about the pool.
	blocked := time.Since(callStart)
	out := map[string]interface{}{
		"watch_id":        w.ID,
		"event":           string(w.Event),
		"constraint":      w.Constraint,
		"fired":           got != nil && !got.FiredAt.IsZero(),
		"blocked_seconds": int(blocked.Round(time.Second).Seconds()),
	}
	if got != nil {
		out["watch_age_seconds"] = int(time.Since(got.CreatedAt).Round(time.Second).Seconds())
		out["unsatisfiable"] = got.Unsatisfiable
	}
	return structuredTextResult(renderWatchRegistration(got, w, blocked), out), nil
}

func (s *Server) toolCheckWatches(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if !s.jobWatchEnabled() {
		return nil, fmt.Errorf("job watches are not configured on this server")
	}
	owner, err := s.watchActor(ctx)
	if err != nil {
		return nil, err
	}
	wanted, _ := args["watch_id"].(string)
	includeDelivered, _ := args["include_delivered"].(bool)

	// Evaluating before reporting is what makes this tool answerable at
	// all: an agent asking "what happened" should not be told "nothing
	// yet" only because the sweep is a few seconds out of phase with its
	// turn. wait_seconds keeps doing exactly that until something fires
	// or the deadline passes, so waiting is the same sweep, held open --
	// there is no second mechanism, and an answer that already exists
	// still comes back on the first pass without blocking.
	callStart := time.Now()
	deadline := callStart.Add(time.Duration(s.clampWait(intArg(args, "wait_seconds", 0))) * time.Second)
	var news, waiting []*jobwatch.Watch
	err = s.awaitAnswer(ctx, owner, deadline, func() (bool, error) {
		var err error
		news, waiting, err = s.sortWatches(ctx, owner, wanted, includeDelivered)
		if err != nil {
			return false, err
		}
		return len(news) > 0, nil
	})
	if err != nil {
		return nil, err
	}
	blocked := time.Since(callStart)

	deliver := make([]string, 0, len(news))
	for _, w := range news {
		deliver = append(deliver, w.ID)
	}
	if len(deliver) > 0 {
		if err := s.jobWatch.MarkDelivered(ctx, owner, deliver); err != nil {
			s.logger.Warn(logging.DestinationGeneral, "recording job watch delivery failed", "error", err)
		}
	}
	watchEntry := func(w *jobwatch.Watch, fired bool) map[string]interface{} {
		e := map[string]interface{}{
			"watch_id":      w.ID,
			"event":         string(w.Event),
			"constraint":    w.Constraint,
			"fired":         fired,
			"matched_total": w.MatchedTotal,
		}
		// Age for a watch still waiting, time-to-answer for one that
		// fired: in both cases how long this question has been open,
		// which is what an agent needs to judge whether to keep waiting
		// or go and look at the pool itself.
		if fired {
			e["waited_seconds"] = int(w.FiredAt.Sub(w.CreatedAt).Round(time.Second).Seconds())
			e["unsatisfiable"] = w.Unsatisfiable
		} else {
			e["waited_seconds"] = int(time.Since(w.CreatedAt).Round(time.Second).Seconds())
		}
		return e
	}
	entries := make([]map[string]interface{}, 0, len(news)+len(waiting))
	for _, w := range news {
		entries = append(entries, watchEntry(w, true))
	}
	for _, w := range waiting {
		entries = append(entries, watchEntry(w, false))
	}
	return structuredTextResult(renderWatchReport(news, waiting, includeDelivered, blocked), map[string]interface{}{
		"watches": entries,
		"count":   len(entries),
		// How long THIS CALL blocked, as against the per-watch
		// waited_seconds, which is how long that watch has been open.
		"blocked_seconds": int(blocked.Round(time.Second).Seconds()),
		"new_count":       len(news),
		"waiting_count":   len(waiting),
	}), nil
}

// sortWatches splits this owner's watches into the ones with an answer to
// report and the ones still waiting, applying the same filters the report
// does -- one watch when watch_id names it, and answers already shown only
// when they are asked for. A blocking call asks this every pass, so what it
// waits for and what it finally prints cannot come apart.
func (s *Server) sortWatches(ctx context.Context, owner, wanted string, includeDelivered bool) (news, waiting []*jobwatch.Watch, err error) {
	all, err := s.jobWatch.ForOwner(ctx, owner, nil)
	if err != nil {
		return nil, nil, err
	}
	for _, w := range all {
		if wanted != "" && w.ID != wanted {
			continue
		}
		if w.FiredAt.IsZero() {
			waiting = append(waiting, w)
			continue
		}
		if !w.DeliveredAt.IsZero() && !includeDelivered && wanted == "" {
			continue
		}
		news = append(news, w)
	}
	return news, waiting, nil
}

func (s *Server) toolCancelWatch(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if !s.jobWatchEnabled() {
		return nil, fmt.Errorf("job watches are not configured on this server")
	}
	owner, err := s.watchActor(ctx)
	if err != nil {
		return nil, err
	}
	id, _ := args["watch_id"].(string)
	ok, err := s.jobWatch.Cancel(ctx, owner, id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("no watch %q of yours to cancel; it may have already fired and expired, or never existed", id)
	}
	return structuredTextResult(fmt.Sprintf("Cancelled watch %s.", id),
		map[string]interface{}{"watch_id": id, "cancelled": true}), nil
}

func (s *Server) oneWatch(ctx context.Context, owner, id string) (*jobwatch.Watch, error) {
	all, err := s.jobWatch.ForOwner(ctx, owner, nil)
	if err != nil {
		return nil, err
	}
	for _, w := range all {
		if w.ID == id {
			return w, nil
		}
	}
	return nil, nil
}

func (s *Server) clampWait(n int) int {
	limit := s.maxWaitSeconds()
	switch {
	case n < 0:
		return 0
	case n > limit:
		return limit
	}
	return n
}
