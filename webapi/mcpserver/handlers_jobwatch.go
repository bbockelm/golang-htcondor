package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
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
// HTTP_API_MCP_WATCH_MAX_WAIT. Anything longer belongs to check_watches,
// which does not depend on a connection staying open.
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

// jobWatchTools returns the tool definitions, with the event vocabulary
// rendered from jobwatch.Events so what the agent is told and what the
// evaluator implements cannot drift.
func jobWatchTools(maxWait int) []Tool {
	// Rendered from the cap, so what the agent is told to do and how long it
	// is allowed to do it cannot drift apart. See watch_advice.go.
	advice := waitAdvice(maxWait)

	events := make([]interface{}, 0, len(jobwatch.Events))
	for _, spec := range jobwatch.Events {
		events = append(events, string(spec.Event))
	}
	return []Tool{
		{
			Name: "watch_jobs",
			Description: "Wait for something to happen to your jobs WITHOUT polling. " + advice.Strategy + "\n\n" +
				"CALL THIS ONCE PER QUESTION. To see whether a watch has been answered, call check_watches: " +
				"calling watch_jobs again resolves back to the same watch and does not check it.\n\n" +
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
						"type": "integer",
						"description": advice.WaitParam + " Waiting again by re-calling watch_jobs is not " +
							"how to check on a watch you already registered; that is check_watches.",
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
				"THIS is the tool to call every time you want to know whether a watch has been answered; watch_jobs only " +
				"registers it. Returns watches that have fired since you last looked, plus the progress of those still waiting. " +
				"Cheap to call at the start of a turn. Reading does not consume an answer; pass include_delivered to see ones you have already been shown.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"watch_id":          map[string]interface{}{"type": "string", "description": "Only report this watch."},
					"include_delivered": map[string]interface{}{"type": "boolean", "description": "Also report answers you have already been shown (default false)."},
				},
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
	// Answer from what is already known and name the tool that does
	// this properly.
	deadline := time.Now().Add(time.Duration(s.clampWait(intArg(args, "wait_seconds", 0))) * time.Second)
	if w.Coalesced && !blockingIsPrimary(s.maxWaitSeconds()) {
		deadline = time.Now()
	}
	for {
		if _, err := s.jobWatchEval.CheckOwner(ctx, owner); err != nil {
			s.logger.Warn(logging.DestinationGeneral, "evaluating a new job watch failed", "error", err)
		}
		got, err := s.oneWatch(ctx, owner, w.ID)
		if err != nil {
			return nil, err
		}
		if got == nil || !got.FiredAt.IsZero() || !time.Now().Before(deadline) {
			return structuredTextResult(renderWatchRegistration(got, w), map[string]interface{}{
				"watch_id":   w.ID,
				"event":      string(w.Event),
				"constraint": w.Constraint,
				"fired":      got != nil && !got.FiredAt.IsZero(),
			}), nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Server) toolCheckWatches(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if !s.jobWatchEnabled() {
		return nil, fmt.Errorf("job watches are not configured on this server")
	}
	owner, err := s.watchActor(ctx)
	if err != nil {
		return nil, err
	}
	// Evaluate before reporting: an agent asking "what happened" should
	// not be told "nothing yet" only because the sweep is a few seconds
	// out of phase with its turn.
	if _, err := s.jobWatchEval.CheckOwner(ctx, owner); err != nil {
		s.logger.Warn(logging.DestinationGeneral, "evaluating job watches failed", "error", err)
	}

	all, err := s.jobWatch.ForOwner(ctx, owner, nil)
	if err != nil {
		return nil, err
	}
	wanted, _ := args["watch_id"].(string)
	includeDelivered, _ := args["include_delivered"].(bool)

	var news, waiting []*jobwatch.Watch
	var deliver []string
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
		deliver = append(deliver, w.ID)
	}
	if len(deliver) > 0 {
		if err := s.jobWatch.MarkDelivered(ctx, owner, deliver); err != nil {
			s.logger.Warn(logging.DestinationGeneral, "recording job watch delivery failed", "error", err)
		}
	}
	watchEntry := func(w *jobwatch.Watch, fired bool) map[string]interface{} {
		return map[string]interface{}{
			"watch_id":      w.ID,
			"event":         string(w.Event),
			"constraint":    w.Constraint,
			"fired":         fired,
			"matched_total": w.MatchedTotal,
		}
	}
	entries := make([]map[string]interface{}, 0, len(news)+len(waiting))
	for _, w := range news {
		entries = append(entries, watchEntry(w, true))
	}
	for _, w := range waiting {
		entries = append(entries, watchEntry(w, false))
	}
	return structuredTextResult(renderWatchReport(news, waiting, includeDelivered), map[string]interface{}{
		"watches":       entries,
		"count":         len(entries),
		"new_count":     len(news),
		"waiting_count": len(waiting),
	}), nil
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
