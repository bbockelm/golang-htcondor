package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	htcondor "github.com/htcondor/golang-htcondor"
	"github.com/htcondor/golang-htcondor/logging"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Asking a person before a bulk removal or a bulk submission.
//
// A site can set a job count above which submit_job and remove_jobs stop
// and ask the human on the other end of the agent to confirm. Both
// thresholds are off by default, which is deliberate and is explained
// under "why off" below.
//
// The unit is jobs, not resources. A site that wants to bound core-hours
// wants a schedd SUBMIT_REQUIREMENT, which binds every submitter rather
// than only the ones who arrive through an agent; what this gate is for
// is the other thing -- an agent that misreads an instruction and acts at
// a scale the person never pictured. For that, "how many jobs" is the
// quantity the person approving can actually judge.
//
// # How the asking works
//
// The transport-level mechanism is elicitation, and the way it is reached
// is not the obvious one. The obvious one is to call ServerSession.Elicit
// from inside the tool and block on the answer. That is broken for
// exactly the newest clients: since protocol revision 2026-07-28 a server
// may not send a request while it is serving one, and the SDK enforces
// it -- Elicit returns "cannot be sent while serving a request on protocol
// version 2026-07-28" rather than asking anyone anything.
//
// The mechanism that works for both old and new clients is the
// multi-round-trip request (SEP-2322): the tool RETURNS the question, as
// an InputRequests map, and the client calls the tool a second time with
// the answer in InputResponses. New clients do that themselves; for old
// ones the SDK's own middleware fulfils the request by calling Elicit and
// re-invoking the handler, so one code path covers both.
//
// The consequence to keep in mind when reading the handlers: a gated tool
// RUNS TWICE. Everything before the gate happens again on the retry. That
// is why the gate sits after the counting and before the acting, and why
// the count is taken again on the second pass rather than carried across
// in the request state -- see confirmedCount.
//
// # Why off by default
//
// Client support is poor and fails in the worst available way. A client
// that declares the elicitation capability and then silently declines, or
// hangs, turns every gated call into a failure the user cannot explain --
// and the capability is declared by clients that do not honour it. A site
// turning this on should test it with the clients its users actually run.
//
// # What happens when the client cannot be asked
//
// The call proceeds, and the skip is logged at WARN.
//
// This is a deliberate choice between two bad options, and the one not
// taken deserves stating: refusing instead would mean that turning a
// threshold on does not gate bulk operations for an incompatible client
// but BLOCKS them, which for a site whose users are mostly on clients
// older than 2026-07-28 is not a safety feature at all -- it is an
// outage with a polite message. Letting the call through keeps the
// threshold a gate for the clients that can honour it and a no-op for
// the rest.
//
// The cost is the thing to be honest about: an operator who sets a
// threshold does NOT thereby have a limit. Every skip is logged with
// the count, the operation and the reason, so "the gate is not firing"
// is something an operator can see rather than infer. That log line is
// load-bearing -- it is the only evidence the limit was not applied.

// confirmRequestID is the key for this server's confirmation in the
// InputRequests/InputResponses maps. One id, because a call never asks
// two questions.
const confirmRequestID = "htcondor/bulk-confirm"

// bulkConfirmKind distinguishes the two gated operations in log lines and
// in the text the person is shown.
type bulkConfirmKind string

const (
	confirmSubmit bulkConfirmKind = "submit"
	confirmRemove bulkConfirmKind = "remove"
)

// confirmationRequired is what a gated tool returns instead of a result
// when the person has not been asked yet. handleCallTool passes it
// through untouched and each transport turns it into whatever it can: the
// SDK transport into an input-required result, the built-in one into a
// refusal, since it has no way to ask.
//
// It is not an error. An error result tells the model the call failed and
// invites it to try something else; this is a call that has not finished.
type confirmationRequired struct {
	Kind   bulkConfirmKind
	Count  int
	Params *mcp.ElicitParams
	// State is echoed by the client and read back by confirmedCount on
	// the retry. It carries the count the person was shown.
	State string
}

// confirmState is the request state, carried across the round trip.
//
// It is not signed. The spec requires integrity protection for an
// UNAUTHENTICATED server; every request here is authenticated, and the
// client echoes this value rather than composing it. The one thing it is
// relied on for is detecting that the queue moved under the question --
// see confirmedCount -- and that check only ever tightens the gate.
type confirmState struct {
	Kind  bulkConfirmKind `json:"kind"`
	Count int             `json:"count"`
}

// --- the client's side of the conversation ---------------------------

// elicitSupport is what a transport knows about the client's ability to
// answer a question. The built-in JSON-RPC transport records nothing, so
// the zero value -- cannot ask -- is what a caller arriving there gets.
type elicitSupport struct {
	// OK reports that this client declared form elicitation and this
	// transport can carry it.
	OK bool
	// Why, when OK is false, is the half-sentence put in the refusal so
	// the person reading the agent's transcript knows which end to fix.
	Why string
	// Responses are the answers the client echoed back, present only on
	// the second call of a round trip.
	Responses mcp.InputResponseMap
}

type elicitSupportKey struct{}

// withElicitSupport records what the transport knows about this client.
func withElicitSupport(ctx context.Context, s elicitSupport) context.Context {
	return context.WithValue(ctx, elicitSupportKey{}, s)
}

// elicitSupportFrom reports what the transport recorded, or a zero value
// -- cannot ask -- when nothing did.
func elicitSupportFrom(ctx context.Context) elicitSupport {
	s, _ := ctx.Value(elicitSupportKey{}).(elicitSupport)
	if !s.OK && s.Why == "" {
		s.Why = "this client did not offer to ask"
	}
	return s
}

// elicitSupportFromCapabilities reads a client's declared capabilities.
//
// An absent Elicitation block means the client never offered to ask
// anyone anything, and the spec is explicit that a server must not send
// an input request a client has not declared support for. Within the
// block, neither Form nor URL set means form elicitation, which is the
// backward-compatible reading the SDK itself takes; a client offering
// only URL elicitation cannot present this question, which is a form.
//
// No capabilities AT ALL is its own case, and it is the one that catches
// most real clients today. This server serves MCP statelessly, so each
// request is answered on its own: a 2026-07-28 client restates its
// capabilities in every request's _meta and is readable here, while an
// older client declared them once during an initialize whose session is
// gone -- the SDK hands this handler a synthesized InitializeParams
// carrying the protocol version and nothing else. So an older client's
// ability to ask is not merely absent, it is unknowable, and it is
// reported separately because the fix is different: the person has to
// use a newer client, not enable something in the one they have.
func elicitSupportFromCapabilities(caps *mcp.ClientCapabilities) elicitSupport {
	switch {
	case caps == nil:
		return elicitSupport{Why: "this client did not say whether it can ask anyone, " +
			"which is what a client older than the 2026-07-28 protocol looks like to a stateless server"}
	case caps.Elicitation == nil:
		return elicitSupport{Why: "this client says it cannot put a question to the person running it"}
	case caps.Elicitation.Form == nil && caps.Elicitation.URL != nil:
		return elicitSupport{Why: "this client offers only URL elicitation, and this is a form"}
	default:
		return elicitSupport{OK: true}
	}
}

// --- the gate --------------------------------------------------------

// confirmBulk is the gate itself, called once a tool knows how many jobs
// its call is about and before it acts on any of them.
//
// It returns (nil, nil) to proceed -- the threshold is off, the count is
// under it, the person has already said yes, or this client cannot be
// asked at all -- a *confirmationRequired to put the question, or an
// error carrying the person's "no".
//
// detail is the specifics for the question: the constraint for a removal,
// nothing for a submission. It is shown to a person, so it is quoted
// rather than interpreted.
func (s *Server) confirmBulk(ctx context.Context, kind bulkConfirmKind, count int, detail string) (*confirmationRequired, error) {
	threshold := s.confirmThreshold(kind)
	if threshold <= 0 || count <= threshold {
		return nil, nil
	}

	// Already asked? The answer rides on the second call of the round
	// trip. An approval is for a specific number of jobs: if more match
	// now than when the person said yes, the queue moved under the
	// question, and the right thing is to ask again rather than to act
	// on a bigger set than was approved.
	approved, answered, err := confirmedCount(ctx, kind)
	switch {
	case err != nil:
		return nil, err
	case answered && count <= approved:
		return nil, nil
	}

	// A client that cannot present the question does not block the call:
	// see "What happens when the client cannot be asked" above. It is
	// logged every time, because this line is the only record that a
	// configured threshold was not applied, and an operator reading
	// these is the one who finds out their gate reaches nobody.
	support := elicitSupportFrom(ctx)
	if !support.OK {
		s.logger.Warn(logging.DestinationMCP,
			"Allowing a bulk job operation unconfirmed: this client cannot be asked",
			"operation", string(kind),
			"jobs", count,
			"threshold", threshold,
			"reason", support.Why,
			"actor", htcondor.GetAuthenticatedUserFromContext(ctx))
		return nil, nil
	}

	state, err := json.Marshal(confirmState{Kind: kind, Count: count})
	if err != nil {
		return nil, fmt.Errorf("preparing the confirmation: %w", err)
	}
	return &confirmationRequired{
		Kind:   kind,
		Count:  count,
		Params: confirmElicitParams(kind, count, detail),
		State:  string(state),
	}, nil
}

// confirmThreshold is the configured job count for one operation, or 0
// where the site has not set one.
func (s *Server) confirmThreshold(kind bulkConfirmKind) int {
	switch kind {
	case confirmSubmit:
		return int(s.confirmSubmitOver.Load())
	case confirmRemove:
		return int(s.confirmRemoveOver.Load())
	default:
		return 0
	}
}

// confirmedCount reports the count a person approved on the first pass of
// this round trip: (count, true, nil) for a yes, and an error for a no.
//
// (0, false, nil) means no answer is present, which is the first call,
// and also covers an answer whose state cannot be tied back to a number
// -- an approval that names no count is not one this gate can honour.
func confirmedCount(ctx context.Context, kind bulkConfirmKind) (int, bool, error) {
	support := elicitSupportFrom(ctx)
	raw, ok := support.Responses[confirmRequestID]
	if !ok {
		return 0, false, nil
	}
	res, ok := raw.(*mcp.ElicitResult)
	if !ok {
		return 0, false, nil
	}
	if res.Action != "accept" {
		return 0, false, errConfirmDeclined(kind, res.Action)
	}

	var st confirmState
	if err := json.Unmarshal([]byte(confirmStateFrom(ctx)), &st); err != nil || st.Kind != kind {
		return 0, false, nil
	}
	return st.Count, true, nil
}

type confirmStateKey struct{}

// withConfirmState records the request state the client echoed back.
func withConfirmState(ctx context.Context, state string) context.Context {
	return context.WithValue(ctx, confirmStateKey{}, state)
}

func confirmStateFrom(ctx context.Context) string {
	s, _ := ctx.Value(confirmStateKey{}).(string)
	return s
}

// --- what the person is shown ----------------------------------------

// confirmElicitParams builds the question.
//
// It is written for the person, not the model: it leads with the number,
// because the number is the thing they are being asked to judge, and it
// says what will happen rather than naming the tool. A removal says it
// cannot be undone, because it cannot.
func confirmElicitParams(kind bulkConfirmKind, count int, detail string) *mcp.ElicitParams {
	var msg string
	switch kind {
	case confirmSubmit:
		msg = fmt.Sprintf("Submit %d jobs to this access point?", count)
		if detail != "" {
			msg += "\n\n" + detail
		}
	case confirmRemove:
		msg = fmt.Sprintf("Remove %d jobs? Removal cannot be undone.", count)
		if detail != "" {
			msg += fmt.Sprintf("\n\nThey are the jobs matching: %s", detail)
		}
	}
	msg += "\n\nAn agent asked for this, and this access point is configured to check with you first."
	return &mcp.ElicitParams{
		Mode:    "form",
		Message: msg,
		// No fields: the answer is the accept/decline action itself. An
		// empty object schema is what the spec provides for a question
		// whose whole content is the choice.
		RequestedSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	}
}

// errConfirmDeclined is the person saying no, or the question going away
// unanswered. Phrased so the model does not treat it as a transient
// failure to route around: it names the person as the decider and says
// not to retry.
func errConfirmDeclined(kind bulkConfirmKind, action string) error {
	what, done := "submission", "submitted"
	if kind == confirmRemove {
		what, done = "removal", "removed"
	}
	if action == "decline" {
		return fmt.Errorf("the person running this client declined the %s, so nothing was %s; "+
			"do not retry it -- ask them what they would like instead", what, done)
	}
	return fmt.Errorf("the confirmation for this %s was dismissed without an answer, so nothing was done; "+
		"ask the person whether they want it before trying again", what)
}

// SetConfirmThresholds sets the job counts above which submit_job and
// remove_jobs ask a person first. Zero turns a gate off. It is the
// dynamic half of the two settings: a reconfigure calls this.
//
// Unlike SetReadOnly this does not invalidate the catalogue. The tool
// list is the same either way -- what changes is whether a call over the
// threshold finishes in one round trip or two -- and a client holding a
// catalogue from before the change is not holding anything wrong.
func (s *Server) SetConfirmThresholds(submitOver, removeOver int) {
	if submitOver < 0 {
		submitOver = 0
	}
	if removeOver < 0 {
		removeOver = 0
	}
	wasSubmit := s.confirmSubmitOver.Swap(int64(submitOver))
	wasRemove := s.confirmRemoveOver.Swap(int64(removeOver))
	if wasSubmit == int64(submitOver) && wasRemove == int64(removeOver) {
		return
	}
	switch {
	case submitOver <= 0 && removeOver <= 0:
		s.logger.Info(logging.DestinationMCP,
			"MCP no longer asks anyone to confirm a bulk submission or removal")
	default:
		s.logger.Info(logging.DestinationMCP,
			"MCP will ask the person running the client to confirm bulk job operations",
			"submit_over", submitOver, "remove_over", removeOver,
			"note", "a client that cannot present the question proceeds unasked; each skip is logged at WARN")
	}
}

// countMatching is how many jobs a constraint matches right now.
//
// It projects ClusterId alone, because the only thing wanted is the
// length of the answer, and asking for the whole ad of every job about
// to be removed would make the gate more expensive than the removal.
//
// Limit is -1 -- unlimited -- and saying so explicitly is the point of
// using QueryWithOptions here. A capped count is not a smaller count,
// it is a WRONG one, and wrong in the direction that matters: a query
// that stopped at the default 50 would report 50 for a constraint
// matching ten thousand jobs, which is under every threshold a site
// would plausibly set, so the gate would fall silent exactly when it
// was needed. Leaving the limit unset happens to mean unlimited on this
// path today; it is one ApplyDefaults call away from meaning 50.
func (s *Server) countMatching(ctx context.Context, constraint string) (int, error) {
	ads, _, err := s.scheddFor(ctx).QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Limit:      -1,
		Projection: []string{"ClusterId"},
	})
	if err != nil {
		return 0, err
	}
	return len(ads), nil
}
