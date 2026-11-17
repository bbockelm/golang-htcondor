package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func confirmServer(t *testing.T, submitOver, removeOver int) *Server {
	t.Helper()
	s, err := NewServer(Config{
		ScheddName:        "test",
		ScheddAddr:        "127.0.0.1:9618",
		ConfirmSubmitOver: submitOver,
		ConfirmRemoveOver: removeOver,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// canAsk is a context from a client that declared form elicitation, with
// whatever it has already answered.
func canAsk(answers mcp.InputResponseMap, state string) context.Context {
	ctx := withElicitSupport(context.Background(), elicitSupport{OK: true, Responses: answers})
	return withConfirmState(ctx, state)
}

// accepted is the answer map for a person who said yes.
func accepted() mcp.InputResponseMap {
	return mcp.InputResponseMap{confirmRequestID: &mcp.ElicitResult{Action: "accept"}}
}

// The default. A server nobody configured asks nobody anything, however
// large the call -- which is the behaviour every deployment had before
// this existed.
func TestNoThresholdAsksNobody(t *testing.T) {
	s := confirmServer(t, 0, 0)
	for _, kind := range []bulkConfirmKind{confirmSubmit, confirmRemove} {
		ask, err := s.confirmBulk(context.Background(), kind, 100000, "")
		if err != nil || ask != nil {
			t.Errorf("%s with no threshold: got (%v, %v), want (nil, nil)", kind, ask, err)
		}
	}
}

// The threshold is a ceiling that is allowed, not one that trips: a site
// that says 50 means 50 is fine.
func TestThresholdIsInclusive(t *testing.T) {
	s := confirmServer(t, 50, 50)
	for _, count := range []int{1, 49, 50} {
		ask, err := s.confirmBulk(canAsk(nil, ""), confirmSubmit, count, "")
		if err != nil || ask != nil {
			t.Errorf("%d jobs under a threshold of 50: got (%v, %v), want (nil, nil)", count, ask, err)
		}
	}
	ask, err := s.confirmBulk(canAsk(nil, ""), confirmSubmit, 51, "")
	if err != nil {
		t.Fatalf("51 jobs: unexpected error %v", err)
	}
	if ask == nil {
		t.Fatal("51 jobs over a threshold of 50 did not ask")
	}
	if ask.Count != 51 {
		t.Errorf("asked about %d jobs, want 51", ask.Count)
	}
}

// Each setting gates its own tool. A site that wants a gate on removal
// and not on submission gets exactly that.
func TestThresholdsAreIndependent(t *testing.T) {
	s := confirmServer(t, 0, 50)

	ask, err := s.confirmBulk(canAsk(nil, ""), confirmSubmit, 5000, "")
	if err != nil || ask != nil {
		t.Errorf("submit is ungated here but was stopped: (%v, %v)", ask, err)
	}
	ask, err = s.confirmBulk(canAsk(nil, ""), confirmRemove, 51, "true")
	if err != nil {
		t.Fatalf("remove: unexpected error %v", err)
	}
	if ask == nil {
		t.Fatal("remove is gated at 50 but 51 jobs were not stopped")
	}
}

// THE failure this gate must not have. A client that cannot be asked is
// refused, never waved through: an operator who set a threshold and got
// no gate has a limit they believe in and do not have.
func TestClientThatCannotBeAskedIsRefused(t *testing.T) {
	s := confirmServer(t, 50, 50)

	// A bare context is what the built-in JSON-RPC transport provides:
	// it records nothing, because it cannot ask anyone.
	ask, err := s.confirmBulk(context.Background(), confirmRemove, 500, "true")
	if ask != nil {
		t.Fatal("a client that cannot be asked was handed a question it cannot present")
	}
	if err == nil {
		t.Fatal("a call over the threshold was allowed through a client that cannot be asked")
	}
	for _, want := range []string{"HTTP_API_MCP_CONFIRM_REMOVE_OVER", "50", "500", "nothing was done"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %s", want, err)
		}
	}
	// It must not teach the agent the workaround it is forbidding.
	if !strings.Contains(err.Error(), "Do not work around this by splitting") {
		t.Errorf("the refusal does not tell the agent against splitting the call: %s", err)
	}
}

// A client offering only URL elicitation cannot present a form, and is
// treated as a client that cannot be asked rather than being sent a
// request the spec says not to send it.
func TestCapabilityReading(t *testing.T) {
	form := &mcp.FormElicitationCapabilities{}
	url := &mcp.URLElicitationCapabilities{}
	for _, tc := range []struct {
		name   string
		caps   *mcp.ClientCapabilities
		wantOK bool
	}{
		{"no capabilities at all", nil, false},
		{"capabilities without elicitation", &mcp.ClientCapabilities{}, false},
		{"elicitation, unspecified kind", &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{}}, true},
		{"form elicitation", &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{Form: form}}, true},
		{"form and url", &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{Form: form, URL: url}}, true},
		{"url only", &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{URL: url}}, false},
	} {
		got := elicitSupportFromCapabilities(tc.caps)
		if got.OK != tc.wantOK {
			t.Errorf("%s: OK = %v, want %v", tc.name, got.OK, tc.wantOK)
		}
		if !got.OK && got.Why == "" {
			t.Errorf("%s: refused without saying why", tc.name)
		}
	}
}

// The second pass of the round trip: the person said yes, so the call
// goes through.
func TestApprovalLetsTheCallThrough(t *testing.T) {
	s := confirmServer(t, 50, 50)

	ask, err := s.confirmBulk(canAsk(nil, ""), confirmRemove, 500, "Owner == \"alice\"")
	if err != nil || ask == nil {
		t.Fatalf("first pass: got (%v, %v), want a question", ask, err)
	}

	ctx := canAsk(accepted(), ask.State)
	again, err := s.confirmBulk(ctx, confirmRemove, 500, "Owner == \"alice\"")
	if err != nil {
		t.Fatalf("after approval: %v", err)
	}
	if again != nil {
		t.Fatal("the person approved and the call was asked about again")
	}
}

// A "no" is a final answer, not a transient failure. The model is told
// so in as many words, because an agent that reads a refusal as a hiccup
// retries it.
func TestDeclineStopsTheCall(t *testing.T) {
	s := confirmServer(t, 50, 50)
	ask, _ := s.confirmBulk(canAsk(nil, ""), confirmRemove, 500, "true")

	for _, action := range []string{"decline", "cancel"} {
		answers := mcp.InputResponseMap{confirmRequestID: &mcp.ElicitResult{Action: action}}
		again, err := s.confirmBulk(canAsk(answers, ask.State), confirmRemove, 500, "true")
		if again != nil {
			t.Errorf("%s: asked again instead of stopping", action)
		}
		if err == nil {
			t.Fatalf("%s: the call went through", action)
		}
		if !strings.Contains(err.Error(), "nothing was") {
			t.Errorf("%s: the refusal does not say nothing happened: %s", action, err)
		}
	}
	declined := mcp.InputResponseMap{confirmRequestID: &mcp.ElicitResult{Action: "decline"}}
	_, err := s.confirmBulk(canAsk(declined, ask.State), confirmRemove, 500, "true")
	if !strings.Contains(err.Error(), "do not retry") {
		t.Errorf("a decline does not tell the model to stop: %s", err)
	}
}

// The queue moved under the question. An approval is for a number, and
// acting on a bigger set than the person saw is the whole risk this
// gate exists to manage -- so it asks again rather than proceeding.
func TestApprovalDoesNotCoverAGrownSet(t *testing.T) {
	s := confirmServer(t, 50, 50)
	ask, err := s.confirmBulk(canAsk(nil, ""), confirmRemove, 100, "true")
	if err != nil || ask == nil {
		t.Fatalf("first pass: got (%v, %v), want a question", ask, err)
	}

	// 40 more jobs matched between the question and the answer.
	ctx := canAsk(accepted(), ask.State)
	again, err := s.confirmBulk(ctx, confirmRemove, 140, "true")
	if err != nil {
		t.Fatalf("after the set grew: %v", err)
	}
	if again == nil {
		t.Fatal("an approval for 100 jobs was taken to cover 140")
	}
	if again.Count != 140 {
		t.Errorf("asked again about %d jobs, want 140", again.Count)
	}

	// A set that SHRANK is still covered: the person approved more than
	// is about to happen, and asking twice for less is just noise.
	fewer, err := s.confirmBulk(ctx, confirmRemove, 60, "true")
	if err != nil || fewer != nil {
		t.Errorf("a smaller set than was approved was asked about again: (%v, %v)", fewer, err)
	}
}

// An approval carrying no state cannot be tied to a number, so it is not
// an approval. Without this, a client echoing an empty requestState
// would turn every gated call into a one-round-trip formality.
func TestApprovalWithoutStateIsNotAnApproval(t *testing.T) {
	s := confirmServer(t, 50, 50)
	ask, err := s.confirmBulk(canAsk(accepted(), ""), confirmRemove, 500, "true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ask == nil {
		t.Fatal("an approval with no state was honoured")
	}
}

// An approval for the other operation does not carry over. The two
// thresholds are separate decisions and so are the two answers.
func TestApprovalDoesNotCrossOperations(t *testing.T) {
	s := confirmServer(t, 50, 50)
	ask, _ := s.confirmBulk(canAsk(nil, ""), confirmSubmit, 500, "")

	ctx := canAsk(accepted(), ask.State)
	again, err := s.confirmBulk(ctx, confirmRemove, 500, "true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if again == nil {
		t.Fatal("an approval to submit 500 jobs was taken as approval to remove 500")
	}
}

// What the person actually reads. It has to carry the number, say which
// way round the operation is, and say that an agent asked -- a dialog
// that says only "confirm?" is one people learn to click through.
func TestTheQuestionSaysWhatIsHappening(t *testing.T) {
	submit := confirmElicitParams(confirmSubmit, 500, "")
	if !strings.Contains(submit.Message, "500") || !strings.Contains(submit.Message, "Submit") {
		t.Errorf("the submit question does not say what it is: %q", submit.Message)
	}

	remove := confirmElicitParams(confirmRemove, 500, `Owner == "alice"`)
	for _, want := range []string{"500", "Remove", "cannot be undone", `Owner == "alice"`} {
		if !strings.Contains(remove.Message, want) {
			t.Errorf("the remove question does not mention %q: %q", want, remove.Message)
		}
	}
	for _, p := range []*mcp.ElicitParams{submit, remove} {
		if !strings.Contains(p.Message, "An agent asked for this") {
			t.Errorf("the question does not say an agent asked: %q", p.Message)
		}
		if p.Mode != "form" {
			t.Errorf("mode = %q, want form", p.Mode)
		}
	}
}

// SetConfirmThresholds is the reconfigure half. A negative value is off
// rather than a gate at a nonsense number.
func TestSetConfirmThresholds(t *testing.T) {
	s := confirmServer(t, 0, 0)

	s.SetConfirmThresholds(50, 100)
	if got := s.confirmThreshold(confirmSubmit); got != 50 {
		t.Errorf("submit threshold = %d, want 50", got)
	}
	if got := s.confirmThreshold(confirmRemove); got != 100 {
		t.Errorf("remove threshold = %d, want 100", got)
	}

	s.SetConfirmThresholds(-1, -1)
	if got := s.confirmThreshold(confirmSubmit); got != 0 {
		t.Errorf("a negative submit threshold became %d, want 0 (off)", got)
	}
	if got := s.confirmThreshold(confirmRemove); got != 0 {
		t.Errorf("a negative remove threshold became %d, want 0 (off)", got)
	}
}

// --- the gate as the tools actually reach it -------------------------

// submit_job is gated before it submits anything.
//
// It goes through handleCallTool, the path every transport shares, and
// needs no schedd: the point is that the gate stops the call BEFORE
// submitRemote, so a server with nowhere to submit to still refuses
// rather than failing to connect. A "connection refused" here would mean
// the gate ran too late.
func TestSubmitJobIsGatedBeforeItSubmits(t *testing.T) {
	s := confirmServer(t, 50, 0)
	params := []byte(`{"name":"submit_job","arguments":{"submit_file":"executable = /bin/sleep\ntransfer_executable = False\narguments = 60\nqueue 500\n"}}`)

	_, err := s.handleCallTool(context.Background(), params)
	if err == nil {
		t.Fatal("a 500-job submission went through a threshold of 50")
	}
	if !strings.Contains(err.Error(), "HTTP_API_MCP_CONFIRM_SUBMIT_OVER") {
		t.Fatalf("the call failed for some other reason than the gate: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("the refusal does not say how many jobs were asked for: %v", err)
	}
}

// And a submission under the threshold is NOT stopped by it. The call
// still fails -- there is no schedd -- but it has to fail having tried,
// which is what tells us the gate let it past rather than that the gate
// happens to be the only thing that can fail here.
func TestSubmitJobUnderTheThresholdReachesTheSchedd(t *testing.T) {
	s := confirmServer(t, 50, 0)
	params := []byte(`{"name":"submit_job","arguments":{"submit_file":"executable = /bin/sleep\ntransfer_executable = False\narguments = 60\nqueue 10\n"}}`)

	_, err := s.handleCallTool(context.Background(), params)
	if err == nil {
		t.Fatal("expected the submission to fail with no schedd to submit to")
	}
	if strings.Contains(err.Error(), "HTTP_API_MCP_CONFIRM_SUBMIT_OVER") {
		t.Fatalf("10 jobs were stopped by a threshold of 50: %v", err)
	}
}

// The count the gate uses is the jobs the file really asks for, not the
// number of `queue` statements. A queue over a list of 500 items is 500
// jobs and has to be counted as 500.
func TestTheCountIsJobsNotQueueStatements(t *testing.T) {
	s := confirmServer(t, 50, 0)
	var items strings.Builder
	for i := 0; i < 500; i++ {
		items.WriteString("item")
		items.WriteString(string(rune('A' + i%26)))
		items.WriteString(strings.Repeat("x", i%3))
		items.WriteString("\n")
	}
	submit := "executable = /bin/sleep\ntransfer_executable = False\narguments = $(name)\nqueue name from (\n" + items.String() + ")\n"
	params := []byte(`{"name":"submit_job","arguments":{"submit_file":` + jsonQuote(submit) + `}}`)

	_, err := s.handleCallTool(context.Background(), params)
	if err == nil || !strings.Contains(err.Error(), "HTTP_API_MCP_CONFIRM_SUBMIT_OVER") {
		t.Fatalf("a 500-item queue list was not counted as 500 jobs: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("the refusal does not say 500 jobs: %v", err)
	}
}

func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
