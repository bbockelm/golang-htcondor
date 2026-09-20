package httpserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// postForDeadlineTest posts an empty body, carrying a context so the linter's
// noctx rule is satisfied and a hung server cannot wedge the test.
func postForDeadlineTest(t *testing.T, url string) (*http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}

func deadlineTestHandler(t *testing.T) *Handler {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return &Handler{logger: lg}
}

// TestProgressiveDeadlineOutlivesWriteTimeout is the behaviour the change
// exists for: a request that keeps running is not cut off by the server-wide
// write timeout, which is what forced watch_jobs to advertise a wait short
// enough to fit inside it.
func TestProgressiveDeadlineOutlivesWriteTimeout(t *testing.T) {
	h := deadlineTestHandler(t)
	h.mcpMaxRequest = time.Minute
	// A window far shorter than the work, so answering requires the
	// deadline to be moved repeatedly rather than once at the start.
	h.mcpWriteWindow = 300 * time.Millisecond

	const work = 2 * time.Second
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		ctx, stop := h.progressiveWriteDeadline(r.Context(), w)
		defer stop()
		select {
		case <-time.After(work):
		case <-ctx.Done():
			t.Errorf("the request was cancelled early: %v", ctx.Err())
		}
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"fired":true}}`)
	}))
	// Far shorter than the work: without extension this response dies.
	ts.Config.WriteTimeout = 300 * time.Millisecond
	ts.Start()
	defer ts.Close()

	start := time.Now()
	resp, err := postForDeadlineTest(t, ts.URL)
	if err != nil {
		t.Fatalf("the response was severed despite the extension: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	t.Logf("answered after %v under a %v write timeout: %s",
		time.Since(start).Round(100*time.Millisecond), ts.Config.WriteTimeout, body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestProgressiveDeadlineStopsAtTheHardStop: extension is not a way for a hung
// tool to hold a connection for as long as its bug lasts. The context is
// cancelled at the cap, so the tool gives up rather than being severed
// mid-write.
func TestProgressiveDeadlineStopsAtTheHardStop(t *testing.T) {
	h := deadlineTestHandler(t)
	h.mcpMaxRequest = 400 * time.Millisecond

	observed := make(chan error, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		ctx, stop := h.progressiveWriteDeadline(r.Context(), w)
		defer stop()
		select {
		case <-ctx.Done():
			observed <- ctx.Err()
		case <-time.After(10 * time.Second):
			observed <- nil
		}
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"deadline"}}`)
	}))
	defer ts.Close()

	start := time.Now()
	resp, err := postForDeadlineTest(t, ts.URL)
	if err == nil {
		_ = resp.Body.Close()
	}
	err = <-observed
	elapsed := time.Since(start)
	t.Logf("hard stop fired after %v: %v", elapsed.Round(100*time.Millisecond), err)
	if err == nil {
		t.Fatal("the request ran past the hard stop")
	}
	if elapsed > 3*time.Second {
		t.Errorf("the hard stop took %v, want about %v", elapsed, h.mcpMaxRequest)
	}
}

// TestProgressiveDeadlineWithoutDeadlineSupport: a ResponseWriter that cannot
// take a deadline must still yield a working, capped context rather than
// failing the request. The server-wide timeout then applies, as it did before.
func TestProgressiveDeadlineWithoutDeadlineSupport(t *testing.T) {
	h := deadlineTestHandler(t)
	h.mcpMaxRequest = time.Minute

	ctx, stop := h.progressiveWriteDeadline(context.Background(), httptest.NewRecorder())
	defer stop()

	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("no deadline on the returned context")
	}
	if d := time.Until(dl); d <= 0 || d > time.Minute+time.Second {
		t.Errorf("deadline is %v away, want about a minute", d)
	}
}

// TestWatchMaxWaitDerivation: what the agent is told it may wait for has to be
// what the transport will actually allow, and an operator who knows their
// gateway has to be able to say so.
func TestWatchMaxWaitDerivation(t *testing.T) {
	cases := []struct {
		name string
		cfg  HandlerConfig
		want time.Duration
	}{
		{
			// Not DefaultMCPMaxRequestDuration-mcpWatchWaitMargin: the
			// request deadline is not the binding constraint, the client's
			// own timeout is, and advertising 14m30s to an agent is what
			// made a 120s wait return nothing at all.
			name: "the default is what the client will wait for, not what we will run",
			cfg:  HandlerConfig{},
			want: DefaultDeliverableWatchWait,
		},
		{
			name: "a configured hard stop still does not raise it past deliverable",
			cfg:  HandlerConfig{MCPMaxRequestDuration: 5 * time.Minute},
			want: DefaultDeliverableWatchWait,
		},
		{
			// The tighter of the two wins, whichever it is.
			name: "a hard stop tighter than deliverable is the cap",
			cfg:  HandlerConfig{MCPMaxRequestDuration: 50 * time.Second},
			want: 20 * time.Second,
		},
		{
			// The operator knows the gateway; we do not.
			name: "an explicit setting always wins",
			cfg:  HandlerConfig{MCPWatchMaxWait: 15 * time.Second, MCPMaxRequestDuration: 5 * time.Minute},
			want: 15 * time.Second,
		},
		{
			// Including upwards: an operator whose clients are configured
			// for a long tool timeout is the only one who can know that.
			name: "an explicit setting above the deliverable ceiling wins too",
			cfg:  HandlerConfig{MCPWatchMaxWait: 10 * time.Minute},
			want: 10 * time.Minute,
		},
		{
			// Nothing sensible to derive: leave the mcpserver default.
			name: "a hard stop too small to derive from",
			cfg:  HandlerConfig{MCPMaxRequestDuration: 10 * time.Second},
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := watchMaxWait(tc.cfg); got != tc.want {
				t.Errorf("watchMaxWait = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDeliverableWatchWaitFitsAClientMinute pins the VALUE, not just the
// wiring.
//
// Everything else about the cap is derived, and this one number deliberately
// is not: it came from watching a live deployment, where a 45s and a 50s
// block arrived with their answer and a 120s one returned no payload at all.
// A test that only checks watchMaxWait returns DefaultDeliverableWatchWait
// keeps passing while the constant is raised back through the client's own
// timeout, which is exactly the regression the constant exists to prevent --
// so the band it has to sit in is asserted here.
func TestDeliverableWatchWaitFitsAClientMinute(t *testing.T) {
	// Reported around a minute, and varying by client, which is why the
	// headroom below is a floor rather than a rounding allowance.
	const observedClientTimeout = 60 * time.Second
	// The longest block measured to come back with its answer.
	const observedLongestDelivered = 50 * time.Second
	// Left for the evaluation pass that precedes the block and the reply
	// that follows it, neither of which is inside the wait.
	const minHeadroom = 10 * time.Second

	if DefaultDeliverableWatchWait <= 0 || DefaultDeliverableWatchWait > observedLongestDelivered {
		t.Fatalf("DefaultDeliverableWatchWait = %v, want a positive value no greater than the %v that was observed to arrive",
			DefaultDeliverableWatchWait, observedLongestDelivered)
	}
	if h := observedClientTimeout - DefaultDeliverableWatchWait; h < minHeadroom {
		t.Errorf("DefaultDeliverableWatchWait = %v leaves %v of a %v client timeout; want at least %v for the evaluation pass and the reply",
			DefaultDeliverableWatchWait, h, observedClientTimeout, minHeadroom)
	}
}
