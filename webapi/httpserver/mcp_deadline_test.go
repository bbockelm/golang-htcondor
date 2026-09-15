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
			name: "derived from the default hard stop",
			cfg:  HandlerConfig{},
			want: DefaultMCPMaxRequestDuration - mcpWatchWaitMargin,
		},
		{
			name: "derived from a configured hard stop",
			cfg:  HandlerConfig{MCPMaxRequestDuration: 5 * time.Minute},
			want: 5*time.Minute - mcpWatchWaitMargin,
		},
		{
			// The operator knows the gateway; we do not.
			name: "an explicit setting always wins",
			cfg:  HandlerConfig{MCPWatchMaxWait: 15 * time.Second, MCPMaxRequestDuration: 5 * time.Minute},
			want: 15 * time.Second,
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
