package htcondor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
)

// quietTestLogger keeps the dialer's mode-change lines out of test output.
func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ccbTestAddr is a sinful naming one broker, so dials through it are CCB dials.
const ccbTestAddr = "<10.0.0.1:9618?CCBID=192.0.2.1:9618%2342>"

// ccbTestAddrOtherBroker names a different broker, for checking that what is
// learned about one is not applied to the other.
const ccbTestAddrOtherBroker = "<10.0.0.2:9618?CCBID=192.0.2.9:9618%2377>"

// fakeRouter is a CCBReverseRouter that hands out a closed-on-demand listener
// and counts registrations.
type fakeRouter struct {
	registrations int
	lns           []net.Listener
}

func (f *fakeRouter) Register() (net.Listener, string, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	f.lns = append(f.lns, ln)
	f.registrations++
	return ln, fmt.Sprintf("<10.9.9.9:9618?sock=fake-%d>", f.registrations), nil
}

func (f *fakeRouter) closeAll() {
	for _, ln := range f.lns {
		_ = ln.Close()
	}
}

// attempt records one dial the policy made.
type attempt struct {
	address   string
	streaming bool
	reverse   bool
}

// interceptDials replaces the dial seam with one that records what was asked
// for and returns scripted results, and restores it when the test ends.
func interceptDials(t *testing.T, results ...error) *[]attempt {
	t.Helper()
	var seen []attempt
	restore := ccbDialSinful
	i := 0
	ccbDialSinful = func(_ context.Context, addr string, _ *security.SecurityConfig, opts *DialOptions) (*client.HTCondorClient, error) {
		seen = append(seen, attempt{
			address:   addr,
			streaming: opts != nil && opts.CCBRequireStreaming,
			reverse:   opts != nil && opts.CCBReverseListener != nil,
		})
		// Stand in for cedar: a standard-mode dial calls the hook to get its
		// inbound path, and closes it when the dial ends. Without doing that
		// here, a hook that could not produce a listener would go unnoticed.
		if opts != nil && opts.CCBReverseListener != nil {
			ln, advertised, lerr := opts.CCBReverseListener()
			if lerr != nil {
				return nil, fmt.Errorf("reverse listener: %w", lerr)
			}
			if advertised == "" {
				return nil, errors.New("reverse listener advertised no address")
			}
			_ = ln.Close()
		}
		var err error
		if i < len(results) {
			err = results[i]
		}
		i++
		if err != nil {
			return nil, err
		}
		// A nil client with a nil error is fine: nothing here dereferences it.
		return nil, nil
	}
	t.Cleanup(func() { ccbDialSinful = restore })
	return &seen
}

func newTestDialer(router CCBReverseRouter, streaming bool) *CCBDialer {
	return NewCCBDialer(CCBDialerConfig{
		Router:    router,
		Streaming: streaming,
		Logger:    quietTestLogger(),
	})
}

// TestCCBDialerPrefersTheSharedPortOverStreaming pins the ordering the whole
// feature turns on. Streaming needs a broker from 25.13, and the broker is
// chosen by the execute node, so the mode that works with every broker has to
// be the one tried first.
func TestCCBDialerPrefersTheSharedPortOverStreaming(t *testing.T) {
	router := &fakeRouter{}
	defer router.closeAll()
	seen := interceptDials(t, nil)

	d := newTestDialer(router, true)
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if len(*seen) != 1 {
		t.Fatalf("made %d dials, want 1: %+v", len(*seen), *seen)
	}
	if !(*seen)[0].reverse || (*seen)[0].streaming {
		t.Errorf("first attempt was %+v, want reverse-connect through the router", (*seen)[0])
	}
	if router.registrations != 1 {
		t.Errorf("router registrations = %d, want 1", router.registrations)
	}
}

// TestCCBDialerFallsBackToStreaming covers the case the user hit from the
// other side: the shared port is open but the execute node still cannot reach
// it, so the broker must relay instead.
func TestCCBDialerFallsBackToStreaming(t *testing.T) {
	router := &fakeRouter{}
	defer router.closeAll()
	seen := interceptDials(t, fmt.Errorf("dial: %w", ccb.ErrReverseConnect), nil)

	d := newTestDialer(router, true)
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if len(*seen) != 2 {
		t.Fatalf("made %d dials, want 2 (reverse then streaming): %+v", len(*seen), *seen)
	}
	if !(*seen)[0].reverse {
		t.Errorf("first attempt = %+v, want reverse", (*seen)[0])
	}
	if !(*seen)[1].streaming || (*seen)[1].reverse {
		t.Errorf("second attempt = %+v, want streaming", (*seen)[1])
	}
}

// TestCCBDialerRemembersThatStreamingIsNeeded is the caching the whole point
// of which is not paying the reverse-connect timeout on every exec. The
// broker is picked by the execute node, so this cannot be probed ahead of
// time -- it is learned from the first failure and then reused.
func TestCCBDialerRemembersThatStreamingIsNeeded(t *testing.T) {
	router := &fakeRouter{}
	defer router.closeAll()
	seen := interceptDials(t,
		fmt.Errorf("dial: %w", ccb.ErrReverseConnect), // first: reverse fails
		nil, // first: streaming works
		nil, // second dial: should go straight to streaming
	)

	d := newTestDialer(router, true)
	for i := 0; i < 2; i++ {
		if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
			t.Fatalf("Dial %d: %v", i, err)
		}
	}

	if len(*seen) != 3 {
		t.Fatalf("made %d dials, want 3 (reverse, streaming, streaming): %+v", len(*seen), *seen)
	}
	if !(*seen)[2].streaming || (*seen)[2].reverse {
		t.Errorf("the second dial was %+v; the failed reverse-connect was not remembered, "+
			"so every exec pays that timeout again", (*seen)[2])
	}
}

// What is learned is about one broker, not about CCB in general: a pool can
// run several, and one unreachable EP network says nothing about another.
func TestCCBDialerLearnsPerBroker(t *testing.T) {
	router := &fakeRouter{}
	defer router.closeAll()
	seen := interceptDials(t,
		fmt.Errorf("dial: %w", ccb.ErrReverseConnect), // broker A: reverse fails
		nil, // broker A: streaming works
		nil, // broker B: reverse should still be tried first
	)

	d := newTestDialer(router, true)
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
		t.Fatalf("Dial A: %v", err)
	}
	if _, err := d.Dial(context.Background(), ccbTestAddrOtherBroker, nil, nil); err != nil {
		t.Fatalf("Dial B: %v", err)
	}

	if len(*seen) != 3 {
		t.Fatalf("made %d dials, want 3: %+v", len(*seen), *seen)
	}
	if !(*seen)[2].reverse {
		t.Errorf("the dial to the second broker was %+v; what was learned about one broker "+
			"must not decide for another", (*seen)[2])
	}
}

// TestCCBDialerForgetsAfterTTL: a firewall change or a broker upgrade should
// be picked up without restarting the server.
func TestCCBDialerForgetsAfterTTL(t *testing.T) {
	router := &fakeRouter{}
	defer router.closeAll()
	seen := interceptDials(t,
		fmt.Errorf("dial: %w", ccb.ErrReverseConnect),
		nil,
		nil,
	)

	now := time.Now()
	d := NewCCBDialer(CCBDialerConfig{
		Router: router, Streaming: true, LearnedTTL: time.Minute, Logger: quietTestLogger(),
	})
	d.now = func() time.Time { return now }

	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	now = now.Add(2 * time.Minute) // the lesson has expired
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
		t.Fatalf("Dial after TTL: %v", err)
	}

	if len(*seen) != 3 {
		t.Fatalf("made %d dials, want 3: %+v", len(*seen), *seen)
	}
	if !(*seen)[2].reverse {
		t.Errorf("after the TTL the dial was %+v; a stale lesson is never revisited", (*seen)[2])
	}
}

// TestCCBDialerStopsOfferingStreamingToAnOldBroker is the mirror case: a
// broker too old to relay must not be asked again, or every dial to it pays a
// pointless second round trip on top of the one that already failed.
func TestCCBDialerStopsOfferingStreamingToAnOldBroker(t *testing.T) {
	router := &fakeRouter{}
	defer router.closeAll()
	seen := interceptDials(t,
		fmt.Errorf("dial: %w", ccb.ErrReverseConnect),            // reverse fails
		&ccb.StreamingUnsupportedError{Broker: "192.0.2.1:9618"}, // and the broker cannot relay
		nil, // next dial: reverse, and this time it works
	)

	d := newTestDialer(router, true)
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err == nil {
		t.Fatal("expected the dial to fail when neither mode works")
	}
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
		t.Fatalf("second Dial: %v", err)
	}

	if len(*seen) != 3 {
		t.Fatalf("made %d dials, want 3 (reverse, streaming, reverse): %+v", len(*seen), *seen)
	}
	if !(*seen)[2].reverse || (*seen)[2].streaming {
		t.Errorf("the second dial was %+v; a broker known not to support streaming "+
			"should not be offered it again", (*seen)[2])
	}
}

// A failure that is not about reachability must not be retried in the other
// mode: streaming authenticates to the same broker with the same credential,
// so retrying only buries the reason in a second error.
func TestCCBDialerDoesNotRetryNonReachabilityFailures(t *testing.T) {
	router := &fakeRouter{}
	defer router.closeAll()
	authErr := errors.New("ccb: authenticating to broker 192.0.2.1:9618: AUTH_PW_ERROR")
	seen := interceptDials(t, authErr, nil)

	d := newTestDialer(router, true)
	_, err := d.Dial(context.Background(), ccbTestAddr, nil, nil)
	if err == nil {
		t.Fatal("expected the dial to fail")
	}
	if !errors.Is(err, authErr) {
		t.Errorf("error = %v, want it to carry the broker's rejection", err)
	}
	if len(*seen) != 1 {
		t.Errorf("made %d dials, want 1: a broker that rejected our credentials will reject them again: %+v",
			len(*seen), *seen)
	}
}

// With no router configured the dialer behaves exactly as the streaming-only
// setting did before it existed.
func TestCCBDialerWithoutRouterStreamsOnly(t *testing.T) {
	seen := interceptDials(t, nil)
	d := newTestDialer(nil, true)
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if len(*seen) != 1 || !(*seen)[0].streaming || (*seen)[0].reverse {
		t.Errorf("attempts = %+v, want a single streaming dial", *seen)
	}
}

// And with neither, it is cedar's own behavior -- what a tool on a pool host
// has always done.
func TestCCBDialerWithNothingConfiguredIsTheCedarDefault(t *testing.T) {
	seen := interceptDials(t, nil)
	d := newTestDialer(nil, false)
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if len(*seen) != 1 || (*seen)[0].streaming || (*seen)[0].reverse {
		t.Errorf("attempts = %+v, want one dial with no CCB options set", *seen)
	}
}

// A nil dialer is a valid caller (a tool that configured none of this) and
// must not panic or add CCB options of its own.
func TestNilCCBDialerDialsPlainly(t *testing.T) {
	seen := interceptDials(t, nil)
	var d *CCBDialer
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, nil); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if len(*seen) != 1 || (*seen)[0].streaming || (*seen)[0].reverse {
		t.Errorf("attempts = %+v, want one plain dial", *seen)
	}
	if d.HasRouter() || d.Streaming() {
		t.Error("a nil dialer should report no router and no streaming")
	}
}

// A non-CCB address must not be routed through any of this, and in particular
// must not consume a router registration.
func TestCCBDialerLeavesDirectAddressesAlone(t *testing.T) {
	router := &fakeRouter{}
	defer router.closeAll()
	seen := interceptDials(t, nil)

	d := newTestDialer(router, true)
	if _, err := d.Dial(context.Background(), "<10.0.0.1:9618>", nil, nil); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if len(*seen) != 1 || (*seen)[0].streaming || (*seen)[0].reverse {
		t.Errorf("attempts = %+v, want one plain dial", *seen)
	}
	if router.registrations != 0 {
		t.Errorf("router registrations = %d, want 0 for a direct address", router.registrations)
	}
}

// Caller options other than the CCB ones have to survive, since the dialer
// owns only the mode.
func TestCCBDialerPreservesCallerOptions(t *testing.T) {
	var gotTimeout time.Duration
	restore := ccbDialSinful
	ccbDialSinful = func(_ context.Context, _ string, _ *security.SecurityConfig, opts *DialOptions) (*client.HTCondorClient, error) {
		gotTimeout = opts.Timeout
		return nil, nil
	}
	defer func() { ccbDialSinful = restore }()

	d := newTestDialer(nil, true)
	if _, err := d.Dial(context.Background(), ccbTestAddr, nil, &DialOptions{Timeout: 7 * time.Second}); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if gotTimeout != 7*time.Second {
		t.Errorf("Timeout = %v, want the caller's 7s", gotTimeout)
	}
}

func TestCCBBrokerKey(t *testing.T) {
	cases := []struct {
		name    string
		address string
		want    string
		isCCB   bool
	}{
		{"direct", "<10.0.0.1:9618>", "", false},
		{"shared port only", "<10.0.0.1:9618?sock=schedd>", "", false},
		{"one broker", ccbTestAddr, "192.0.2.1:9618", true},
		{"garbage", "not-a-sinful", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, isCCB := ccbBrokerKey(tc.address)
			if isCCB != tc.isCCB {
				t.Fatalf("isCCB = %v, want %v", isCCB, tc.isCCB)
			}
			if got != tc.want {
				t.Errorf("key = %q, want %q", got, tc.want)
			}
		})
	}
}

// The key must not depend on the order brokers are listed in, or a pool with
// several would relearn the same fact per permutation.
func TestCCBBrokerKeyIsOrderIndependent(t *testing.T) {
	a, okA := ccbBrokerKey("<10.0.0.1:9618?CCBID=192.0.2.1:9618%2342%20192.0.2.2:9618%2343>")
	b, okB := ccbBrokerKey("<10.0.0.1:9618?CCBID=192.0.2.2:9618%2343%20192.0.2.1:9618%2342>")
	if !okA || !okB {
		t.Fatalf("expected both to parse as CCB (%v, %v)", okA, okB)
	}
	if a != b {
		t.Errorf("keys differ by broker order: %q vs %q", a, b)
	}
}
