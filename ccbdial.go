package htcondor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
)

// CCBReverseRouter hands out inbound paths for CCB connection reversal: a
// listener the execute node's connection back to us will arrive on, and the
// HTCondor sinful to advertise as the address it should dial.
//
// The implementation is an in-process shared-port router (see
// webapi/sharedportrouter), which multiplexes any number of concurrent
// reversals over one inbound TCP port. It is an interface here so the core
// library does not require one, and so tests can supply a trivial one.
type CCBReverseRouter interface {
	// Register claims one inbound path. The caller closes the listener when
	// the dial is done, which releases the registration.
	Register() (net.Listener, string, error)
}

// ccbMode is one way of reaching a daemon behind a CCB broker.
type ccbMode int

const (
	// ccbModeDefault is cedar's own behavior: open a private TCP socket and
	// have the target dial back to it. Used when this process has neither a
	// router nor permission to stream -- the same thing it did before either
	// existed.
	ccbModeDefault ccbMode = iota

	// ccbModeReverse has the target dial back to a route on our shared port.
	// Needs an inbound path; works with any broker, however old.
	ccbModeReverse

	// ccbModeStreaming has the broker relay both directions over the request
	// socket. Needs no inbound path; needs a broker from 25.13 or newer.
	ccbModeStreaming
)

func (m ccbMode) String() string {
	switch m {
	case ccbModeReverse:
		return "reverse-via-shared-port"
	case ccbModeStreaming:
		return "streaming"
	default:
		return "reverse-via-private-socket"
	}
}

// DefaultCCBLearnedTTL is how long a CCBDialer trusts what it learned about a
// broker. It is a compromise: long enough that a busy server is not
// re-measuring the same broker all day, short enough that a firewall change or
// a broker upgrade is picked up without a restart.
const DefaultCCBLearnedTTL = 15 * time.Minute

// CCBDialerConfig configures a CCBDialer.
type CCBDialerConfig struct {
	// Router, when set, gives this process an inbound path, which makes
	// connection reversal possible and is preferred over streaming: it works
	// with every broker version, while streaming does not, and the broker for
	// a given dial is chosen by the execute node.
	Router CCBReverseRouter

	// Streaming permits the broker-relayed mode. With no Router it is the only
	// thing that works from a host the execute nodes cannot reach; with one it
	// is the fallback for when they turn out not to reach us anyway.
	Streaming bool

	// LearnedTTL bounds how long what we learned about a broker is trusted
	// (default DefaultCCBLearnedTTL).
	LearnedTTL time.Duration

	// Logger receives one line per mode change. Defaults to slog.Default().
	Logger *slog.Logger
}

// CCBDialer reaches daemons behind a Condor Connection Broker, choosing
// between connection reversal and broker relaying, and remembering what
// worked.
//
// The choice cannot be made ahead of time. Which broker a dial goes through is
// decided by the execute node, in the sinful it advertised, so this process
// does not know until it holds the address -- and even then the two things
// that determine the answer are not things it can ask about. Whether the
// execute node can reach us is a fact about the network between two hosts that
// are not this one; whether the broker can relay is a fact about a version we
// only see once we have authenticated to it. So both are learned by trying,
// and the result is cached per broker so a server that has learned the answer
// does not pay for it on every exec.
//
// The zero value is not usable; call NewCCBDialer. A nil *CCBDialer is valid
// and dials exactly as DialSinful does with no CCB options -- the behavior of
// a caller that never configured any of this.
type CCBDialer struct {
	router    CCBReverseRouter
	streaming bool
	ttl       time.Duration
	log       *slog.Logger
	now       func() time.Time // overridden in tests

	mu      sync.Mutex
	learned map[string]*ccbBrokerState
}

// ccbBrokerState is what we learned about one broker, and when it goes stale.
type ccbBrokerState struct {
	// preferStreaming records that connection reversal was tried here and the
	// target never arrived, so the next dial should not pay that timeout again.
	preferStreaming bool

	// streamingUnsupported records that the broker is too old to relay, so the
	// next dial should not offer it a request it will mishandle.
	streamingUnsupported bool

	expires time.Time
}

// NewCCBDialer builds a CCBDialer from cfg.
func NewCCBDialer(cfg CCBDialerConfig) *CCBDialer {
	ttl := cfg.LearnedTTL
	if ttl <= 0 {
		ttl = DefaultCCBLearnedTTL
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &CCBDialer{
		router:    cfg.Router,
		streaming: cfg.Streaming,
		ttl:       ttl,
		log:       log,
		now:       time.Now,
		learned:   make(map[string]*ccbBrokerState),
	}
}

// HasRouter reports whether an inbound path is configured, for callers that
// log or report their configuration.
func (d *CCBDialer) HasRouter() bool { return d != nil && d.router != nil }

// Streaming reports whether broker relaying is permitted.
func (d *CCBDialer) Streaming() bool { return d != nil && d.streaming }

// ccbDialSinful is DialSinful, indirected so the mode CCBDialer selects -- and
// the fallback it performs -- can be observed without a live broker.
var ccbDialSinful = DialSinful

// Dial establishes an authenticated connection to address, choosing how to
// traverse CCB if the address needs it. Non-CCB addresses are dialed
// unchanged.
//
// opts supplies everything but the CCB mode (notably Timeout); the CCB fields
// on it are ignored, since choosing them is this method's job.
func (d *CCBDialer) Dial(ctx context.Context, address string, secConfig *security.SecurityConfig, opts *DialOptions) (*client.HTCondorClient, error) {
	base := DialOptions{}
	if opts != nil {
		base = *opts
	}
	base.CCBReturnAddr = ""
	base.CCBRequireStreaming = false
	base.CCBReverseListener = nil

	broker, isCCB := ccbBrokerKey(address)
	if d == nil || !isCCB {
		// Nothing to choose: either this caller configured no policy, or the
		// address names a daemon we reach directly.
		return ccbDialSinful(ctx, address, secConfig, &base)
	}

	plan := d.plan(broker)
	var errs []error
	for i, mode := range plan {
		attempt := base
		switch mode {
		case ccbModeReverse:
			attempt.CCBReverseListener = d.reverseListener()
		case ccbModeStreaming:
			attempt.CCBRequireStreaming = true
		}

		conn, err := ccbDialSinful(ctx, address, secConfig, &attempt)
		if err == nil {
			d.record(broker, mode, nil)
			if i > 0 {
				d.log.Info("reached a CCB daemon after falling back",
					"address", address, "broker", broker, "mode", mode.String())
			}
			return conn, nil
		}
		d.record(broker, mode, err)
		errs = append(errs, fmt.Errorf("%s: %w", mode, err))

		if i == len(plan)-1 || !fallbackWorthwhile(mode, err) {
			break
		}
		d.log.Warn("CCB dial failed; trying the other mode",
			"address", address, "broker", broker,
			"failed_mode", mode.String(), "next_mode", plan[i+1].String(), "error", err)
	}
	return nil, fmt.Errorf("failed to reach %s via CCB: %w", address, errors.Join(errs...))
}

// reverseListener builds the hook cedar calls to obtain this dial's inbound
// path. A fresh route per dial, because the id is what tells one caller's
// inbound connection from another's.
func (d *CCBDialer) reverseListener() ccb.ReverseListenerFunc {
	router := d.router
	return func() (net.Listener, string, error) {
		return router.Register()
	}
}

// plan returns the modes to try, in order.
func (d *CCBDialer) plan(broker string) []ccbMode {
	reverseOK := d.router != nil
	state := d.state(broker)
	streamingOK := d.streaming && (state == nil || !state.streamingUnsupported)

	switch {
	case reverseOK && streamingOK:
		if state != nil && state.preferStreaming {
			return []ccbMode{ccbModeStreaming, ccbModeReverse}
		}
		return []ccbMode{ccbModeReverse, ccbModeStreaming}
	case reverseOK:
		return []ccbMode{ccbModeReverse}
	case streamingOK:
		return []ccbMode{ccbModeStreaming}
	default:
		// No inbound path and no permission to stream. Cedar's own listener is
		// all that is left; on a host the execute nodes cannot reach it will
		// fail, but failing is better than silently doing nothing at all.
		return []ccbMode{ccbModeDefault}
	}
}

// fallbackWorthwhile reports whether the next mode has a chance after this
// error. The point is to not retry failures the other mode shares: bad
// credentials, an unreachable broker, a cancelled context.
func fallbackWorthwhile(mode ccbMode, err error) bool {
	switch mode {
	case ccbModeReverse, ccbModeDefault:
		// Only a target that could not reach us. A broker that rejected our
		// credentials or could not be dialed at all will reject a proxy
		// request the same way, and retrying buries the real reason.
		return errors.Is(err, ccb.ErrReverseConnect)
	case ccbModeStreaming:
		// Only a broker too old to relay. Everything else is shared.
		var unsupported *ccb.StreamingUnsupportedError
		return errors.As(err, &unsupported)
	}
	return false
}

// state returns the unexpired knowledge about broker, or nil.
func (d *CCBDialer) state(broker string) *ccbBrokerState {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.learned[broker]
	if !ok {
		return nil
	}
	if d.now().After(st.expires) {
		delete(d.learned, broker)
		return nil
	}
	cp := *st
	return &cp
}

// record folds the outcome of one attempt into what we know about broker.
func (d *CCBDialer) record(broker string, mode ccbMode, err error) {
	var (
		preferStreaming      bool
		streamingUnsupported bool
	)
	var unsupported *ccb.StreamingUnsupportedError
	switch {
	case mode == ccbModeStreaming && errors.As(err, &unsupported):
		// The broker cannot relay, so preferring streaming here would send
		// every future dial down a path that cannot work. Clear it.
		streamingUnsupported = true
	case mode == ccbModeStreaming && err == nil:
		preferStreaming = true // it worked; keep taking the short path
	case mode == ccbModeStreaming:
		return
	case err == nil:
		preferStreaming = false
	case errors.Is(err, ccb.ErrReverseConnect):
		preferStreaming = true
	default:
		return // says nothing about reachability
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	prev := d.learned[broker]
	next := &ccbBrokerState{
		preferStreaming:      preferStreaming,
		streamingUnsupported: streamingUnsupported,
		expires:              d.now().Add(d.ttl),
	}
	// A streaming outcome says nothing about reachability and vice versa, so
	// carry the other fact across rather than resetting it.
	if prev != nil && d.now().Before(prev.expires) {
		if mode == ccbModeStreaming {
			next.preferStreaming = preferStreaming || (prev.preferStreaming && !streamingUnsupported)
		} else {
			next.streamingUnsupported = prev.streamingUnsupported
		}
	}
	if prev == nil || prev.preferStreaming != next.preferStreaming || prev.streamingUnsupported != next.streamingUnsupported {
		d.log.Info("learned how to reach daemons behind a CCB broker",
			"broker", broker,
			"prefer_streaming", next.preferStreaming,
			"streaming_unsupported", next.streamingUnsupported,
			"valid_for", d.ttl.String())
	}
	d.learned[broker] = next
}

// ccbBrokerKey reduces a sinful to a stable key for the brokers it names, or
// reports that it names none.
//
// The key is the broker set, not the ccbid: what we learn -- whether execute
// nodes can reach us, whether the broker can relay -- is a property of the
// broker and the network around it, shared by every daemon registered with it.
// Keying on the target instead would relearn the same fact for every job.
func ccbBrokerKey(address string) (string, bool) {
	sinful, err := addresses.ParseSinful(address)
	if err != nil || !sinful.IsCCB() {
		return "", false
	}
	brokers := make([]string, 0, len(sinful.CCBContacts))
	for _, c := range sinful.CCBContacts {
		if c.BrokerAddr != "" {
			brokers = append(brokers, c.BrokerAddr)
		}
	}
	if len(brokers) == 0 {
		return "", false
	}
	sort.Strings(brokers)
	return strings.Join(brokers, ","), true
}
