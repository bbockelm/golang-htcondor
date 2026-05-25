package htcondor

// Multi-collector "happy eyeballs" failover.
//
// HTCondor accepts a comma-separated list of collector addresses
// (the OSPool ships its config that way, e.g.
//   COLLECTOR_HOST = cm-1.ospool.osg-htc.org,cm-2.ospool.osg-htc.org
// ). The C++ client implementation picks one at random and only
// fails over when an operation against that one *fails outright*,
// which on a hung TCP connect can mean a long stall.
//
// This package implements an RFC 8305-style staggered race:
//   t=0           start attempt against address[0]
//   t=stagger     start attempt against address[1] in parallel
//   t=2*stagger   start attempt against address[2] in parallel
//   …
//
// The first attempt to deliver an authenticated CEDAR client wins;
// the rest are cancelled and any clients that snuck in late are
// closed.
//
// This is one layer above the v4/v6 happy-eyeballs that Go's
// net.Dialer already performs internally for a single hostname.
// The two stack naturally: a 4-collector list with dual-stack
// hostnames will produce up to 8 concurrent connect attempts,
// each spaced by `stagger`, and the first authenticated socket
// wins. The cedar/client dialer needs FallbackDelay tuned for
// the v4/v6 piece — see the package README.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
)

// DefaultCollectorRaceStagger is the time between successive
// per-address connect attempts. 150 ms matches the inner v4/v6
// happy-eyeballs cadence the user-facing dialer should be running.
const DefaultCollectorRaceStagger = 150 * time.Millisecond

// splitCollectorList parses an HTCondor-style comma-separated
// COLLECTOR_HOST string. Whitespace around each entry is trimmed;
// empty entries are dropped.
//
// Bracket awareness: HTCondor sinful strings of the form
// "<host:port?key=val&key=val>" are opaque blobs we must not
// dissect. In practice the well-known sub-separators inside a
// sinful are "+" (between addrs) and space (between CCB
// contacts), not comma — but there's no formal guarantee a
// future attribute won't embed a comma, and mixing a bracketed
// sinful with a bare hostname inside one COLLECTOR_HOST line is
// fully expected. A simple strings.Split(",") would break in
// those cases.
//
// We therefore track angle-bracket depth and only treat a
// top-level comma (depth == 0) as a separator. Anything between
// matching "<" / ">" is preserved verbatim. Unbalanced brackets
// are tolerated by clamping depth at zero on the close side.
func splitCollectorList(s string) []string {
	if s == "" {
		return nil
	}
	var (
		out   []string
		cur   strings.Builder
		depth int
	)
	flush := func() {
		t := strings.TrimSpace(cur.String())
		if t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for _, r := range s {
		switch r {
		case '<':
			depth++
			cur.WriteRune(r)
		case '>':
			if depth > 0 {
				depth--
			}
			cur.WriteRune(r)
		case ',':
			if depth == 0 {
				flush()
				continue
			}
			cur.WriteRune(r)
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// raceCloseable is the minimal interface a racing helper needs:
// the ability to close a winning sibling that arrived too late.
// The cedar client satisfies it via its Close() method; the unit
// tests in collector_race_test.go satisfy it with a tiny stub.
type raceCloseable interface {
	Close() error
}

// raceResult is one attempt's outcome. The generic parameter is
// the resource being dialed — *client.HTCondorClient in production.
type raceResult[T raceCloseable] struct {
	val  T
	addr string
	err  error
	idx  int
}

// raceDial is the shared race body. It launches one `connect`
// goroutine per address staggered by `stagger`, returns the first
// successful result, cancels every other attempt's context, and
// closes any successes that arrive after the winner. When every
// attempt fails it returns errors.Join-ed errors.
//
// Each per-attempt goroutine is handed its own context derived
// from `parent`; cancelling that context is independent of the
// winner's so we can stop the losers without nuking the winner
// mid-handshake.
func raceDial[T raceCloseable](
	parent context.Context,
	addrs []string,
	stagger time.Duration,
	connect func(ctx context.Context, addr string) (T, error),
) (T, string, error) {
	var zero T
	if len(addrs) == 0 {
		return zero, "", fmt.Errorf("no collector addresses to dial")
	}

	cancels := make([]context.CancelFunc, len(addrs))
	attemptCtxs := make([]context.Context, len(addrs))
	for i := range addrs {
		// Bind cancel to a local var first so gosec G118 sees the
		// canonical "cancel := …; defer cancel()" pattern. We
		// still store the cancel in the slice so the loser-
		// cancellation loop below can fire it early — defer is
		// just the lifecycle backstop that guarantees no leak
		// regardless of whichever path we take out of raceDial.
		actx, cancel := context.WithCancel(parent)
		defer cancel()
		attemptCtxs[i] = actx
		cancels[i] = cancel
	}

	out := make(chan raceResult[T], len(addrs))
	var wg sync.WaitGroup
	wg.Add(len(addrs))
	for i, addr := range addrs {
		go func(i int, addr string, actx context.Context) {
			defer wg.Done()
			if i > 0 && stagger > 0 {
				t := time.NewTimer(time.Duration(i) * stagger)
				defer t.Stop()
				select {
				case <-actx.Done():
					out <- raceResult[T]{addr: addr, idx: i, err: actx.Err()}
					return
				case <-t.C:
				}
			}
			val, err := connect(actx, addr)
			out <- raceResult[T]{val: val, addr: addr, idx: i, err: err}
		}(i, addr, attemptCtxs[i])
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	winnerIdx := -1
	var errs []error
	for res := range out {
		if res.err == nil {
			if winnerIdx < 0 {
				winnerIdx = res.idx
				// Cancel every OTHER attempt so the losers stop
				// wasting time. Don't touch the winner's cancel
				// func — its context must stay live for whatever
				// follows (e.g., session resumption inside cedar).
				for i, cancel := range cancels {
					if i != winnerIdx {
						cancel()
					}
				}
				// Drain remaining results so per-goroutine writes
				// to `out` don't block. Close any late successes.
				go func() {
					for r := range out {
						if r.err == nil {
							_ = r.val.Close()
						}
					}
				}()
				return res.val, res.addr, nil
			}
			// Belt-and-suspenders: the drain goroutine handles
			// this, but if we ever reach here close the latecomer.
			_ = res.val.Close()
			continue
		}
		if winnerIdx >= 0 {
			// Cancellation noise from attempts we already shut down.
			continue
		}
		errs = append(errs, fmt.Errorf("%s: %w", res.addr, res.err))
	}
	if winnerIdx >= 0 {
		// Unreachable — the winner path returns above.
		return zero, "", nil
	}
	if len(errs) == 0 {
		return zero, "", fmt.Errorf("no collector addresses to dial")
	}
	return zero, "", fmt.Errorf("all %d collector addresses failed: %w",
		len(addrs), errors.Join(errs...))
}

// dialAndAuthenticate races authenticated connect attempts across
// every address the Collector knows about, returning the winning
// client. Each attempt gets its own derived context so cancelling
// the losers does not affect the winner. The winning address is
// recorded internally for sticky reordering on subsequent dials;
// callers that need the address for logging can read it back via
// the returned client's stream (`GetStream().PeerAddr()`).
//
// When the Collector has exactly one address the helper short-
// circuits straight to ConnectAndAuthenticate so the no-failover
// case pays no goroutine / channel overhead.
func (c *Collector) dialAndAuthenticate(ctx context.Context, cmd commands.CommandType) (*client.HTCondorClient, error) {
	// orderedAddrs applies the sticky-preferred reordering on top
	// of the shuffled construction order.
	addrs := c.orderedAddrs()
	if len(addrs) == 0 {
		// Fallback: c.addresses should be populated by NewCollector,
		// but a hand-built &Collector{address: "…"} could skip it.
		addrs = splitCollectorList(c.address)
		if len(addrs) == 0 {
			addrs = []string{c.address}
		}
	}

	// Single-address fast path — preserves the pre-multi-collector
	// behaviour and error shape for callers that never set up a list.
	if len(addrs) == 1 {
		addr := addrs[0]
		secConfig, err := GetSecurityConfigOrDefault(ctx, nil, int(cmd), "CLIENT", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to create security config: %w", err)
		}
		cl, err := client.ConnectAndAuthenticate(ctx, addr, secConfig)
		if err != nil {
			return nil, err
		}
		c.notePreferred(addr)
		return cl, nil
	}

	stagger := c.raceStagger
	if stagger <= 0 {
		stagger = DefaultCollectorRaceStagger
	}
	cl, winner, err := raceDial(ctx, addrs, stagger,
		func(actx context.Context, addr string) (*client.HTCondorClient, error) {
			secConfig, err := GetSecurityConfigOrDefault(actx, nil, int(cmd), "CLIENT", addr)
			if err != nil {
				return nil, fmt.Errorf("failed to create security config: %w", err)
			}
			return client.ConnectAndAuthenticate(actx, addr, secConfig)
		})
	if err != nil {
		return nil, err
	}
	// Mark the winning address as preferred so subsequent dials
	// from this Collector go to it first (the "sticky" half of the
	// failover policy).
	c.notePreferred(winner)
	return cl, nil
}
