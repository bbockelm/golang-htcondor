package dbmirror

import (
	"context"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	cedarclient "github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// Finding the database without the collector.
//
// Collector discovery is the pool-wide answer: it is how a daemon finds a
// database it was never told about, and the ad it returns carries the freshness
// the routing policy gates on. It also has a failure mode that looks like the
// database being gone when it is merely unadvertised -- the daemon cannot
// authorize its update, the collector is down, the ad has aged out -- and an
// htcondor-api sitting on the same host as the database it cannot find is a
// confusing thing for an operator to look at, particularly when every other
// htcondordb client on that host resolves it from the address file without
// trouble.
//
// So when the collector yields nothing, ask the database directly. The daemon
// answers the status command with the same ClassAd it advertises, which is what
// makes this a fallback rather than a second, weaker kind of discovery: the ad
// is parsed by the same ParseAd and produces the same Info, so every freshness
// gate downstream applies unchanged. What is lost is the pool-wide view -- a
// local lookup finds the local database or nothing.

// StatusCommand is htcondordb's DBSyncStatus CEDAR command
// (github.com/bbockelm/htcondordb/command.DBSyncStatus = 74005). Duplicated for
// the same reason as SessionCommand: htcondordb depends on this module, so
// importing it back would be a cycle.
const StatusCommand = 74005

// Subsystem is htcondordb's HTCondor subsystem name, which prefixes the knobs
// that name the daemon: HTCONDORDB_ADDRESS_FILE (default
// $(LOG)/.htcondordb_address) and HTCONDORDB_HOST. Using the same names as
// htcondordb's own locate package means an operator who redirects the daemon
// redirects everything that looks for it, this included.
const Subsystem = "HTCONDORDB"

// statusQuery runs the status exchange. A variable so tests can exercise
// discoverLocal's decisions without a daemon on the other end, the same seam
// collector.go uses for sendOneAd.
var statusQuery = (*Locator).queryStatus

// discoverLocal resolves the database from the local address file (or the
// operator's pinned address) and asks it for its status ad.
func (l *Locator) discoverLocal(ctx context.Context) (*Info, error) {
	addr, source, err := l.localAddress()
	if err != nil {
		return nil, err
	}

	ad, err := statusQuery(l, ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("asking the htcondordb daemon at %s (%s) for its status: %w", addr, source, err)
	}
	// ParseAd is best-effort by design -- it fills what it finds and never
	// reports a miss -- so check the ad is the right kind here. Otherwise a
	// reply from something else entirely parses into a zero Info that reads
	// as a database with no sync at all.
	if mt, _ := ad.EvaluateAttrString("MyType"); mt != AdType {
		return nil, fmt.Errorf("the daemon at %s returned a %q ad, not %s", addr, mt, AdType)
	}
	info := ParseAd(ad)

	// Targeting still applies. An operator who named a database meant that
	// one, and the fact that a different database happens to be running on
	// this host is not a reason to route reads to it.
	if l.opts.Name != "" && info.Name != l.opts.Name {
		return nil, fmt.Errorf("the htcondordb daemon at %s is named %q, not the configured %q", addr, info.Name, l.opts.Name)
	}

	// The ad's own Address is what it advertises to the collector, which is
	// not necessarily reachable from here -- that it was not is one reason
	// to be on this path at all. Dial what we resolved.
	info.Address = addr
	return info, nil
}

// localAddress returns the database's command address and a short description
// of where that came from, for the error an operator reads when it does not
// work.
func (l *Locator) localAddress() (addr string, source string, err error) {
	if l.opts.Address != "" {
		return l.opts.Address, "configured address", nil
	}
	resolve, src, err := htcondor.LocalDaemonAddress(l.cfg, Subsystem)
	if err != nil {
		return "", "", err
	}
	addr, err = resolve()
	if err != nil {
		return "", "", fmt.Errorf("reading the htcondordb address from %s: %w", src, err)
	}
	if strings.TrimSpace(addr) == "" {
		return "", "", fmt.Errorf("the htcondordb address at %s is empty", src)
	}
	return addr, src, nil
}

// queryStatus runs the status exchange: one request ClassAd, one reply. The
// reply is the ad the daemon advertises.
func (l *Locator) queryStatus(ctx context.Context, addr string) (*classad.ClassAd, error) {
	sec, err := l.securityConfigForCommand(ctx, addr, StatusCommand)
	if err != nil {
		return nil, err
	}

	cl, err := cedarclient.ConnectAndAuthenticate(ctx, addr, sec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cl.Close() }()

	s := cl.GetStream()
	out := message.NewMessageForStream(s)
	// The daemon ignores the body today; the exchange is request/response so
	// a selector can be added later without a new command number.
	req := classad.New()
	req.InsertAttrString("Action", "status")
	if err := out.PutClassAd(ctx, req); err != nil {
		return nil, err
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, err
	}

	ad, err := message.NewMessageFromStream(s).GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the status reply: %w", err)
	}
	if ok, present := ad.EvaluateAttrBool("Ok"); present && !ok {
		msg, _ := ad.EvaluateAttrString("Error")
		if msg == "" {
			msg = "the daemon refused the status request"
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return ad, nil
}
