package multiap

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// Two federation hubs, or more.
//
// A site runs two independent hubs, each fed from every spoke; their
// tables are deterministic functions of the spokes' data, so they
// converge without talking to each other. This server knows every hub
// discovery finds (or the operator names) and reads from ONE of them at
// a time -- the active hub -- failing over when it stops answering.
//
// One at a time, never mixed, because what a read concludes from a hub
// is only meaningful against that hub: a watch cursor is a position in
// one hub's change log, JobsSyncedAt and LastReset describe one hub's
// streams, and a job missing from one hub's jobs table says nothing
// about the other's. So a read is pinned to a hub when it starts (Pin)
// and every query it makes, and every freshness verdict it reports, is
// that hub's. A switch bumps the generation; a pin carries the
// generation it was taken in, so the job-watch evaluator and the jobs
// feed see a switch as a new origin and start over on the new hub.
//
// Selection is sticky. The active hub is kept while it answers and is
// not clearly worse. It is replaced when:
//
//   - it is unreachable: FailAfter federation_sources reads in a row
//     failed, or none succeeded within three refresh intervals. The
//     replacement is the reachable hub with the most fresh APs.
//   - another hub has reported at least SwitchMargin more fresh APs at
//     every refresh for SwitchAfter, and the last switch is at least
//     SwitchAfter old. A brief difference -- one hub's state pass
//     landing a second before the other's -- resets the clock.
//
// It never switches back merely because the old hub returned. With one
// hub there is nothing to select and nothing here changes what a read
// does.

// Selection defaults.
const (
	// DefaultHubSwitchAfter is how long another hub must have been
	// fresher before the active one is replaced.
	DefaultHubSwitchAfter = 2 * time.Minute
	// DefaultHubSwitchMargin is how many more fresh APs make another
	// hub fresher.
	DefaultHubSwitchMargin = 1
	// DefaultHubFailAfter is how many federation_sources reads in a row
	// must fail before the active hub counts as unreachable.
	DefaultHubFailAfter = 2
	// DefaultHubDiscoverInterval is how often the hub set is
	// re-discovered.
	DefaultHubDiscoverInterval = 30 * time.Second
	// DefaultHubDiscoveryGrace is how long a discovery that finds no hub
	// at all is taken for a collector that lost its ads (it restarted)
	// rather than for every hub gone: the last known set is kept.
	DefaultHubDiscoveryGrace = 5 * time.Minute
	// DefaultHubSettle is how long after a switch the new hub's copy of
	// every AP is reported settling rather than fresh: htcondordb's
	// default fresh threshold (60 s) and a margin.
	DefaultHubSettle = 90 * time.Second
)

// HubPolicy is how the active hub is chosen. Zero fields take the
// defaults.
type HubPolicy struct {
	SwitchAfter  time.Duration
	SwitchMargin int
	FailAfter    int
	// Settle is how long after a switch the new hub is not trusted to
	// hold everything the old one did (see Hub.Settling).
	Settle time.Duration
}

func (p HubPolicy) withDefaults() HubPolicy {
	if p.SwitchAfter <= 0 {
		p.SwitchAfter = DefaultHubSwitchAfter
	}
	if p.SwitchMargin <= 0 {
		p.SwitchMargin = DefaultHubSwitchMargin
	}
	if p.FailAfter <= 0 {
		p.FailAfter = DefaultHubFailAfter
	}
	if p.Settle <= 0 {
		p.Settle = DefaultHubSettle
	}
	return p
}

// HubSpec names one hub and how to dial it.
type HubSpec struct {
	Name    string
	Address string
	Dial    Dialer
}

// HubSwitch records a change of active hub.
type HubSwitch struct {
	From, To string
	// Reason is "unreachable", "fresher" or "initial".
	Reason     string
	Generation uint64
	At         time.Time
}

// HubOptions configures a hub set.
type HubOptions struct {
	// Interval is how often every hub's federation_sources is re-read;
	// zero is DefaultSourcesInterval.
	Interval time.Duration
	Policy   HubPolicy
	// Static are hubs named by configuration.
	Static []HubSpec
	// Discover, when set, lists the hubs to know about; it is called
	// every DiscoverInterval, and every refresh while no hub answers.
	Discover         func(ctx context.Context) ([]HubSpec, error)
	DiscoverInterval time.Duration
	// OnSwitch, when set, is told of every change of active hub.
	OnSwitch func(HubSwitch)
}

// Hub is the federation hubs this server reads from and the one it reads
// from now. See the comment above.
type Hub struct {
	interval         time.Duration
	discoverInterval time.Duration
	policy           HubPolicy
	discover         func(ctx context.Context) ([]HubSpec, error)
	onSwitch         func(HubSwitch)
	// now replaces the clock, for tests.
	now   func() time.Time
	kick  chan struct{}
	scope func(schedd string) bool

	mu         sync.RWMutex
	eps        []*HubEndpoint // sorted by name
	active     *HubEndpoint
	gen        uint64
	changed    chan struct{} // closed at the next switch
	switchedAt time.Time
	last       *HubSwitch
	// cand is the hub that has been fresher than the active one at every
	// refresh since candSince.
	cand      *HubEndpoint
	candSince time.Time

	discoverAt  time.Time
	discoverErr string
	// emptySince is when discovery started finding no hub at all.
	emptySince time.Time
}

// NewHub returns a Hub of one hub, dialed with dial. It is always the
// active one.
func NewHub(dial Dialer, interval time.Duration) *Hub {
	h := newHub(HubOptions{Interval: interval})
	ep := h.endpoint(HubSpec{Dial: dial})
	h.eps = []*HubEndpoint{ep}
	h.active = ep
	return h
}

// NewHubSet returns a Hub that selects among the hubs opts names or
// discovers. No hub is active until the first refresh has heard from
// one; until then reads go to the first by name.
func NewHubSet(opts HubOptions) *Hub {
	h := newHub(opts)
	h.setEndpoints(opts.Static)
	return h
}

func newHub(opts HubOptions) *Hub {
	if opts.Interval <= 0 {
		opts.Interval = DefaultSourcesInterval
	}
	if opts.DiscoverInterval <= 0 {
		opts.DiscoverInterval = DefaultHubDiscoverInterval
	}
	return &Hub{interval: opts.Interval, discoverInterval: opts.DiscoverInterval, policy: opts.Policy.withDefaults(),
		discover: opts.Discover, onSwitch: opts.OnSwitch, now: time.Now, kick: make(chan struct{}, 1),
		changed: make(chan struct{})}
}

func (h *Hub) clock() time.Time {
	if h == nil || h.now == nil {
		return time.Now()
	}
	return h.now()
}

// SetMembership limits the fresh-AP count selection ranks hubs on to
// the access points member accepts (the AP set). Call it before Run.
func (h *Hub) SetMembership(member func(schedd string) bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scope = member
}

func (h *Hub) isMember(schedd string) bool {
	if h == nil || h.scope == nil {
		return true
	}
	return h.scope(schedd)
}

func (h *Hub) endpoint(spec HubSpec) *HubEndpoint {
	return &HubEndpoint{owner: h, name: spec.Name, dial: spec.Dial, address: spec.Address}
}

// setEndpoints makes the hub set specs: new hubs are added, a known
// hub's address is updated, and a hub missing from specs is dropped --
// unless it is the active one, which is kept until selection replaces
// it, so a hub whose ad lapsed while it still answers is not abandoned
// mid-stream.
func (h *Hub) setEndpoints(specs []HubSpec) {
	h.mu.Lock()
	defer h.mu.Unlock()
	byName := map[string]*HubEndpoint{}
	for _, ep := range h.eps {
		byName[strings.ToLower(ep.name)] = ep
	}
	var out []*HubEndpoint
	seen := map[string]bool{}
	for _, spec := range specs {
		key := strings.ToLower(spec.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		if ep := byName[key]; ep != nil {
			ep.mu.Lock()
			if spec.Address != "" {
				ep.address = spec.Address
			}
			ep.mu.Unlock()
			out = append(out, ep)
			continue
		}
		out = append(out, h.endpoint(spec))
	}
	if h.active != nil && !seen[strings.ToLower(h.active.name)] {
		out = append(out, h.active)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	h.eps = out
	if h.cand != nil && !seen[strings.ToLower(h.cand.name)] {
		h.cand = nil
	}
}

// Active is the hub reads go to now: the selected one, or before any
// selection the first by name. Nil when no hub is known.
func (h *Hub) Active() *HubEndpoint {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.activeLocked()
}

func (h *Hub) activeLocked() *HubEndpoint {
	if h.active != nil {
		return h.active
	}
	if len(h.eps) > 0 {
		return h.eps[0]
	}
	return nil
}

// Several reports whether more than one hub is known: a watch's jobs
// may have been seen on another hub than the one read now.
func (h *Hub) Several() bool {
	if h == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.eps) > 1
}

// Generation counts changes of active hub.
func (h *Hub) Generation() uint64 {
	if h == nil {
		return 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.gen
}

// LastSwitch is the most recent change of active hub, or nil.
func (h *Hub) LastSwitch() *HubSwitch {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.last == nil {
		return nil
	}
	c := *h.last
	return &c
}

// --- pinning ------------------------------------------------------------

type hubPinKey struct{}

// hubPin is a read's hub: the endpoint, the generation it was taken in,
// and the channel the next switch closes.
type hubPin struct {
	hub     *Hub
	ep      *HubEndpoint
	gen     uint64
	changed <-chan struct{}
	// settling is the switch that made ep active, while it is younger
	// than the settle window; nil otherwise.
	settling *HubSwitch
}

// origin names a pin for the consumers that must start over on another
// hub: the hub and the generation, so leaving a hub and coming back is a
// new origin too.
func (p hubPin) origin() string { return fmt.Sprintf("%s/%d", p.ep.Name(), p.gen) }

// Pin returns ctx carrying the active hub, so every read made with it
// goes to that hub even if another becomes active meanwhile. A ctx
// already pinned to this Hub is returned unchanged.
func (h *Hub) Pin(ctx context.Context) context.Context {
	if h == nil {
		return ctx
	}
	if p, ok := ctx.Value(hubPinKey{}).(hubPin); ok && p.hub == h {
		return ctx
	}
	return context.WithValue(ctx, hubPinKey{}, h.pinNow())
}

func (h *Hub) pinNow() hubPin {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p := hubPin{hub: h, ep: h.activeLocked(), gen: h.gen, changed: h.changed}
	if sw := h.last; sw != nil && sw.Reason != "initial" && sw.Generation == h.gen &&
		h.clock().Sub(sw.At) < h.policy.Settle {
		c := *sw
		p.settling = &c
	}
	return p
}

// Settling reports whether the hub ctx is pinned to (else the active
// one) became active by a switch less than the settle window ago, and
// that switch. Until the window passes, the new hub's copy of an AP is
// not trusted to hold everything the old hub's did -- a job the caller
// saw there may not have reached it yet -- so its fresh APs are reported
// settling, a by-id miss is asked of the AP itself, and a bulk action
// does not skip an AP on its word. The first selection at startup is not
// a switch.
func (h *Hub) Settling(ctx context.Context) (HubSwitch, bool) {
	if h == nil {
		return HubSwitch{}, false
	}
	p := h.pinOf(ctx)
	if p.settling == nil {
		return HubSwitch{}, false
	}
	return *p.settling, true
}

// SettleUntil is when a switch's settle window ends.
func (h *Hub) SettleUntil(sw HubSwitch) time.Time { return sw.At.Add(h.policy.Settle) }

func (h *Hub) pinOf(ctx context.Context) hubPin {
	if p, ok := ctx.Value(hubPinKey{}).(hubPin); ok && p.hub == h {
		return p
	}
	return h.pinNow()
}

// For is the hub ctx is pinned to, else the active one.
func (h *Hub) For(ctx context.Context) *HubEndpoint {
	if h == nil {
		return nil
	}
	return h.pinOf(ctx).ep
}

// Origin names the hub ctx is pinned to (else the active one) and the
// generation of the pin: two reads with the same origin read the same
// hub with no switch between them.
func (h *Hub) Origin(ctx context.Context) string {
	if h == nil {
		return ""
	}
	return h.pinOf(ctx).origin()
}

// --- delegation to the active hub ---------------------------------------

// Client dials the active hub.
func (h *Hub) Client(ctx context.Context) (*dbrpc.Client, func(), error) {
	return h.For(ctx).Client(ctx)
}

// Status reports the active hub's reachability.
func (h *Hub) Status() HubStatus {
	ep := h.Active()
	if ep == nil && h != nil {
		st := HubStatus{LastError: "no federation hub has been found"}
		if e := h.DiscoveryError(); e != "" {
			st.LastError += ": " + e
		}
		return st
	}
	st := ep.Status()
	st.Active = ep != nil
	return st
}

// ReadSources reads the active hub's federation_sources now.
func (h *Hub) ReadSources(ctx context.Context) (map[string]Source, time.Time, error) {
	return h.For(ctx).ReadSources(ctx)
}

// Statuses reports every known hub, the active one marked, by name.
func (h *Hub) Statuses() []HubStatus {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	eps := append([]*HubEndpoint(nil), h.eps...)
	active := h.activeLocked()
	h.mu.RUnlock()
	out := make([]HubStatus, 0, len(eps))
	for _, ep := range eps {
		st := ep.Status()
		st.Active = ep == active
		out = append(out, st)
	}
	return out
}

// AnyReachable reports whether some known hub answers.
func (h *Hub) AnyReachable() bool {
	for _, st := range h.Statuses() {
		if st.Reachable {
			return true
		}
	}
	return false
}

// DiscoveryError is why the last discovery failed, empty when it did not.
func (h *Hub) DiscoveryError() string {
	if h == nil {
		return ""
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.discoverErr
}

// --- refresh and selection ----------------------------------------------

// Refresh re-reads every hub's federation_sources, then selects the
// active hub. It returns the active hub's error, if any.
func (h *Hub) Refresh(ctx context.Context) error {
	if h == nil {
		return fmt.Errorf("no federation hub is configured")
	}
	h.mu.RLock()
	eps := append([]*HubEndpoint(nil), h.eps...)
	h.mu.RUnlock()
	if len(eps) == 0 {
		return fmt.Errorf("no federation hub has been found")
	}
	errs := make([]error, len(eps))
	var wg sync.WaitGroup
	for i, ep := range eps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = ep.refresh(ctx)
		}()
	}
	wg.Wait()
	h.selectActive()
	active := h.Active()
	for i, ep := range eps {
		if ep == active {
			return errs[i]
		}
	}
	return nil
}

// Discover re-reads the hub set from Options.Discover.
func (h *Hub) Discover(ctx context.Context) error {
	if h == nil || h.discover == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	specs, err := h.discover(ctx)
	h.mu.Lock()
	h.discoverAt = h.clock()
	if err != nil {
		h.discoverErr = err.Error()
		h.mu.Unlock()
		return err
	}
	h.discoverErr = ""
	if len(specs) == 0 && len(h.eps) > 0 {
		// A collector that restarted answers with no ads until the hubs
		// advertise again; that is no reason to forget the standbys.
		if h.emptySince.IsZero() {
			h.emptySince = h.discoverAt
		}
		if h.discoverAt.Sub(h.emptySince) < DefaultHubDiscoveryGrace {
			h.discoverErr = "the collector lists no federation hub; keeping the hubs it last listed"
			h.mu.Unlock()
			return nil
		}
	} else {
		h.emptySince = time.Time{}
	}
	h.mu.Unlock()
	h.setEndpoints(specs)
	return nil
}

// usable reports whether ep can be the active hub.
func (h *Hub) usableLocked(ep *HubEndpoint) bool {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.failures < h.policy.FailAfter && ep.readFailures < h.policy.FailAfter && ep.reachableLocked()
}

func (h *Hub) freshOf(ep *HubEndpoint) int {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.freshLocked(h.isMember)
}

// selectActive applies the selection policy once.
func (h *Hub) selectActive() {
	h.mu.Lock()
	sw := h.selectLocked(h.clock())
	h.mu.Unlock()
	if sw != nil && h.onSwitch != nil {
		h.onSwitch(*sw)
	}
}

func (h *Hub) selectLocked(now time.Time) *HubSwitch {
	if len(h.eps) < 2 && h.active != nil {
		return nil
	}
	// The best usable hub other than the active one: most fresh APs,
	// ties to the first by name.
	var best *HubEndpoint
	bestFresh := -1
	for _, ep := range h.eps {
		if ep == h.active || !h.usableLocked(ep) {
			continue
		}
		if f := h.freshOf(ep); f > bestFresh {
			best, bestFresh = ep, f
		}
	}
	switch {
	case h.active == nil:
		if best == nil {
			return nil
		}
		return h.switchLocked(best, "initial", now)
	case !h.usableLocked(h.active):
		h.cand = nil
		if best == nil {
			return nil
		}
		return h.switchLocked(best, "unreachable", now)
	}
	if best == nil || bestFresh < h.freshOf(h.active)+h.policy.SwitchMargin {
		h.cand = nil
		return nil
	}
	if h.cand != best {
		h.cand, h.candSince = best, now
		return nil
	}
	if now.Sub(h.candSince) < h.policy.SwitchAfter || now.Sub(h.switchedAt) < h.policy.SwitchAfter {
		return nil
	}
	return h.switchLocked(best, "fresher", now)
}

func (h *Hub) switchLocked(to *HubEndpoint, reason string, now time.Time) *HubSwitch {
	from := h.activeLocked()
	h.active, h.cand = to, nil
	if from != nil && from != to {
		// Its failed reads were reads as the active hub; as a standby it
		// is judged by its sources reads until it is read from again.
		from.mu.Lock()
		from.readFailures = 0
		from.mu.Unlock()
	}
	if from == to {
		// The first selection kept the hub reads were already going to.
		return nil
	}
	h.gen++
	close(h.changed)
	h.changed = make(chan struct{})
	h.switchedAt = now
	h.last = &HubSwitch{From: from.Name(), To: to.Name(), Reason: reason, Generation: h.gen, At: now}
	c := *h.last
	return &c
}

// kickRefresh asks Run for an early refresh: a read could not dial the
// active hub. Run honours it at most once per half refresh interval.
func (h *Hub) kickRefresh() {
	if h == nil {
		return
	}
	select {
	case h.kick <- struct{}{}:
	default:
	}
}

// Run discovers and refreshes until ctx is done, starting immediately.
// onResult sees each refresh's outcome for the active hub.
func (h *Hub) Run(ctx context.Context, onResult func(error)) {
	poll := func() {
		h.mu.RLock()
		since := h.clock().Sub(h.discoverAt)
		h.mu.RUnlock()
		// While nothing answers, look for hubs at every refresh interval
		// rather than every discovery interval.
		due := h.discover != nil && (since >= h.discoverInterval || (since >= h.interval && !h.AnyReachable()))
		if due {
			_ = h.Discover(ctx)
		}
		err := h.Refresh(ctx)
		if onResult != nil {
			onResult(err)
		}
	}
	poll()
	t := time.NewTicker(h.interval)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-h.kick:
			if time.Since(last) < h.interval/2 {
				continue
			}
		}
		last = time.Now()
		poll()
	}
}
