package reservation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/startd"
)

// PoolActuator applies a plan to real execute points.
//
// Every command rides the administrative capability the execute point
// publishes to the collector. That puts the authorization in one place
// -- the collector, where the capability is only handed to a client
// with ADMINISTRATOR -- and asks nothing of each execute point's own
// configuration, which is the difference between a pool an operator can
// turn this on for and one they would have to reconfigure node by node.
//
// The capability is a bearer credential with a half-hour life, re-minted
// on every collector update. It is therefore read fresh rather than
// held: the actuator re-reads the pool on an interval, and once more
// when a command comes back denied, since a capability that expired
// between the read and the push looks exactly like lost authorization.
type PoolActuator struct {
	// Query reads the pool. It must be able to ask for private
	// attributes, and the identity it reads as must hold ADMINISTRATOR
	// at the collector, or no capability comes back.
	Query SlotQuerier
	// Only is the site expression naming the execute points
	// reservations may draw seats from, exactly as the census uses it.
	Only string
	// Refresh is how often capabilities are re-read. Zero means
	// DefaultCapabilityRefresh. It has to stay comfortably inside the
	// half hour a capability lives.
	Refresh time.Duration
	// RequireCapability refuses to fall back to this process's own
	// credentials. The fallback works only on a pool whose execute
	// points authorize this access point directly, and leaving it on
	// means a pool that stopped publishing capabilities degrades to
	// refusing every command instead of saying what changed.
	RequireCapability bool
	// Graceful vacates a claim by retiring it, which lets a job take
	// its soft-kill signal and checkpoint if it can. False kills it.
	Graceful bool
	// Now is overridable for tests; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	admins  map[string]*startd.Admin
	readAt  time.Time
	cache   *startd.AdminOptions
	lastErr error
}

// DefaultCapabilityRefresh is how often the pool is re-read for
// capabilities. A capability lives half an hour; this leaves room for a
// read to fail twice and still be replaced before the one in hand
// expires.
const DefaultCapabilityRefresh = 8 * time.Minute

// capabilityProjection is what the actuator reads. It is deliberately
// not SlotProjection: this query carries bearer credentials and should
// carry as little else as it can.
var capabilityProjection = []string{
	"Name", "Machine", "MyAddress", "PartitionableSlot", startd.AdminCapabilityAttr,
}

var _ Actuator = (*PoolActuator)(nil)
var _ Provisioner = (*PoolActuator)(nil)

func (a *PoolActuator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *PoolActuator) refresh() time.Duration {
	if a.Refresh > 0 {
		return a.Refresh
	}
	return DefaultCapabilityRefresh
}

// Refreshed is when the capabilities in hand were read, and how many
// execute points answered with one. The admin page uses it: a pool that
// has stopped publishing capabilities is a configuration change nobody
// made on purpose, and the controller goes on planning correctly while
// changing nothing.
func (a *PoolActuator) Refreshed() (at time.Time, machines int, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.readAt, len(a.admins), a.lastErr
}

// admin finds the execute point that owns a machine, re-reading the
// pool when what is in hand is stale.
func (a *PoolActuator) admin(ctx context.Context, machine string) (*startd.Admin, error) {
	a.mu.Lock()
	stale := a.admins == nil || a.now().Sub(a.readAt) >= a.refresh()
	if !stale {
		if ad, ok := a.admins[machine]; ok {
			a.mu.Unlock()
			return ad, nil
		}
	}
	a.mu.Unlock()

	if err := a.reload(ctx); err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if ad, ok := a.admins[machine]; ok {
		return ad, nil
	}
	return nil, fmt.Errorf("no execute point answered for machine %s", machine)
}

// reload re-reads every permissible execute point's address and
// capability.
//
// One query for the whole pool rather than one per machine: a controller
// holding dozens of machines would otherwise ask the collector dozens of
// times a tick for ads it already has.
func (a *PoolActuator) reload(ctx context.Context) error {
	ads, _, err := a.Query.QueryAdsWithOptions(ctx, "StartdAd", censusConstraint(a.Only), &htcondor.QueryOptions{
		Limit:             slotLimit,
		Projection:        capabilityProjection,
		PrivateAttributes: true,
	})
	if err != nil {
		a.mu.Lock()
		a.lastErr = err
		a.mu.Unlock()
		return fmt.Errorf("reading execute points: %w", err)
	}

	admins := map[string]*startd.Admin{}
	opts := a.adminOptions()
	var errs []error
	for _, ad := range ads {
		if ad == nil {
			continue
		}
		machine, _ := ad.EvaluateAttrString("Machine")
		if machine == "" || admins[machine] != nil {
			continue
		}
		admin, err := startd.NewAdminFromAd(ad, a.RequireCapability, opts)
		if err != nil {
			// One execute point that will not answer is not a reason to
			// leave the rest unheld.
			errs = append(errs, fmt.Errorf("%s: %w", machine, err))
			continue
		}
		admins[machine] = admin
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.admins, a.readAt, a.lastErr = admins, a.now(), errors.Join(errs...)
	return nil
}

// adminOptions shares one session cache across every execute point, so
// a controller that touches the same machine each tick resumes its
// session rather than importing it again.
func (a *PoolActuator) adminOptions() *startd.AdminOptions {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache == nil {
		a.cache = &startd.AdminOptions{Cache: security.NewSessionCache()}
	}
	return a.cache
}

// invalidate drops the capabilities in hand, so the next command
// re-reads them.
func (a *PoolActuator) invalidate() {
	a.mu.Lock()
	a.readAt = time.Time{}
	a.mu.Unlock()
}

// push sends one machine-ad update, retrying once against freshly read
// capabilities if the first attempt is denied.
//
// A denial is ambiguous: it is what a capability that expired between
// the read and the push looks like, and it is also what genuinely lost
// authorization looks like. Retrying once resolves it, and a second
// denial is the one worth reporting.
func (a *PoolActuator) push(ctx context.Context, machine string, ad *classad.ClassAd) error {
	admin, err := a.admin(ctx, machine)
	if err != nil {
		return err
	}
	err = admin.UpdateMachineAd(ctx, ad)
	if err == nil || !denied(err) {
		return err
	}

	a.invalidate()
	admin, rerr := a.admin(ctx, machine)
	if rerr != nil {
		return errors.Join(err, rerr)
	}
	return admin.UpdateMachineAd(ctx, ad)
}

// denied reports whether an error was the execute point refusing on
// authorization rather than the request being wrong.
func denied(err error) bool {
	var ca *startd.CAError
	return errors.As(err, &ca) && ca.Denied()
}

// Hold puts a machine under a reservation.
func (a *PoolActuator) Hold(ctx context.Context, h HoldRequest) error {
	return a.push(ctx, h.Machine, HoldAd(h.Deadline, h.Until, h.Project))
}

// Release takes a machine back out of one. Nothing is deleted, because
// nothing can be; the times are set into the past.
func (a *PoolActuator) Release(ctx context.Context, machine string) error {
	return a.push(ctx, machine, ReleaseAd())
}

// Probe satisfies Provisioner by writing the sieve, which is the only
// way to learn whether this access point may still update machine ads
// -- see ProbeAd.
func (a *PoolActuator) Probe(ctx context.Context, machine string) error {
	return a.push(ctx, machine, ProbeAd())
}

// Evict preempts one running job.
//
// The startd sends no reply to a vacate, so this returns once the
// command is written. Whether the job actually went is read back from
// the next census rather than asserted here -- which is the same rule
// the rest of the controller follows, and the reason a tick that
// evicts the same slot twice is harmless.
func (a *PoolActuator) Evict(ctx context.Context, e EvictRequest) error {
	if e.Slot == "" {
		return errors.New("no slot name to vacate")
	}
	admin, err := a.admin(ctx, e.Machine)
	if err != nil {
		return err
	}
	err = admin.VacateClaim(ctx, e.Slot, !a.Graceful)
	if err == nil || !denied(err) {
		return err
	}
	a.invalidate()
	admin, rerr := a.admin(ctx, e.Machine)
	if rerr != nil {
		return errors.Join(err, rerr)
	}
	return admin.VacateClaim(ctx, e.Slot, !a.Graceful)
}

// HeldPool reads back what the pool is currently holding, for
// Controller.Pool.
//
// It reads the published attributes rather than remembering what was
// pushed. A controller restarted mid-drain, a push that failed, and a
// deadline left by a process that died all have to be visible before
// they can be corrected, and a controller that trusted its own
// recollection would disagree with the pool silently.
func HeldPool(ctx context.Context, q SlotQuerier, only string, now time.Time) (map[string]time.Time, error) {
	ads, _, err := q.QueryAdsWithOptions(ctx, "StartdAd", censusConstraint(only), &htcondor.QueryOptions{
		Limit:      slotLimit,
		Projection: []string{"Machine", AttrDeadline, AttrUntil, AttrProject},
	})
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	for _, ad := range ads {
		if ad == nil {
			continue
		}
		machine, _ := ad.EvaluateAttrString("Machine")
		if machine == "" {
			continue
		}
		deadline, _, _, held := HeldFromAd(ad, now)
		if !held {
			continue
		}
		// Slots of one machine share the ad, so they agree; taking the
		// first is taking the machine's.
		if _, seen := out[machine]; !seen {
			out[machine] = deadline
		}
	}
	return out, nil
}
