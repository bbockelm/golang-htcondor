package reservation

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/startd"
)

// countingQuerier is fakeQuerier with a call count, for the questions
// about how often the pool is re-read.
type countingQuerier struct {
	fakeQuerier
	calls int
}

func (c *countingQuerier) QueryAdsWithOptions(ctx context.Context, adType, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error) {
	c.calls++
	return c.fakeQuerier.QueryAdsWithOptions(ctx, adType, constraint, opts)
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// TestActuatorAsksForPrivateAttributes is the trap in this adapter. The
// capability is a private attribute: a query that does not ask for it
// succeeds, returns ads, and carries no capability at all -- so the
// actuator would fall back to this process's own credentials on every
// machine in a pool that was publishing capabilities the whole time.
func TestActuatorAsksForPrivateAttributes(t *testing.T) {
	q := &fakeQuerier{ads: ads(t, capAd("wn01"))}
	a := &PoolActuator{Query: q}

	if err := a.Hold(context.Background(), HoldRequest{
		Machine: "wn01", Deadline: time.Now().Add(time.Hour),
		Until: time.Now().Add(2 * time.Hour), Project: "cs301",
	}); err == nil {
		// There is no startd behind the fake ad, so the push itself
		// must fail; what is being checked is the query that preceded
		// it.
		t.Log("push unexpectedly succeeded against a fake address")
	}

	if q.opts == nil {
		t.Fatalf("the actuator sent no query options")
	}
	if !q.opts.PrivateAttributes {
		t.Errorf("the actuator did not ask for private attributes, so no capability can come back")
	}
	if !hasAttr(q.opts.Projection, startd.AdminCapabilityAttr) {
		t.Errorf("projection %v does not include %s", q.opts.Projection, startd.AdminCapabilityAttr)
	}
	if !hasAttr(q.opts.Projection, "MyAddress") {
		t.Errorf("projection %v does not include MyAddress, so there is nothing to connect to", q.opts.Projection)
	}
}

// TestActuatorHonoursTheExecutePointConstraint: a reservation draws
// seats from the execute points the site named, and administering one
// outside that set is beyond what the operator agreed to.
func TestActuatorHonoursTheExecutePointConstraint(t *testing.T) {
	q := &fakeQuerier{ads: ads(t, capAd("wn01"))}
	a := &PoolActuator{Query: q, Only: `HasTeachingNodes =?= true`}
	_ = a.Release(context.Background(), "wn01")
	if q.constraint == SlotConstraint {
		t.Errorf("constraint %q does not carry the site expression", q.constraint)
	}
	if !contains(q.constraint, "HasTeachingNodes") {
		t.Errorf("constraint %q does not carry the site expression", q.constraint)
	}
}

// TestActuatorReportsAnUnknownMachine: a machine the pool does not
// answer for has to be an error. Returning nil would let the controller
// count a machine as held that nothing was ever pushed to, and the
// class would start on a pool that was never drained.
func TestActuatorReportsAnUnknownMachine(t *testing.T) {
	q := &fakeQuerier{ads: ads(t, capAd("wn01"))}
	a := &PoolActuator{Query: q}
	err := a.Release(context.Background(), "wn99")
	if err == nil {
		t.Fatalf("releasing an unknown machine reported success")
	}
	if !contains(err.Error(), "wn99") {
		t.Errorf("error %q does not name the machine", err)
	}
}

// TestActuatorRequiresACapabilityWhenAsked: on a pool whose
// authorization lives in the collector, falling back to this process's
// own credentials refuses every command with nothing to say why.
func TestActuatorRequiresACapabilityWhenAsked(t *testing.T) {
	q := &fakeQuerier{ads: ads(t, `Name = "slot1@wn02"
Machine = "wn02"
MyAddress = "<127.0.0.1:19618>"
PartitionableSlot = true`)}

	a := &PoolActuator{Query: q, RequireCapability: true}
	if err := a.Release(context.Background(), "wn02"); err == nil {
		t.Errorf("a machine with no capability was accepted although one was required")
	}

	a = &PoolActuator{Query: q}
	err := a.Release(context.Background(), "wn02")
	if err == nil {
		t.Log("push unexpectedly succeeded against a fake address")
	} else if contains(err.Error(), "no execute point answered") {
		t.Errorf("a machine with no capability was dropped although the fallback was allowed: %v", err)
	}
}

// TestActuatorRereadsCapabilities: a capability lives half an hour and
// is re-minted on every collector update, so one read cannot serve a
// controller that runs for days.
func TestActuatorRereadsCapabilities(t *testing.T) {
	q := &countingQuerier{fakeQuerier: fakeQuerier{ads: ads(t, capAd("wn01"))}}
	now := time.Unix(1_762_600_000, 0)
	a := &PoolActuator{Query: q, Refresh: 5 * time.Minute, Now: func() time.Time { return now }}

	_ = a.Release(context.Background(), "wn01")
	first := q.calls
	if first == 0 {
		t.Fatalf("the actuator never read the pool")
	}

	_ = a.Release(context.Background(), "wn01")
	if q.calls != first {
		t.Errorf("re-read the pool after %d calls with nothing stale", q.calls)
	}

	now = now.Add(6 * time.Minute)
	_ = a.Release(context.Background(), "wn01")
	if q.calls == first {
		t.Errorf("did not re-read the pool after the refresh interval passed")
	}
}

// TestActuatorRefusesAnEvictionWithoutASlot: the startd vacates by slot
// name, and there is nothing sensible to send without one.
func TestActuatorRefusesAnEvictionWithoutASlot(t *testing.T) {
	a := &PoolActuator{Query: &fakeQuerier{}}
	if err := a.Evict(context.Background(), EvictRequest{Machine: "wn01"}); err == nil {
		t.Errorf("an eviction with no slot name was accepted")
	}
}

// TestHeldPoolReadsBackWhatThePoolSays is how the controller learns what
// is held: from the pool, never from what it remembers pushing.
func TestHeldPoolReadsBackWhatThePoolSays(t *testing.T) {
	now := time.Unix(1_762_600_000, 0)
	draining := now.Add(time.Hour)
	over := now.Add(-time.Hour)

	q := &fakeQuerier{ads: ads(t,
		adText("wn01", draining, now.Add(2*time.Hour), "cs301"),
		adText("wn02", over, over, "cs301"),
		`Name = "slot1@wn03"
Machine = "wn03"`,
	)}

	held, err := HeldPool(context.Background(), q, "", now)
	if err != nil {
		t.Fatalf("HeldPool: %v", err)
	}
	if len(held) != 1 {
		t.Fatalf("HeldPool() = %v, want only wn01", held)
	}
	if got, ok := held["wn01"]; !ok || !got.Equal(draining.Truncate(time.Second)) {
		t.Errorf("wn01 deadline = %v, want %v", got, draining)
	}
}

func adText(machine string, deadline, until time.Time, project string) string {
	return `Name = "slot1@` + machine + `"
Machine = "` + machine + `"
` + AttrDeadline + ` = ` + itoa(deadline.Unix()) + `
` + AttrUntil + ` = ` + itoa(until.Unix()) + `
` + AttrProject + ` = "` + project + `"`
}

func capAd(machine string) string {
	return `Name = "slot1@` + machine + `"
Machine = "` + machine + `"
MyAddress = "<127.0.0.1:19618>"
PartitionableSlot = true
` + startd.AdminCapabilityAttr + ` = "admin_<127.0.0.1:19618>#1#1#[Encryption=\"YES\";Integrity=\"YES\";CryptoMethods=\"AES\"]abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"`
}

func hasAttr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
