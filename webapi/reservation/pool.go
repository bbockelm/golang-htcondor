package reservation

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// This file is the only part of the package that touches the pool. It
// turns the collector's slot ads into the []Machine census.go works on,
// and nothing else: the arithmetic stays pure and testable without a
// collector.

// SlotConstraint selects the slot ads the census needs. Backfill slots
// are excluded because the resources they hold are already counted as
// free on the partitionable slot they came from; counting them again
// would let a reservation promise the same core twice.
const SlotConstraint = `BackfillSlot =!= true`

// SlotProjection is what MachinesFromAds reads. It must be sent
// explicitly: a collector query with no projection comes back with a
// handful of attributes, and a missing JobStart reads as "brand new"
// rather than "not asked for".
var SlotProjection = []string{
	"Name", "Machine", "SlotType", "PartitionableSlot", "DynamicSlot", "BackfillSlot",
	"State", "Activity", "Cpus", "GPUs", "Memory", "Disk",
	"JobStart", "RemoteProject", "GlobalJobId",
	// MyAddress is how the actuator reaches the startd that owns the
	// slot. Without it a census is read-only: there is nothing to
	// connect to.
	"MyAddress",
}

// slotLimit caps one census query. A pool larger than this is reported
// on the machines that did come back rather than not at all; the
// controller re-censuses every tick.
const slotLimit = 100_000

// SlotQuerier is the collector read the census needs.
// *htcondor.Collector satisfies it; tests substitute a fake.
type SlotQuerier interface {
	QueryAdsWithOptions(ctx context.Context, adType string, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error)
}

// Census reads the pool and returns one Machine per execute node.
//
// only, when not empty, is a site expression naming the execute points
// reservations may draw capacity from -- a reservation for a course
// should take the teaching nodes, not whatever the collector happens to
// report. It is ANDed with
// SlotConstraint and sent to the collector rather than filtered here, so
// a large pool is not read in full to discard most of it.
func Census(ctx context.Context, q SlotQuerier, only string) ([]Machine, error) {
	ads, _, err := q.QueryAdsWithOptions(ctx, "StartdAd", censusConstraint(only), &htcondor.QueryOptions{
		Limit:      slotLimit,
		Projection: SlotProjection,
	})
	if err != nil {
		return nil, err
	}
	return MachinesFromAds(ads), nil
}

// ViewProjection is what one tick reads: the census attributes plus the
// three a held machine publishes. The union is sent once rather than
// the two halves separately -- see ReadPool.
var ViewProjection = append(append([]string{}, SlotProjection...),
	AttrDeadline, AttrUntil, AttrProject)

// View is everything one controller tick reads from the pool, taken
// from a single collector query.
type View struct {
	// Machines is the census.
	Machines []Machine
	// Held is the deadline currently pushed to each held machine.
	Held map[string]time.Time
	// Running counts each project's running jobs across the pool.
	Running map[string]int
}

// ReadPool reads the pool once and derives everything a tick needs.
//
// The three parts used to be three collector queries -- the census,
// what is held, and running-by-project -- against the same ad type with
// the same constraint, differing only in projection, and the third
// re-ran the first verbatim. One query is not only a third of the dials
// but the only way the three agree: read separately they are three
// different moments, so a machine could be censused and then not be in
// the held map, or a job could be counted running and already be gone,
// and the plan would be built from a pool that never existed.
//
// now is when "held" is judged, since a deadline in the past holds
// nothing.
func ReadPool(ctx context.Context, q SlotQuerier, only string, now time.Time) (View, error) {
	ads, _, err := q.QueryAdsWithOptions(ctx, "StartdAd", censusConstraint(only), &htcondor.QueryOptions{
		Limit:      slotLimit,
		Projection: ViewProjection,
	})
	if err != nil {
		return View{}, err
	}
	machines := MachinesFromAds(ads)
	return View{
		Machines: machines,
		Held:     heldFromAds(ads, now),
		Running:  RunningByProject(machines),
	}, nil
}

// RunningByProject counts each project's running jobs in a census.
//
// A reservation's seats are pool-wide: a job that landed from another
// access point is still a seat its project holds, so this counts the
// dynamic slots the pool reports rather than this access point's queue.
func RunningByProject(machines []Machine) map[string]int {
	out := map[string]int{}
	for _, m := range machines {
		for _, d := range m.Dslots {
			if d.Project != "" && !d.Started.IsZero() {
				out[d.Project]++
			}
		}
	}
	return out
}

// censusConstraint ANDs the site's execute-point expression onto the
// census's own, parenthesised so a top-level || in the site expression
// cannot swallow it.
func censusConstraint(only string) string {
	if strings.TrimSpace(only) == "" {
		return SlotConstraint
	}
	return "(" + SlotConstraint + ") && (" + strings.TrimSpace(only) + ")"
}

// MachinesFromAds groups slot ads by machine.
//
// A partitionable slot's own Cpus/Memory/Disk are what it has left to
// carve up, so they are the machine's Free. Each dynamic slot is one
// running job and becomes a Dslot. A static slot is both at once: free
// when nothing is on it, a Dslot when something is.
//
// Machines come back in the order their first ad appeared, so the same
// pool produces the same census twice running.
//
// Dslot.Remaining is left zero. It is the runtime estimator's bound on
// how much longer a job will run, which this package cannot know;
// a later caller fills it in before ranking.
func MachinesFromAds(ads []*classad.ClassAd) []Machine {
	byName := map[string]*Machine{}
	var order []string

	for _, ad := range ads {
		if ad == nil {
			continue
		}
		s := slotFromAd(ad)
		if s.machine == "" {
			continue
		}
		m := byName[s.machine]
		if m == nil {
			m = &Machine{Name: s.machine}
			byName[s.machine] = m
			order = append(order, s.machine)
		}
		switch {
		case s.partitionable:
			m.Free = m.Free.add(s.res)
		case s.dynamic || s.occupied:
			m.Dslots = append(m.Dslots, Dslot{
				Slot:    s.name,
				Started: s.started,
				Res:     s.res,
				Project: s.project,
			})
		default:
			m.Free = m.Free.add(s.res)
		}
	}

	out := make([]Machine, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// slot is one slot ad, reduced to what the census uses.
type slot struct {
	// name is the slot ad's Name, which the startd evicts by.
	name          string
	machine       string
	res           Resources
	started       time.Time
	project       string
	partitionable bool
	dynamic       bool
	// occupied is whether something is running here, which is what makes
	// a static slot a Dslot rather than free capacity.
	occupied bool
}

// slotFromAd reads one slot ad. ClassAd attribute names are
// case-insensitive, so the startd's spelling does not matter.
func slotFromAd(ad *classad.ClassAd) slot {
	str := func(n string) string {
		v, _ := ad.EvaluateAttrString(n)
		return v
	}
	boolean := func(n string) bool {
		v, _ := ad.EvaluateAttrBool(n)
		return v
	}

	s := slot{name: str("Name"), machine: str("Machine")}
	if s.machine == "" {
		// Fall back to the slot name's host half: "slot1_3@host".
		if i := strings.LastIndexByte(s.name, '@'); i >= 0 {
			s.machine = s.name[i+1:]
		} else {
			s.machine = s.name
		}
	}

	slotType := str("SlotType")
	s.partitionable = boolean("PartitionableSlot") || strings.EqualFold(slotType, "Partitionable")
	s.dynamic = boolean("DynamicSlot") || strings.EqualFold(slotType, "Dynamic")

	// Memory is MiB and Disk is KiB in a machine ad; Resources is MB for
	// both.
	s.res = Resources{
		Cpus:     int(adNum(ad, "Cpus")),
		Gpus:     int(adNum(ad, "GPUs")),
		MemoryMB: int64(adNum(ad, "Memory")),
		DiskMB:   int64(adNum(ad, "Disk")) / 1024,
	}
	if s.res.Cpus < 0 {
		s.res.Cpus = 0
	}
	if s.res.Gpus < 0 {
		s.res.Gpus = 0
	}
	if s.res.MemoryMB < 0 {
		s.res.MemoryMB = 0
	}
	if s.res.DiskMB < 0 {
		s.res.DiskMB = 0
	}

	// JobStart is the startd's ATTR_JOB_START: unix seconds, published
	// on a claim only while a job is actually running. Absent or zero
	// means no job has started here, which census.go reads as an idle
	// core.
	if v := adNum(ad, "JobStart"); v > 0 {
		s.started = time.Unix(int64(v), 0)
	}
	s.project = str("RemoteProject")
	s.occupied = !s.started.IsZero() ||
		str("GlobalJobId") != "" ||
		strings.EqualFold(str("State"), "Claimed")

	return s
}

// adNum evaluates a numeric attribute, returning 0 when it is absent,
// not a number, or not finite.
func adNum(ad *classad.ClassAd, name string) float64 {
	v, ok := ad.EvaluateAttrNumber(name)
	if !ok || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

// Defaults for a seat whose job ad does not say. They match what the
// submit language fills in when the submitter is silent: one core, no
// GPU, and the schedd's usual floors for memory and disk.
const (
	defaultSeatCpus     = 1
	defaultSeatMemoryMB = 1024
	defaultSeatDiskMB   = 1024
)

// SeatShapeFromJobAd reads the resources one seat needs from a rendered
// job ad: the submit file a reservation carries is what defines the
// shape of the thing it is holding cores for.
//
// The Request* attributes are evaluated rather than read as literals,
// because a submit file is free to write `RequestMemory = 2 * 1024` or
// make the ask depend on another attribute, and a literal read would
// silently see nothing and fall back to the default.
//
// RequestMemory is MiB and RequestDisk is KiB, matching the machine ad;
// both come out as MB. An attribute that is absent, non-numeric, or not
// positive takes the default.
func SeatShapeFromJobAd(ad *classad.ClassAd) Resources {
	r := Resources{
		Cpus:     defaultSeatCpus,
		MemoryMB: defaultSeatMemoryMB,
		DiskMB:   defaultSeatDiskMB,
	}
	if ad == nil {
		return r
	}
	if v := adNum(ad, "RequestCpus"); v > 0 {
		r.Cpus = int(math.Ceil(v))
	}
	if v := adNum(ad, "RequestGpus"); v > 0 {
		r.Gpus = int(math.Ceil(v))
	}
	if v := adNum(ad, "RequestMemory"); v > 0 {
		r.MemoryMB = int64(math.Ceil(v))
	}
	if v := adNum(ad, "RequestDisk"); v > 0 {
		r.DiskMB = int64(math.Ceil(v / 1024))
	}
	return r
}
