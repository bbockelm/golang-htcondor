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
func Census(ctx context.Context, q SlotQuerier) ([]Machine, error) {
	ads, _, err := q.QueryAdsWithOptions(ctx, "StartdAd", SlotConstraint, &htcondor.QueryOptions{
		Limit:      slotLimit,
		Projection: SlotProjection,
	})
	if err != nil {
		return nil, err
	}
	return MachinesFromAds(ads), nil
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

	s := slot{machine: str("Machine")}
	if s.machine == "" {
		// Fall back to the slot name's host half: "slot1_3@host".
		name := str("Name")
		if i := strings.LastIndexByte(name, '@'); i >= 0 {
			s.machine = name[i+1:]
		} else {
			s.machine = name
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
