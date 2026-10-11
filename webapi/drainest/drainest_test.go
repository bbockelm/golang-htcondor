package drainest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

var now = time.Unix(1_800_000_000, 0)

const (
	here  = "ap2001.chtc.wisc.edu"
	there = "ap2002.chtc.wisc.edu"
	hour  = int64(3600)
	day   = 24 * hour
)

func TestParseGlobalJobID(t *testing.T) {
	cases := []struct {
		in            string
		schedd        string
		cluster, proc int64
		ok            bool
	}{
		{"ap2002.chtc.wisc.edu#6256006.977#1790107033", "ap2002.chtc.wisc.edu", 6256006, 977, true},
		{"name@host.example#1.0#5", "name@host.example", 1, 0, true},
		{"", "", 0, 0, false},
		{"host#1.0", "", 0, 0, false},
		{"#1.0#5", "", 0, 0, false},
		{"host#1#5", "", 0, 0, false},
		{"host#x.0#5", "", 0, 0, false},
		{"host#1.-2#5", "", 0, 0, false},
	}
	for _, c := range cases {
		s, cl, p, ok := ParseGlobalJobID(c.in)
		if s != c.schedd || cl != c.cluster || p != c.proc || ok != c.ok {
			t.Errorf("ParseGlobalJobID(%q) = %q %d %d %v", c.in, s, cl, p, ok)
		}
	}
}

func TestSlotFromAd(t *testing.T) {
	ad, err := classad.ParseOld(`Name = "slot1_3@e2231.chtc.wisc.edu"
Machine = "e2231.chtc.wisc.edu"
SlotType = "Dynamic"
State = "Claimed"
Activity = "Busy"
Cpus = 8
GlobalJobId = "ap2002.chtc.wisc.edu#6256006.977#1790107033"
RemoteOwner = "elnesr@chtc.wisc.edu"
JobStart = 1791716517
MyCurrentTime = 1791724570
RetirementTimeRemaining = 0
MaxJobRetirementTime = JobRuntimeGuarantee
ExpectedMachineGracefulDrainingCompletion = 1791725170`)
	if err != nil {
		t.Fatal(err)
	}
	s := SlotFromAd(ad)
	if s.Machine != "e2231.chtc.wisc.edu" || !s.Dynamic || s.Partitionable || s.Cpus != 8 ||
		s.JobStart != 1791716517 || s.AdTime != 1791724570 || s.RetirementRemaining == nil ||
		*s.RetirementRemaining != 0 || s.GracefulCompletion != 1791725170 || s.RemoteOwner != "elnesr@chtc.wisc.edu" {
		t.Errorf("%+v", s)
	}
	if !s.hasJob() {
		t.Error("a busy dynamic slot holds a job")
	}

	// Without Machine, the host comes from the name; without
	// RetirementTimeRemaining, there is no deadline.
	ad, _ = classad.ParseOld(`Name = "slot1@e9.example"
PartitionableSlot = true
State = "Drained"
Draining = true`)
	s = SlotFromAd(ad)
	if s.Machine != "e9.example" || !s.Partitionable || !s.Draining || s.RetirementRemaining != nil || s.hasJob() {
		t.Errorf("%+v", s)
	}
}

// slot is a running job's slot ad as the collector last heard it,
// adAge seconds ago.
// Every job has been running for 600 seconds.
func slot(machine, name, schedd string, cluster int, cpus float64, retirementLeft, adAge int64) Slot {
	const running = 600
	rem := retirementLeft
	return Slot{
		Name:                name + "@" + machine,
		Machine:             machine,
		State:               "Claimed",
		Activity:            "Busy",
		GlobalJobID:         schedd + "#" + itoa(int64(cluster)) + ".0#1",
		RemoteOwner:         "someone@example",
		Cpus:                cpus,
		Dynamic:             true,
		JobStart:            now.Unix() - running,
		AdTime:              now.Unix() - adAge,
		RetirementRemaining: &rem,
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// estimates answers by cluster: remaining seconds, or -1 for a job that
// has outrun its history. A cluster with no entry has no estimate.
func estimates(remaining map[int]float64) func(string) (runtimeest.Result, bool) {
	return func(gid string) (runtimeest.Result, bool) {
		_, cluster, _, ok := ParseGlobalJobID(gid)
		if !ok {
			return runtimeest.Result{}, false
		}
		r, ok := remaining[int(cluster)]
		if !ok {
			return runtimeest.Result{Reason: runtimeest.ReasonInsufficientHistory}, true
		}
		elapsed := 600.0
		if r < 0 {
			return runtimeest.Result{Available: true, ExceededHistory: true, ElapsedSeconds: &elapsed}, true
		}
		return runtimeest.Result{
			Available: true, EstimateSeconds: elapsed + r, P90Seconds: elapsed + 2*r,
			ElapsedSeconds: &elapsed, RemainingSeconds: &r,
		}, true
	}
}

func compute(remaining map[int]float64, slots ...Slot) *Response {
	return Compute(Input{Now: now, Slots: slots, AccessPoint: here, Estimate: estimates(remaining)})
}

func only(t *testing.T, r *Response) Machine {
	t.Helper()
	if len(r.Machines) != 1 {
		t.Fatalf("machines: %+v", r.Machines)
	}
	return r.Machines[0]
}

func f(p *float64) float64 {
	if p == nil {
		return -1
	}
	return *p
}

func TestAllEstimated(t *testing.T) {
	m := only(t, compute(map[int]float64{1: 1800, 2: 7800},
		slot("e1", "slot1_1", here, 1, 4, 3*day, 0),
		slot("e1", "slot1_2", here, 2, 4, 3*day, 0),
	))
	if m.JobsTotal != 2 || m.JobsEstimated != 2 || m.JobsFromThisAP != 2 || m.JobsUnknownEnd != 0 {
		t.Errorf("counts: %+v", m)
	}
	if f(m.LikelyEmptySeconds) != 7800 || m.AtLeastSeconds != nil || m.EvictedOnDrain != 0 {
		t.Errorf("likely empty: %v at least %v evicted %d", f(m.LikelyEmptySeconds), f(m.AtLeastSeconds), m.EvictedOnDrain)
	}
	if m.LikelyEmptyAt == nil || !m.LikelyEmptyAt.Equal(now.Add(7800*time.Second)) {
		t.Errorf("likely empty at %v", m.LikelyEmptyAt)
	}
	// No startd estimate: the latest deadline.
	if f(m.AtMostSeconds) != float64(3*day) {
		t.Errorf("at most %v", f(m.AtMostSeconds))
	}
	if len(m.ExpectedEnds) != 2 || m.ExpectedEnds[1].Seconds != 7800 || m.ExpectedEnds[1].UsuallyBySeconds != 2*7800 || m.ExpectedEnds[1].Cpus != 4 {
		t.Errorf("expected ends %+v", m.ExpectedEnds)
	}
	s := m.Slots[0]
	if !s.FromThisAP || s.SubmittedFrom != here || s.ExpectedEnd == nil || !s.ExpectedEnd.Equal(now.Add(1800*time.Second)) ||
		s.UsuallyBy == nil || !s.UsuallyBy.Equal(now.Add(3600*time.Second)) || f(s.RunningSeconds) != 600 || s.EvictedOnDrain {
		t.Errorf("slot %+v", s)
	}
}

func TestMixed(t *testing.T) {
	m := only(t, compute(map[int]float64{1: 5400},
		slot("e2", "slot1_1", here, 1, 1, 3*day, 0),
		slot("e2", "slot1_2", there, 9, 1, 2*day, 0),
		slot("e2", "slot1_3", there, 8, 1, 3*day-hour, 0),
		// From here, but with no history to go on.
		slot("e2", "slot1_4", here, 3, 1, day, 0),
	))
	if m.JobsTotal != 4 || m.JobsEstimated != 1 || m.JobsFromThisAP != 2 || m.JobsUnknownEnd != 3 || m.JobsUnknownFromOtherAPs != 2 {
		t.Errorf("counts: %+v", m)
	}
	if f(m.LikelyEmptySeconds) != 5400 || f(m.AtLeastSeconds) != 5400 {
		t.Errorf("likely %v at least %v", f(m.LikelyEmptySeconds), f(m.AtLeastSeconds))
	}
	if f(m.UnknownUpToSeconds) != float64(3*day-hour) || f(m.AtMostSeconds) != float64(3*day) {
		t.Errorf("unknown up to %v, at most %v", f(m.UnknownUpToSeconds), f(m.AtMostSeconds))
	}
	other := m.Slots[1]
	if other.FromThisAP || other.SubmittedFrom != there || other.ExpectedEnd != nil || other.RetirementDeadline == nil ||
		!other.RetirementDeadline.Equal(now.Add(time.Duration(2*day)*time.Second)) {
		t.Errorf("other AP's job: %+v", other)
	}
}

func TestNoneEstimated(t *testing.T) {
	m := only(t, compute(nil,
		slot("e3", "slot1_1", there, 1, 1, 2*day, 0),
		slot("e3", "slot1_2", there, 2, 1, 3*day, 0),
	))
	if m.LikelyEmptySeconds != nil || m.AtLeastSeconds != nil || m.JobsUnknownEnd != 2 {
		t.Errorf("no estimates, yet: %+v", m)
	}
	if f(m.UnknownUpToSeconds) != float64(3*day) {
		t.Errorf("unknown up to %v", f(m.UnknownUpToSeconds))
	}
}

// A 30-second retirement limit, or one that has run out, means a drain
// evicts the job; when it would have ended no longer matters.
func TestShortRetirementIsEviction(t *testing.T) {
	m := only(t, compute(map[int]float64{1: 7200},
		slot("e4", "slot1_1", here, 1, 1, 30, 0),
		slot("e4", "slot1_2", there, 2, 1, 0, 0),
		slot("e4", "slot1_3", there, 3, 1, 20, 0),
	))
	if m.EvictedOnDrain != 3 || m.JobsUnknownEnd != 0 {
		t.Errorf("evicted %d unknown %d", m.EvictedOnDrain, m.JobsUnknownEnd)
	}
	if f(m.LikelyEmptySeconds) != 30 || m.AtLeastSeconds != nil {
		t.Errorf("likely %v at least %v", f(m.LikelyEmptySeconds), f(m.AtLeastSeconds))
	}
	if !m.Slots[0].EvictedOnDrain || m.Slots[0].ExpectedEnd == nil {
		t.Errorf("the estimated job keeps its expected end and is evicted: %+v", m.Slots[0])
	}
}

// A deadline before the expected end is an eviction too, and the node
// empties at the deadline.
func TestDeadlineBeforeExpectedEnd(t *testing.T) {
	m := only(t, compute(map[int]float64{1: 7200},
		slot("e5", "slot1_1", here, 1, 1, 3600, 0),
	))
	if m.EvictedOnDrain != 1 || f(m.LikelyEmptySeconds) != 3600 {
		t.Errorf("evicted %d likely %v", m.EvictedOnDrain, f(m.LikelyEmptySeconds))
	}
}

// The deadline counts from when the startd wrote the ad, not from now.
func TestDeadlineFromAdTime(t *testing.T) {
	m := only(t, compute(nil, slot("e6", "slot1_1", there, 1, 1, 3600, 600)))
	if f(m.UnknownUpToSeconds) != 3000 {
		t.Errorf("unknown up to %v, want 3000", f(m.UnknownUpToSeconds))
	}
	// An ad older than its own deadline: the job is due to go now.
	m = only(t, compute(nil, slot("e6", "slot1_1", there, 1, 1, 60, 600)))
	if m.EvictedOnDrain != 1 || f(m.LikelyEmptySeconds) != 0 {
		t.Errorf("evicted %d likely %v", m.EvictedOnDrain, f(m.LikelyEmptySeconds))
	}
}

func TestExceeded(t *testing.T) {
	m := only(t, compute(map[int]float64{1: -1, 2: 600},
		slot("e7", "slot1_1", here, 1, 1, 3*day, 0),
		slot("e7", "slot1_2", here, 2, 1, 3*day, 0),
	))
	if m.Exceeded != 1 || m.JobsEstimated != 1 || m.JobsUnknownEnd != 1 || m.JobsUnknownFromOtherAPs != 0 {
		t.Errorf("%+v", m)
	}
	if f(m.AtLeastSeconds) != 600 {
		t.Errorf("at least %v", f(m.AtLeastSeconds))
	}
	if !m.Slots[0].Exceeded || m.Slots[0].ExpectedEnd != nil {
		t.Errorf("exceeded slot: %+v", m.Slots[0])
	}
}

func TestDrainingAndIdle(t *testing.T) {
	drainingPslot := Slot{Name: "slot1@d1", Machine: "d1", State: "Drained", Activity: "Retiring",
		Partitionable: true, Draining: true, GracefulCompletion: now.Unix() + 9*day}
	idlePslot := Slot{Name: "slot1@d2", Machine: "d2", State: "Drained", Activity: "Idle",
		Partitionable: true, Draining: true}
	claimedIdle := Slot{Name: "slot1_1@i1", Machine: "i1", State: "Claimed", Activity: "Idle", Dynamic: true}
	r := compute(map[int]float64{1: 2400},
		drainingPslot,
		slot("d1", "slot1_1", here, 1, 8, 3*day, 0),
		idlePslot,
		claimedIdle,
		slot("d3", "slot1_1", there, 2, 1, 3*day, 0),
	)
	if len(r.Machines) != 4 {
		t.Fatalf("machines %+v", r.Machines)
	}
	d1, d2, d3, i1 := r.Machines[0], r.Machines[1], r.Machines[2], r.Machines[3]
	if !d1.Draining || f(d1.LikelyEmptySeconds) != 2400 || f(d1.AtMostSeconds) != float64(9*day) {
		t.Errorf("draining node: %+v", d1)
	}
	if !d2.Draining || d2.JobsTotal != 0 || f(d2.LikelyEmptySeconds) != 0 || d2.AtMostSeconds != nil {
		t.Errorf("drained node: %+v", d2)
	}
	if d3.Draining {
		t.Errorf("not draining: %+v", d3)
	}
	if i1.JobsTotal != 0 || f(i1.LikelyEmptySeconds) != 0 {
		t.Errorf("claimed but idle: %+v", i1)
	}
	want := Summary{Machines: 4, JobsRunning: 2, JobsEstimated: 1, JobsFromThisAP: 1,
		CoresFreeingNextHour: 8, DrainingNodes: 2, DrainingLikelyEmptyWithin2h: 2}
	if r.Summary != want {
		t.Errorf("summary %+v, want %+v", r.Summary, want)
	}
}

// Backfill jobs are running jobs, and with no retirement they are
// evicted at once.
func TestBackfill(t *testing.T) {
	b := slot("e8", "backfill1_1", there, 1, 1, 0, 0)
	b.Backfill = true
	m := only(t, compute(nil, b))
	if m.JobsTotal != 1 || m.EvictedOnDrain != 1 || !m.Slots[0].Backfill {
		t.Errorf("%+v", m)
	}
}

// No estimator: the shape and the retirement bounds are all there.
func TestNoEstimator(t *testing.T) {
	r := Compute(Input{Now: now, AccessPoint: here, Slots: []Slot{slot("e9", "slot1_1", here, 1, 1, day, 0)}})
	m := only(t, r)
	if r.EstimatesAvailable || m.JobsEstimated != 0 || m.JobsFromThisAP != 1 || f(m.UnknownUpToSeconds) != float64(day) {
		t.Errorf("%+v %+v", r, m)
	}
}

// A peaceful retirement publishes no real limit.
func TestNoRetirementLimit(t *testing.T) {
	m := only(t, compute(nil, slot("e10", "slot1_1", there, 1, 1, 2147483000, 0)))
	if m.AtMostSeconds != nil || m.UnknownUpToSeconds != nil || m.Slots[0].RetirementDeadline != nil {
		t.Errorf("%+v", m)
	}
}

func TestViews(t *testing.T) {
	r := compute(nil, slot("a", "slot1_1", there, 1, 1, day, 0), slot("b", "slot1_1", there, 2, 1, day, 0))
	all := r.WithoutSlots()
	if len(all.Machines) != 2 || all.Machines[0].Slots != nil || r.Machines[0].Slots == nil {
		t.Errorf("WithoutSlots: %+v (original %+v)", all.Machines, r.Machines)
	}
	one := r.ForMachine("B")
	if len(one.Machines) != 1 || one.Machines[0].Machine != "b" || len(one.Machines[0].Slots) != 1 {
		t.Errorf("ForMachine: %+v", one.Machines)
	}
	if none := r.ForMachine("zzz"); len(none.Machines) != 0 || none.Machines == nil {
		t.Errorf("ForMachine(missing): %+v", none.Machines)
	}
}
