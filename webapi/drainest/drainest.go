// Package drainest answers, for every execute node in the pool, "if this
// node were drained now, when would it be empty?"
//
// A drain lets each running job keep going until its retirement time
// runs out, then evicts it. So a job leaves a draining node at the
// earlier of when it would have finished anyway and its retirement
// deadline. The deadline is known for every job: the startd publishes
// RetirementTimeRemaining on each claimed slot. When the job would
// finish is known only for jobs submitted from this access point, which
// are the only ones whose history the runtime estimator has read. Most
// of a shared pool's jobs come from elsewhere, so a node's answer is
// often a lower bound (the estimated jobs) and an upper bound (the
// retirement deadlines) rather than one time, and the response says
// which it is.
//
// The package does no I/O: a caller reads the slot ads and estimates
// the local jobs, and Compute aggregates them.
package drainest

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// SlotConstraint selects the slot ads Compute needs: every claimed slot
// (one per running job, dynamic or static) and every slot on a draining
// machine, which is where the draining flag and a drained node's empty
// partitionable slot come from. Unclaimed slots on other machines add
// nothing: a node absent from the answer has nothing running.
const SlotConstraint = `State == "Claimed" || Draining =?= true`

// SlotProjection is what SlotFromAd reads.
var SlotProjection = []string{
	"Name", "Machine", "SlotType", "PartitionableSlot", "DynamicSlot", "BackfillSlot",
	"State", "Activity", "Cpus", "GlobalJobId", "RemoteOwner", "JobStart",
	"MyCurrentTime", "RetirementTimeRemaining", "Draining",
	"ExpectedMachineGracefulDrainingCompletion",
}

// EvictionHorizon is how little retirement time a job may have left and
// still be counted as finishing on its own. A job with a 30-second
// retirement limit, or whose limit has run out, is evicted by a drain
// unless it happens to end in the next moment; it is not worth
// pretending otherwise.
const EvictionHorizon = 60 * time.Second

// noLimit is the remaining retirement above which the startd is saying
// "no limit" rather than giving a deadline: a peaceful retirement
// publishes INT_MAX less the job's age.
const noLimit = 365 * 24 * time.Hour

// Slot is the part of a slot ad Compute reads.
type Slot struct {
	Name, Machine, State, Activity string
	// GlobalJobID is "schedd#cluster.proc#qdate", empty when the slot
	// holds no job.
	GlobalJobID string
	// RemoteOwner is the job owner as the startd knows it (user@domain).
	RemoteOwner                      string
	Cpus                             float64
	Partitionable, Dynamic, Backfill bool
	Draining                         bool
	// JobStart is when the job started on this slot, unix seconds; 0 if
	// unknown.
	JobStart int64
	// AdTime is the startd's clock when it wrote the ad (MyCurrentTime);
	// RetirementRemaining is counted from it. 0 if unknown.
	AdTime int64
	// RetirementRemaining is the job's retirement time left at AdTime,
	// in seconds; nil when the ad does not say.
	RetirementRemaining *int64
	// GracefulCompletion is the startd's ExpectedMachineGracefulDrainingCompletion,
	// unix seconds; 0 if absent.
	GracefulCompletion int64
}

// SlotFromAd reads a slot ad. ClassAd attribute names are
// case-insensitive, so the startd's spelling does not matter.
func SlotFromAd(ad *classad.ClassAd) Slot {
	str := func(n string) string {
		v, _ := ad.EvaluateAttrString(n)
		return v
	}
	num := func(n string) (int64, bool) {
		v, ok := ad.EvaluateAttrNumber(n)
		if !ok || math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return int64(v), true
	}
	boolean := func(n string) bool {
		v, _ := ad.EvaluateAttrBool(n)
		return v
	}
	s := Slot{
		Name:        str("Name"),
		Machine:     str("Machine"),
		State:       str("State"),
		Activity:    str("Activity"),
		GlobalJobID: str("GlobalJobId"),
		RemoteOwner: str("RemoteOwner"),
		Draining:    boolean("Draining"),
	}
	if s.Machine == "" {
		s.Machine = s.Name
		if i := strings.LastIndexByte(s.Name, '@'); i >= 0 {
			s.Machine = s.Name[i+1:]
		}
	}
	slotType := str("SlotType")
	s.Partitionable = boolean("PartitionableSlot") || slotType == "Partitionable"
	s.Dynamic = boolean("DynamicSlot") || slotType == "Dynamic"
	s.Backfill = boolean("BackfillSlot") || s.State == "Backfill"
	if v, ok := ad.EvaluateAttrNumber("Cpus"); ok && !math.IsNaN(v) {
		s.Cpus = v
	}
	s.JobStart, _ = num("JobStart")
	s.AdTime, _ = num("MyCurrentTime")
	if v, ok := num("RetirementTimeRemaining"); ok {
		s.RetirementRemaining = &v
	}
	s.GracefulCompletion, _ = num("ExpectedMachineGracefulDrainingCompletion")
	return s
}

// hasJob says whether a slot is running a job. A claimed slot between
// jobs (Claimed/Idle) is not: a drain releases it at once.
func (s Slot) hasJob() bool {
	if s.Partitionable {
		return false
	}
	if s.GlobalJobID != "" {
		return true
	}
	switch s.Activity {
	case "Busy", "Retiring", "Suspended":
		return true
	}
	return false
}

// ParseGlobalJobID splits "schedd#cluster.proc#qdate". The schedd name is
// everything before the first '#'; ok is false when the id has no such
// shape.
func ParseGlobalJobID(gid string) (schedd string, cluster, proc int64, ok bool) {
	schedd, rest, found := strings.Cut(gid, "#")
	if !found || schedd == "" {
		return "", 0, 0, false
	}
	id, _, found := strings.Cut(rest, "#")
	if !found {
		return "", 0, 0, false
	}
	c, p, found := strings.Cut(id, ".")
	if !found {
		return "", 0, 0, false
	}
	var err error
	if cluster, err = strconv.ParseInt(c, 10, 64); err != nil || cluster < 0 {
		return "", 0, 0, false
	}
	if proc, err = strconv.ParseInt(p, 10, 64); err != nil || proc < 0 {
		return "", 0, 0, false
	}
	return schedd, cluster, proc, true
}

// Response is the answer for the pool. Seconds are counted from
// GeneratedAt.
type Response struct {
	GeneratedAt time.Time `json:"generated_at"`
	// AgeSeconds is how old the answer was when it was served.
	AgeSeconds float64 `json:"age_seconds"`
	// Stale is set when the most recent attempt to recompute failed and
	// this is the last answer that worked; Error says why.
	Stale bool   `json:"stale"`
	Error string `json:"error,omitempty"`
	// EstimatesAvailable is false when this access point does not
	// estimate runtimes at all; the retirement bounds are still there.
	EstimatesAvailable bool `json:"estimates_available"`
	// AccessPoint is the schedd name this access point's jobs carry in
	// their GlobalJobId.
	AccessPoint string    `json:"access_point,omitempty"`
	Summary     Summary   `json:"summary"`
	Machines    []Machine `json:"machines"`
}

// Summary is the pool-wide view.
type Summary struct {
	Machines       int `json:"machines"`
	JobsRunning    int `json:"jobs_running"`
	JobsEstimated  int `json:"jobs_estimated"`
	JobsFromThisAP int `json:"jobs_from_this_ap"`
	// CoresFreeingNextHour is the cores held by estimated jobs expected
	// to finish within the hour -- on their own, not by a drain. Only
	// jobs from this access point are counted.
	CoresFreeingNextHour float64 `json:"cores_freeing_next_hour"`
	DrainingNodes        int     `json:"draining_nodes"`
	// DrainingLikelyEmptyWithin2h counts draining nodes every one of
	// whose jobs is expected to be gone within two hours.
	DrainingLikelyEmptyWithin2h int `json:"draining_likely_empty_within_2h"`
}

// Machine is one execute node.
type Machine struct {
	Machine  string `json:"machine"`
	Draining bool   `json:"draining"`
	// JobsTotal counts running jobs, backfill included.
	JobsTotal      int `json:"jobs_total"`
	JobsEstimated  int `json:"jobs_estimated"`
	JobsFromThisAP int `json:"jobs_from_this_ap"`
	// JobsUnknownEnd counts jobs with no estimate whose retirement
	// limit is further off than EvictionHorizon: nobody can say when
	// they leave, only that it is by their deadline.
	JobsUnknownEnd int `json:"jobs_unknown_end"`
	// JobsUnknownFromOtherAPs is how many of those came from other
	// access points.
	JobsUnknownFromOtherAPs int `json:"jobs_unknown_from_other_aps"`
	// LikelyEmptySeconds is when the jobs with a known end are expected
	// to be gone: zero for an idle node, absent when no job has a known
	// end. When JobsUnknownEnd > 0 it is only a lower bound, and
	// AtLeastSeconds repeats it to say so.
	LikelyEmptySeconds *float64   `json:"likely_empty_seconds,omitempty"`
	LikelyEmptyAt      *time.Time `json:"likely_empty_at,omitempty"`
	AtLeastSeconds     *float64   `json:"at_least_seconds,omitempty"`
	// AtMostSeconds is the latest a drain could take: the startd's own
	// expected graceful-drain completion when it publishes one, else the
	// latest retirement deadline. Absent when neither is known.
	AtMostSeconds *float64   `json:"at_most_seconds,omitempty"`
	AtMostAt      *time.Time `json:"at_most_at,omitempty"`
	// UnknownUpToSeconds is the latest retirement deadline among the
	// jobs with an unknown end -- how long they could keep the node.
	UnknownUpToSeconds *float64 `json:"unknown_up_to_seconds,omitempty"`
	// EvictedOnDrain counts jobs a drain now would evict: their
	// retirement deadline comes before their expected end, or is
	// within EvictionHorizon.
	EvictedOnDrain int `json:"evicted_on_drain"`
	// Exceeded counts jobs already running longer than their history
	// says they should.
	Exceeded int `json:"exceeded"`
	// ExpectedEnds holds the estimated jobs' expected ends, for a
	// timeline.
	ExpectedEnds []ExpectedEnd `json:"expected_ends,omitempty"`
	// Slots is per-job detail, returned only when one machine is asked
	// for.
	Slots []SlotEstimate `json:"slots,omitempty"`
}

// ExpectedEnd is one estimated job's expected end, the time it usually
// finishes by, and the cores it holds.
type ExpectedEnd struct {
	Seconds          float64 `json:"seconds"`
	UsuallyBySeconds float64 `json:"usually_by_seconds"`
	Cpus             float64 `json:"cpus"`
}

// SlotEstimate is one running job.
type SlotEstimate struct {
	Name     string  `json:"name"`
	Owner    string  `json:"owner,omitempty"`
	Cpus     float64 `json:"cpus"`
	Backfill bool    `json:"backfill,omitempty"`
	// SubmittedFrom is the schedd name in the job's GlobalJobId.
	SubmittedFrom  string   `json:"submitted_from,omitempty"`
	FromThisAP     bool     `json:"from_this_ap"`
	RunningSeconds *float64 `json:"running_seconds,omitempty"`
	// ExpectedEnd is when the job is expected to finish on its own, and
	// UsuallyBy when jobs like it are usually done (the 90th
	// percentile). Both absent without an estimate.
	ExpectedEnd *time.Time `json:"expected_end,omitempty"`
	UsuallyBy   *time.Time `json:"usually_by,omitempty"`
	// Exceeded is set when the job has run longer than its history says
	// it should; there is then no expected end.
	Exceeded bool `json:"exceeded"`
	// RetirementDeadline is when a drain started now would evict the
	// job; absent when the startd does not say or sets no limit.
	RetirementDeadline *time.Time `json:"retirement_deadline,omitempty"`
	EvictedOnDrain     bool       `json:"evicted_on_drain"`
}

// Input is what Compute aggregates.
type Input struct {
	Now   time.Time
	Slots []Slot
	// AccessPoint is this access point's schedd name, matched
	// case-insensitively against the schedd in each GlobalJobId.
	AccessPoint string
	// Estimate answers for a job from this access point by its
	// GlobalJobId. ok is false when the job could not be looked up (it
	// is still counted as this access point's). Nil when there is no
	// estimator.
	Estimate func(globalJobID string) (res runtimeest.Result, ok bool)
}

// job is one running job's derived times, unix seconds.
type job struct {
	slot      Slot
	schedd    string
	local     bool
	estimated bool
	exceeded  bool
	running   float64
	hasRun    bool
	end       int64 // expected end, when estimated
	usuallyBy int64
	deadline  int64 // retirement deadline, when hasDeadline
	hasDL     bool
	// known: when the job leaves a draining node is known (the earlier of
	// end and deadline, or the deadline when it is about to be evicted).
	known   bool
	leaves  int64
	evicted bool
}

func evaluate(s Slot, in *Input, now int64) job {
	j := job{slot: s}
	if sch, _, _, ok := ParseGlobalJobID(s.GlobalJobID); ok {
		j.schedd = sch
		j.local = in.AccessPoint != "" && strings.EqualFold(sch, in.AccessPoint)
	}
	if s.JobStart > 0 {
		j.running = math.Max(0, float64(now-s.JobStart))
		j.hasRun = true
	}
	if s.RetirementRemaining != nil && time.Duration(*s.RetirementRemaining)*time.Second < noLimit {
		base := s.AdTime
		if base <= 0 {
			base = now
		}
		j.deadline = base + max(*s.RetirementRemaining, 0)
		j.hasDL = true
	}
	if j.local && in.Estimate != nil {
		if res, ok := in.Estimate(s.GlobalJobID); ok && res.Available {
			switch {
			case res.ExceededHistory:
				j.exceeded = true
			case res.RemainingSeconds != nil:
				j.estimated = true
				j.end = now + int64(math.Round(math.Max(0, *res.RemainingSeconds)))
				start := now
				if res.ElapsedSeconds != nil {
					start = now - int64(math.Round(*res.ElapsedSeconds))
				}
				j.usuallyBy = max(start+int64(math.Round(res.P90Seconds)), j.end)
			}
		}
	}
	horizon := now + int64(EvictionHorizon/time.Second)
	switch {
	case j.estimated && j.hasDL && j.deadline < j.end:
		j.known, j.leaves, j.evicted = true, j.deadline, true
	case j.estimated:
		j.known, j.leaves = true, j.end
	case j.hasDL && j.deadline <= horizon:
		j.known, j.leaves, j.evicted = true, j.deadline, true
	}
	return j
}

func secondsFrom(now, t int64) float64 { return float64(max(t-now, 0)) }

func ptr[T any](v T) *T { return &v }

func unixPtr(t int64) *time.Time { return ptr(time.Unix(t, 0).UTC()) }

// Compute aggregates the slots into a Response. Machines are sorted by
// name; each carries its slots, which a caller drops when it serves the
// whole pool.
func Compute(in Input) *Response {
	now := in.Now.Unix()
	resp := &Response{
		GeneratedAt:        time.Unix(now, 0).UTC(),
		EstimatesAvailable: in.Estimate != nil,
		AccessPoint:        in.AccessPoint,
		Machines:           []Machine{},
	}
	byMachine := map[string][]Slot{}
	for _, s := range in.Slots {
		byMachine[s.Machine] = append(byMachine[s.Machine], s)
	}
	names := make([]string, 0, len(byMachine))
	for m := range byMachine {
		names = append(names, m)
	}
	slices.Sort(names)

	sum := &resp.Summary
	for _, name := range names {
		m := machine(name, byMachine[name], &in, now)
		sum.Machines++
		sum.JobsRunning += m.JobsTotal
		sum.JobsEstimated += m.JobsEstimated
		sum.JobsFromThisAP += m.JobsFromThisAP
		for _, s := range m.Slots {
			if s.ExpectedEnd != nil && s.ExpectedEnd.Unix()-now <= 3600 {
				sum.CoresFreeingNextHour += s.Cpus
			}
		}
		if m.Draining {
			sum.DrainingNodes++
			if m.JobsUnknownEnd == 0 && m.LikelyEmptySeconds != nil && *m.LikelyEmptySeconds <= 7200 {
				sum.DrainingLikelyEmptyWithin2h++
			}
		}
		resp.Machines = append(resp.Machines, m)
	}
	return resp
}

func machine(name string, slots []Slot, in *Input, now int64) Machine {
	m := Machine{Machine: name}
	var (
		latestKnown   int64
		anyKnown      bool
		latestDL      int64
		allDL         = true
		latestUnknown int64
		unknownAllDL  = true
		graceful      int64
	)
	slices.SortFunc(slots, func(a, b Slot) int { return strings.Compare(a.Name, b.Name) })
	for _, s := range slots {
		if s.Draining {
			m.Draining = true
		}
		graceful = max(graceful, s.GracefulCompletion)
		if !s.hasJob() {
			continue
		}
		j := evaluate(s, in, now)
		m.JobsTotal++
		if j.local {
			m.JobsFromThisAP++
		}
		if j.estimated {
			m.JobsEstimated++
			m.ExpectedEnds = append(m.ExpectedEnds, ExpectedEnd{
				Seconds:          secondsFrom(now, j.end),
				UsuallyBySeconds: secondsFrom(now, j.usuallyBy),
				Cpus:             s.Cpus,
			})
		}
		if j.exceeded {
			m.Exceeded++
		}
		if j.evicted {
			m.EvictedOnDrain++
		}
		if j.hasDL {
			latestDL = max(latestDL, j.deadline)
		} else {
			allDL = false
		}
		if j.known {
			anyKnown = true
			latestKnown = max(latestKnown, j.leaves)
		} else {
			m.JobsUnknownEnd++
			if !j.local {
				m.JobsUnknownFromOtherAPs++
			}
			if j.hasDL {
				latestUnknown = max(latestUnknown, j.deadline)
			} else {
				unknownAllDL = false
			}
		}
		m.Slots = append(m.Slots, slotEstimate(j, now))
	}

	switch {
	case m.JobsTotal == 0:
		m.LikelyEmptySeconds = ptr(0.0)
		m.LikelyEmptyAt = unixPtr(now)
	case anyKnown:
		m.LikelyEmptySeconds = ptr(secondsFrom(now, latestKnown))
		m.LikelyEmptyAt = unixPtr(max(latestKnown, now))
		if m.JobsUnknownEnd > 0 {
			m.AtLeastSeconds = ptr(*m.LikelyEmptySeconds)
		}
	}
	switch {
	case m.JobsTotal == 0:
	case graceful > 0:
		m.AtMostSeconds = ptr(secondsFrom(now, graceful))
		m.AtMostAt = unixPtr(max(graceful, now))
	case allDL:
		m.AtMostSeconds = ptr(secondsFrom(now, latestDL))
		m.AtMostAt = unixPtr(max(latestDL, now))
	}
	if m.JobsUnknownEnd > 0 {
		switch {
		case unknownAllDL:
			m.UnknownUpToSeconds = ptr(secondsFrom(now, latestUnknown))
		case m.AtMostSeconds != nil:
			m.UnknownUpToSeconds = ptr(*m.AtMostSeconds)
		}
	}
	return m
}

func slotEstimate(j job, now int64) SlotEstimate {
	se := SlotEstimate{
		Name:           j.slot.Name,
		Owner:          j.slot.RemoteOwner,
		Cpus:           j.slot.Cpus,
		Backfill:       j.slot.Backfill,
		SubmittedFrom:  j.schedd,
		FromThisAP:     j.local,
		Exceeded:       j.exceeded,
		EvictedOnDrain: j.evicted,
	}
	if j.hasRun {
		se.RunningSeconds = ptr(j.running)
	}
	if j.estimated {
		se.ExpectedEnd = unixPtr(j.end)
		se.UsuallyBy = unixPtr(j.usuallyBy)
	}
	if j.hasDL {
		se.RetirementDeadline = unixPtr(max(j.deadline, now))
	}
	return se
}

// WithoutSlots returns a copy of the response with every machine's slots
// dropped: the pool-wide answer, which would otherwise carry one entry
// per running job.
func (r *Response) WithoutSlots() *Response {
	out := *r
	out.Machines = make([]Machine, len(r.Machines))
	for i, m := range r.Machines {
		m.Slots = nil
		out.Machines[i] = m
	}
	return &out
}

// ForMachine returns a copy holding only the named machine, with its
// slots; the machine list is empty when the pool has no such machine
// running anything.
func (r *Response) ForMachine(name string) *Response {
	out := *r
	out.Machines = []Machine{}
	for _, m := range r.Machines {
		if strings.EqualFold(m.Machine, name) {
			out.Machines = append(out.Machines, m)
		}
	}
	return &out
}
