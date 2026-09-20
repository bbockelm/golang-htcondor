package httpserver

// Server-side aggregation for the /pool overview. Rather than streaming
// every slot ad to the browser (which, on a large pool, overran the
// response and pushed the aggregation onto the client), this computes the
// per-node and pool-wide capacity/usage totals here and returns a compact
// JSON summary. The aggregation matches condor_status -compact:
//
//   - total per machine is the machine capacity (Total* attrs), once per
//     machine;
//   - a partitionable slot's used portion is capacity minus its free
//     leftover; a claimed static slot contributes its own size; per-job
//     dynamic slots are excluded from the query (their resources are
//     already in the partitionable leftover);
//   - backfill slots re-advertise the same physical cores, so they are
//     excluded from capacity/usage and their claimed CPUs reported apart;
//   - running jobs come from the partitionable slot's NumDynamicSlots plus
//     claimed static slots, so we never fetch the dynamic slots.
//
// ClassAd attribute reads are case-insensitive (EvaluateAttr*), so the
// capital-GPU spellings the startd publishes (GPUs, TotalGPUs) resolve
// regardless of case.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// poolSlotProjection is the attribute set the summary needs. Kept in one
// place so the query and the aggregation cannot drift.
var poolSlotProjection = []string{
	"Name", "Machine", "SlotType", "PartitionableSlot", "DynamicSlot", "BackfillSlot",
	"Cpus", "Memory", "GPUs",
	"TotalCpus", "TotalMemory", "TotalGPUs", "TotalSlotGPUs",
	"NumDynamicSlots", "State", "Activity", "RemoteOwner",
}

type resourceUsage struct {
	UsedCpus      float64 `json:"used_cpus"`
	TotalCpus     float64 `json:"total_cpus"`
	UsedMemoryMB  float64 `json:"used_memory_mb"`
	TotalMemoryMB float64 `json:"total_memory_mb"`
	UsedGpus      float64 `json:"used_gpus"`
	TotalGpus     float64 `json:"total_gpus"`
}

type slotSummary struct {
	Name        string  `json:"name"`
	SlotType    string  `json:"slot_type"`
	Backfill    bool    `json:"backfill"`
	State       string  `json:"state"`
	Activity    string  `json:"activity,omitempty"`
	Cpus        float64 `json:"cpus"`
	MemoryMB    float64 `json:"memory_mb"`
	Gpus        float64 `json:"gpus"`
	RemoteOwner string  `json:"remote_owner,omitempty"`
}

type nodeSummary struct {
	Machine     string        `json:"machine"`
	RunningJobs int64         `json:"running_jobs"`
	Owner       bool          `json:"owner"`
	Usage       resourceUsage `json:"usage"`
	Slots       []slotSummary `json:"slots"`
}

type poolSummaryTotals struct {
	Machines     int           `json:"machines"`
	RunningJobs  int64         `json:"running_jobs"`
	OwnerNodes   int           `json:"owner_nodes"`
	BackfillCpus float64       `json:"backfill_cpus"`
	Usage        resourceUsage `json:"usage"`
}

// poolSummaryResponse is the compact JSON the /pool page renders.
type poolSummaryResponse struct {
	Summary poolSummaryTotals `json:"summary"`
	Nodes   []nodeSummary     `json:"nodes"`
}

// poolSlot is the parsed view of a StartdAd used by the aggregation.
type poolSlot struct {
	name, machine, slotType, state, activity, remoteOwner string
	partitionable, dynamic, backfill                      bool
	cpus, memoryMB, gpus                                  float64
	totalCpus, totalMemoryMB, totalGpus                   float64
	numDynamicSlots                                       int64
}

func adNum(ad *classad.ClassAd, name string) float64 {
	if v, ok := ad.EvaluateAttrNumber(name); ok {
		return v
	}
	return 0
}

func adStr(ad *classad.ClassAd, name string) string {
	if v, ok := ad.EvaluateAttrString(name); ok {
		return v
	}
	return ""
}

func adBool(ad *classad.ClassAd, name string) bool {
	if v, ok := ad.EvaluateAttrBool(name); ok {
		return v
	}
	return false
}

func parsePoolSlot(ad *classad.ClassAd) poolSlot {
	slotType := adStr(ad, "SlotType")
	state := adStr(ad, "State")
	machine := adStr(ad, "Machine")
	if machine == "" {
		machine = adStr(ad, "Name")
	}
	// Machine-wide GPU total, falling back to this slot's full complement.
	totalGpus := adNum(ad, "TotalGPUs")
	if totalGpus == 0 {
		totalGpus = adNum(ad, "TotalSlotGPUs")
	}
	var numDyn int64
	if v, ok := ad.EvaluateAttrInt("NumDynamicSlots"); ok {
		numDyn = v
	}
	return poolSlot{
		name:            adStr(ad, "Name"),
		machine:         machine,
		slotType:        slotType,
		state:           state,
		activity:        adStr(ad, "Activity"),
		remoteOwner:     adStr(ad, "RemoteOwner"),
		partitionable:   adBool(ad, "PartitionableSlot") || slotType == "Partitionable",
		dynamic:         adBool(ad, "DynamicSlot") || slotType == "Dynamic",
		backfill:        adBool(ad, "BackfillSlot") || state == "Backfill",
		cpus:            adNum(ad, "Cpus"),
		memoryMB:        adNum(ad, "Memory"),
		gpus:            adNum(ad, "GPUs"),
		totalCpus:       adNum(ad, "TotalCpus"),
		totalMemoryMB:   adNum(ad, "TotalMemory"),
		totalGpus:       totalGpus,
		numDynamicSlots: numDyn,
	}
}

// accumulateUsage folds one slot into the running usage totals, deduping
// the machine capacity via seen. Backfill slots are skipped.
func accumulateUsage(u *resourceUsage, s poolSlot, seen map[string]bool) {
	if s.backfill {
		return
	}
	if !seen[s.machine] {
		seen[s.machine] = true
		u.TotalCpus += s.totalCpus
		u.TotalMemoryMB += s.totalMemoryMB
		u.TotalGpus += s.totalGpus
	}
	switch {
	case s.partitionable:
		u.UsedCpus += max0(s.totalCpus - s.cpus)
		u.UsedMemoryMB += max0(s.totalMemoryMB - s.memoryMB)
		u.UsedGpus += max0(s.totalGpus - s.gpus)
	case !s.dynamic && s.state == "Claimed":
		u.UsedCpus += s.cpus
		u.UsedMemoryMB += s.memoryMB
		u.UsedGpus += s.gpus
	}
}

func max0(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

func runningJobs(s poolSlot) int64 {
	if s.backfill {
		return 0
	}
	if s.partitionable {
		return s.numDynamicSlots
	}
	if !s.dynamic && s.state == "Claimed" {
		return 1
	}
	return 0
}

// aggregatePoolSummary turns the raw slot ads into the compact summary. It
// is pure over its input so it can be unit-tested without a collector.
func aggregatePoolSummary(ads []*classad.ClassAd) poolSummaryResponse {
	slots := make([]poolSlot, 0, len(ads))
	for _, ad := range ads {
		slots = append(slots, parsePoolSlot(ad))
	}

	byMachine := map[string]*nodeSummary{}
	order := []string{}
	nodeSeen := map[string]map[string]bool{} // per-node machine-dedup for usage

	total := resourceUsage{}
	totalSeen := map[string]bool{}
	var totalRunning int64
	var backfillCpus float64

	for _, s := range slots {
		n := byMachine[s.machine]
		if n == nil {
			n = &nodeSummary{Machine: s.machine}
			byMachine[s.machine] = n
			order = append(order, s.machine)
			nodeSeen[s.machine] = map[string]bool{}
		}
		n.Slots = append(n.Slots, slotSummary{
			Name:        s.name,
			SlotType:    s.slotType,
			Backfill:    s.backfill,
			State:       s.state,
			Activity:    s.activity,
			Cpus:        s.cpus,
			MemoryMB:    s.memoryMB,
			Gpus:        s.gpus,
			RemoteOwner: s.remoteOwner,
		})
		accumulateUsage(&n.Usage, s, nodeSeen[s.machine])
		accumulateUsage(&total, s, totalSeen)

		rj := runningJobs(s)
		n.RunningJobs += rj
		totalRunning += rj

		// A machine is "Owner" when its primary (non-backfill) slot is in
		// Owner state.
		if !s.backfill && (s.partitionable || !s.dynamic) && s.state == "Owner" {
			n.Owner = true
		}
		if s.backfill && s.state == "Claimed" {
			backfillCpus += s.cpus
		}
	}

	sort.Strings(order)
	nodes := make([]nodeSummary, 0, len(order))
	ownerNodes := 0
	primaryMachines := map[string]bool{}
	for _, s := range slots {
		if !s.backfill {
			primaryMachines[s.machine] = true
		}
	}
	for _, m := range order {
		n := byMachine[m]
		sort.Slice(n.Slots, func(i, j int) bool { return n.Slots[i].Name < n.Slots[j].Name })
		if n.Owner {
			ownerNodes++
		}
		nodes = append(nodes, *n)
	}

	return poolSummaryResponse{
		Summary: poolSummaryTotals{
			Machines:     len(primaryMachines),
			RunningJobs:  totalRunning,
			OwnerNodes:   ownerNodes,
			BackfillCpus: backfillCpus,
			Usage:        total,
		},
		Nodes: nodes,
	}
}

// handlePoolSummary serves GET /api/v1/collector/pool-summary. It queries
// the collector for the (non-dynamic) slot ads and returns the aggregated
// summary. An optional `constraint` (ClassAd expression) is ANDed with the
// dynamic-slot exclusion.
func (s *Handler) handlePoolSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.collector == nil {
		s.writeError(w, http.StatusNotImplemented, "Collector not configured")
		return
	}

	constraint := `SlotType =!= "Dynamic"`
	if userExpr := strings.TrimSpace(r.URL.Query().Get("constraint")); userExpr != "" {
		constraint = fmt.Sprintf(`(%s) && (%s)`, constraint, userExpr)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// Stream with no limit and accumulate: the aggregated result is small
	// even when the raw ad set is not, and only the (bounded) non-dynamic
	// slots are held.
	resultCh, err := s.collector.QueryAdsStream(ctx, "StartdAd", constraint, poolSlotProjection, 0, &htcondor.StreamOptions{})
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("collector query failed: %v", err))
		return
	}
	var ads []*classad.ClassAd
	for result := range resultCh {
		if result.Err != nil {
			s.writeError(w, http.StatusBadGateway, fmt.Sprintf("collector query failed: %v", result.Err))
			return
		}
		ads = append(ads, result.Ad)
	}

	s.writeJSON(w, http.StatusOK, aggregatePoolSummary(ads))
}
