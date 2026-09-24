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
	"math"
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

// computeUsage totals used-vs-total over one machine's slots, accounting
// for backfill. A backfill slot re-advertises the SAME machine as the
// primary slot and runs on the cores the primary partition leaves idle, so
// it must not add to the total -- but the resources it consumes ARE in use.
// The residual truly-free amount is the MINIMUM free reported across the
// machine's partitionable slots (primary + backfill), since a backfill
// slot's free is what neither partition has taken; used = total - that.
func computeUsage(slots []poolSlot) resourceUsage {
	var totalCpus, totalMem, totalGpus float64
	for _, s := range slots {
		totalCpus = math.Max(totalCpus, s.totalCpus)
		totalMem = math.Max(totalMem, s.totalMemoryMB)
		totalGpus = math.Max(totalGpus, s.totalGpus)
	}

	var parts []poolSlot
	for _, s := range slots {
		if s.partitionable {
			parts = append(parts, s)
		}
	}

	var usedCpus, usedMem, usedGpus float64
	if len(parts) > 0 {
		freeCpus, freeMem, freeGpus := parts[0].cpus, parts[0].memoryMB, parts[0].gpus
		for _, s := range parts[1:] {
			freeCpus = math.Min(freeCpus, s.cpus)
			freeMem = math.Min(freeMem, s.memoryMB)
			freeGpus = math.Min(freeGpus, s.gpus)
		}
		usedCpus = totalCpus - freeCpus
		usedMem = totalMem - freeMem
		usedGpus = totalGpus - freeGpus
	} else {
		// Static-slot machine: capacity and usage are the sum of the slots;
		// a Claimed static slot is in use.
		var tc, tm, tg float64
		for _, s := range slots {
			if s.dynamic {
				continue
			}
			tc += s.cpus
			tm += s.memoryMB
			tg += s.gpus
			if s.state == "Claimed" {
				usedCpus += s.cpus
				usedMem += s.memoryMB
				usedGpus += s.gpus
			}
		}
		if tc > 0 {
			totalCpus = tc
		}
		if tm > 0 {
			totalMem = tm
		}
		if tg > 0 {
			totalGpus = tg
		}
	}

	return resourceUsage{
		UsedCpus:      clampF(usedCpus, totalCpus),
		TotalCpus:     totalCpus,
		UsedMemoryMB:  clampF(usedMem, totalMem),
		TotalMemoryMB: totalMem,
		UsedGpus:      clampF(usedGpus, totalGpus),
		TotalGpus:     totalGpus,
	}
}

func addUsage(into *resourceUsage, u resourceUsage) {
	into.UsedCpus += u.UsedCpus
	into.TotalCpus += u.TotalCpus
	into.UsedMemoryMB += u.UsedMemoryMB
	into.TotalMemoryMB += u.TotalMemoryMB
	into.UsedGpus += u.UsedGpus
	into.TotalGpus += u.TotalGpus
}

func clampF(used, total float64) float64 {
	if used < 0 {
		return 0
	}
	if used > total {
		return total
	}
	return used
}

func max0(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

// runningJobs counts jobs running on a slot, including backfill jobs (a
// backfill partitionable slot's NumDynamicSlots are real running jobs).
func runningJobs(s poolSlot) int64 {
	if s.partitionable {
		return s.numDynamicSlots
	}
	if !s.dynamic && s.state == "Claimed" {
		return 1
	}
	return 0
}

// backfillCpusUsed is the CPU count a backfill partition has carved out
// (total - free on its partitionable slot), plus any claimed backfill
// static slot.
func backfillCpusUsed(s poolSlot) float64 {
	if !s.backfill {
		return 0
	}
	if s.partitionable {
		return max0(s.totalCpus - s.cpus)
	}
	if !s.dynamic && s.state == "Claimed" {
		return s.cpus
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

	// Group the raw slots per machine first, so usage can be computed with
	// the whole machine (primary + backfill partitions) in view.
	machineSlots := map[string][]poolSlot{}
	order := []string{}
	for _, s := range slots {
		if _, ok := machineSlots[s.machine]; !ok {
			order = append(order, s.machine)
		}
		machineSlots[s.machine] = append(machineSlots[s.machine], s)
	}
	sort.Strings(order)

	total := resourceUsage{}
	var totalRunning int64
	var backfillCpus float64
	ownerNodes := 0
	primaryMachines := map[string]bool{}
	nodes := make([]nodeSummary, 0, len(order))

	for _, m := range order {
		ms := machineSlots[m]
		n := nodeSummary{Machine: m, Usage: computeUsage(ms)}
		for _, s := range ms {
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
			n.RunningJobs += runningJobs(s)
			backfillCpus += backfillCpusUsed(s)
			// A machine is "Owner" when its primary (non-backfill) slot is
			// in Owner state.
			if !s.backfill && (s.partitionable || !s.dynamic) && s.state == "Owner" {
				n.Owner = true
			}
			if !s.backfill {
				primaryMachines[m] = true
			}
		}
		sort.Slice(n.Slots, func(i, j int) bool { return n.Slots[i].Name < n.Slots[j].Name })

		addUsage(&total, n.Usage)
		totalRunning += n.RunningJobs
		if n.Owner {
			ownerNodes++
		}
		nodes = append(nodes, n)
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
