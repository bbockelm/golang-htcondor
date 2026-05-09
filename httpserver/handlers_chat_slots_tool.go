package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/httpserver/chat"
)

// querySlotsArgs is the LLM-facing input shape. All fields are
// optional; the tool defaults to a summarized view of all
// non-dynamic slots, which is what "what's available in the pool"
// almost always wants.
type querySlotsArgs struct {
	// Constraint is a ClassAd expression filter (e.g. "GPUs > 0",
	// `CUDADeviceName == "NVIDIA A100"`). Unlike job queries, slot
	// data is pool-wide public information so we do NOT add any
	// owner scoping. The user only sees what condor_status would
	// have returned anyway.
	Constraint string `json:"constraint,omitempty"`
	// Summarize aggregates ad rows into pool-wide counts (default).
	// Set false to receive a per-slot detail list.
	Summarize *bool `json:"summarize,omitempty"`
	// Limit caps the per-slot detail rows when Summarize=false.
	// Capped at 200 server-side. Ignored when Summarize=true.
	Limit int `json:"limit,omitempty"`
}

// toolQuerySlots advertises a read-only collector query so the LLM
// can answer "what GPU types are available", "is my requested
// resource even in this pool", "how many CPUs are on each machine",
// etc. Pool-wide data — every chat user can see this, no owner
// scoping. Available on every page (jobs page users care about
// queue analysis, submit page users care about resource planning).
func (s *Handler) toolQuerySlots() chat.Tool {
	return &chatTool{
		name: "query_slots",
		description: `Query the HTCondor collector for execute-slot (machine) information. ` +
			`Use to answer questions about the pool: what GPU types exist, how many CPUs ` +
			`are available, what OS/arch is in use, whether a specific resource the user ` +
			`wants to request actually exists. ` +
			`Defaults to an aggregated summary (matched_slots, total_cpus, total_memory_mb, ` +
			`total_gpus, gpu_models breakdown, os_breakdown, arch_breakdown) which is far ` +
			`more useful than per-slot rows for advice. Set summarize=false plus a tight ` +
			`constraint when you genuinely need to see specific slots. ` +
			`Common attributes: GPUs, CUDADeviceName, Cpus, Memory (MiB), TotalCpus, ` +
			`TotalMemory, OpSys, Arch, SlotType, State, Activity, Machine.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"constraint": {
					"type": "string",
					"description": "Optional ClassAd filter (e.g. 'GPUs > 0' or 'CUDADeviceName == \"NVIDIA A100\"'). Pool-wide; not user-scoped."
				},
				"summarize": {
					"type": "boolean",
					"description": "true (default): aggregate counts. false: per-slot detail rows."
				},
				"limit": {
					"type": "integer",
					"description": "When summarize=false, max rows to return (1-200; default 50).",
					"minimum": 1,
					"maximum": 200
				}
			}
		}`),
		exec: func(ctx context.Context, _ string, in json.RawMessage) (string, error) {
			var args querySlotsArgs
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}

			collector := s.getCollector()
			if collector == nil {
				return "", fmt.Errorf(
					"this server has no collector configured; slot status is unavailable " +
						"(suggest the user run `condor_status` from a shell instead)")
			}

			// Default constraint excludes dynamic slots (which are
			// carve-outs of partitionable slots and would double-count
			// CPU/memory totals). Honor whatever the LLM sent on top
			// of that. If the LLM explicitly mentions Dynamic/SlotType,
			// it's probably querying for them on purpose — leave the
			// constraint alone.
			constraint := strings.TrimSpace(args.Constraint)
			if !mentionsSlotType(constraint) {
				if constraint == "" {
					constraint = `SlotType =!= "Dynamic"`
				} else {
					constraint = fmt.Sprintf(`(%s) && (SlotType =!= "Dynamic")`, constraint)
				}
			}

			ads, _, err := collector.QueryAdsWithOptions(ctx, "StartdAd", constraint, &htcondor.QueryOptions{
				Limit: 5000, // hard cap — prevents a runaway pool query
				Projection: []string{
					"Name", "Machine", "SlotType", "PartitionableSlot", "DynamicSlot",
					"Cpus", "Memory", "Disk",
					"TotalCpus", "TotalMemory", "TotalDisk", "TotalGpus",
					"OpSys", "OpSysAndVer", "Arch",
					"State", "Activity",
					"GPUs", "AssignedGPUs",
					"CUDADeviceName", "CUDACapability", "CUDAGlobalMemoryMb", "CUDADriverVersion",
				},
			})
			if err != nil {
				return "", fmt.Errorf("collector query: %w", err)
			}

			summarize := true
			if args.Summarize != nil {
				summarize = *args.Summarize
			}

			if summarize {
				out, _ := json.Marshal(summarizeSlotAds(ads, constraint))
				return string(out), nil
			}

			limit := args.Limit
			if limit <= 0 {
				limit = 50
			}
			if limit > 200 {
				limit = 200
			}
			detail := make([]map[string]any, 0, len(ads))
			for i, ad := range ads {
				if i >= limit {
					break
				}
				detail = append(detail, summarizeSlotForChat(ad))
			}
			out, _ := json.Marshal(map[string]any{
				"slots":      detail,
				"returned":   len(detail),
				"matched":    len(ads),
				"constraint": constraint,
			})
			return string(out), nil
		},
	}
}

// mentionsSlotType reports whether the LLM-supplied constraint
// already references the slot-type axis. If so, our default
// SlotType filter would interfere with the user's intent — better
// to honor what they asked for verbatim.
func mentionsSlotType(constraint string) bool {
	lower := strings.ToLower(constraint)
	return strings.Contains(lower, "slottype") ||
		strings.Contains(lower, "dynamicslot") ||
		strings.Contains(lower, "partitionableslot")
}

// summarizeSlotAds aggregates a slice of slot ads into the compact
// shape the LLM consumes. Designed for "what's in the pool"
// questions: counts, totals, and breakdowns over GPU model / OS /
// arch — not raw rows.
//
// Inflation guards:
//   - Machine deduplication uses the Machine attribute so 16 slots on
//     one host count as one machine.
//   - Total CPU / memory uses TotalCpus / TotalMemory when present
//     (machine-wide), falling back to per-slot Cpus / Memory.
//   - GPU counts come from GPUs (per slot); the gpu_models breakdown
//     uses CUDADeviceName when published.
func summarizeSlotAds(ads []*classad.ClassAd, constraint string) map[string]any {
	machineSeen := map[string]bool{}
	gpuModels := map[string]int{}
	osBreakdown := map[string]int{}
	archBreakdown := map[string]int{}

	var totalCPUs, totalMemMB, totalDiskKB, totalGPUs, machineCount int
	for _, ad := range ads {
		// Deduplicate machines.
		if machine, ok := readString(ad, "Machine"); ok && machine != "" {
			if !machineSeen[machine] {
				machineSeen[machine] = true
				machineCount++
				if v, ok := readInt(ad, "TotalCpus"); ok {
					totalCPUs += v
				} else if v, ok := readInt(ad, "Cpus"); ok {
					totalCPUs += v
				}
				if v, ok := readInt(ad, "TotalMemory"); ok {
					totalMemMB += v
				} else if v, ok := readInt(ad, "Memory"); ok {
					totalMemMB += v
				}
				if v, ok := readInt(ad, "TotalDisk"); ok {
					totalDiskKB += v
				}
				if v, ok := readInt(ad, "TotalGpus"); ok {
					totalGPUs += v
				} else if v, ok := readInt(ad, "GPUs"); ok {
					totalGPUs += v
				}
			}
		}
		if v, ok := readString(ad, "OpSys"); ok && v != "" {
			osBreakdown[v]++
		}
		if v, ok := readString(ad, "Arch"); ok && v != "" {
			archBreakdown[v]++
		}
		if model, ok := readString(ad, "CUDADeviceName"); ok && model != "" {
			// Some pools publish a comma-joined list when the slot has
			// multiple identical GPUs ("Tesla V100, Tesla V100"); split
			// so each GPU is counted once.
			for _, m := range strings.Split(model, ",") {
				m = strings.TrimSpace(m)
				if m != "" {
					gpuModels[m]++
				}
			}
		}
	}

	out := map[string]any{
		"matched_slots":   len(ads),
		"machines":        machineCount,
		"total_cpus":      totalCPUs,
		"total_memory_mb": totalMemMB,
		"total_disk_kb":   totalDiskKB,
		"total_gpus":      totalGPUs,
		"constraint":      constraint,
	}
	if len(gpuModels) > 0 {
		out["gpu_models"] = sortedCountMap(gpuModels)
	}
	if len(osBreakdown) > 0 {
		out["os_breakdown"] = sortedCountMap(osBreakdown)
	}
	if len(archBreakdown) > 0 {
		out["arch_breakdown"] = sortedCountMap(archBreakdown)
	}
	return out
}

// sortedCountMap returns the map as a slice of {key,count} pairs,
// sorted by descending count then ascending key. Stable, LLM-friendly,
// and avoids the random-iteration order that map-as-JSON-object would
// give us via encoding/json.
func sortedCountMap(m map[string]int) []map[string]any {
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	out := make([]map[string]any, len(pairs))
	for i, p := range pairs {
		out[i] = map[string]any{"key": p.k, "count": p.v}
	}
	return out
}

// summarizeSlotForChat is the per-slot detail row used when the LLM
// asks for summarize=false. Mirrors summarizeJobForChat: minimal,
// pre-flattened, no surprises. Unset attributes are omitted so the
// LLM doesn't have to ignore noisy nulls.
func summarizeSlotForChat(ad *classad.ClassAd) map[string]any {
	out := map[string]any{}
	if v, ok := readString(ad, "Name"); ok && v != "" {
		out["name"] = v
	}
	if v, ok := readString(ad, "Machine"); ok && v != "" {
		out["machine"] = v
	}
	if v, ok := readString(ad, "SlotType"); ok && v != "" {
		out["slot_type"] = v
	}
	if v, ok := readInt(ad, "Cpus"); ok {
		out["cpus"] = v
	}
	if v, ok := readInt(ad, "Memory"); ok {
		out["memory_mb"] = v
	}
	if v, ok := readInt(ad, "Disk"); ok {
		out["disk_kb"] = v
	}
	if v, ok := readInt(ad, "GPUs"); ok && v != 0 {
		out["gpus"] = v
	}
	if v, ok := readString(ad, "CUDADeviceName"); ok && v != "" {
		out["gpu_model"] = v
	}
	if v, ok := readString(ad, "OpSys"); ok && v != "" {
		out["os"] = v
	}
	if v, ok := readString(ad, "Arch"); ok && v != "" {
		out["arch"] = v
	}
	if v, ok := readString(ad, "State"); ok && v != "" {
		out["state"] = v
	}
	if v, ok := readString(ad, "Activity"); ok && v != "" {
		out["activity"] = v
	}
	return out
}
