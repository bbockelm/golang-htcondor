package httpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestSummarizeSlotAds verifies the aggregation logic for the
// query_slots tool's default summary mode. Multi-slot machines
// should not double-count CPUs/memory; per-machine totals come from
// TotalCpus/TotalMemory when published; GPU model breakdown should
// split comma-joined CUDADeviceName lists.
func TestSummarizeSlotAds(t *testing.T) {
	// Three slot ads from two distinct machines:
	// - host-a (partitionable): 32 CPUs, 64 GiB, 4 V100s
	// - host-a dynamic carve: would normally arrive too, but our
	//   default constraint already excludes SlotType=="Dynamic".
	//   We omit it here to mirror what the collector would return.
	// - host-b (partitionable): 16 CPUs, 32 GiB, no GPUs, RHEL
	ads := []*classad.ClassAd{
		mustParseChatAd(t, `[
			Name = "slot1@host-a";
			Machine = "host-a";
			SlotType = "Partitionable";
			TotalCpus = 32;
			TotalMemory = 65536;
			TotalGpus = 4;
			Cpus = 32;
			Memory = 65536;
			GPUs = 4;
			OpSys = "LINUX";
			Arch = "X86_64";
			CUDADeviceName = "Tesla V100, Tesla V100, Tesla V100, Tesla V100";
		]`),
		mustParseChatAd(t, `[
			Name = "slot2@host-a";
			Machine = "host-a";
			SlotType = "Static";
			TotalCpus = 32;
			TotalMemory = 65536;
			Cpus = 1;
			Memory = 1024;
			OpSys = "LINUX";
			Arch = "X86_64";
		]`),
		mustParseChatAd(t, `[
			Name = "slot1@host-b";
			Machine = "host-b";
			SlotType = "Partitionable";
			TotalCpus = 16;
			TotalMemory = 32768;
			Cpus = 16;
			Memory = 32768;
			OpSys = "LINUX";
			Arch = "X86_64";
		]`),
	}

	got := summarizeSlotAds(ads, `SlotType =!= "Dynamic"`)
	out, _ := json.Marshal(got)
	js := string(out)

	if got["matched_slots"].(int) != 3 {
		t.Errorf("matched_slots = %v, want 3 (got JSON: %s)", got["matched_slots"], js)
	}
	// Two distinct machines — even though we have three ads, deduping
	// by Machine attribute prevents over-counting.
	if got["machines"].(int) != 2 {
		t.Errorf("machines = %v, want 2 (host-a, host-b)", got["machines"])
	}
	// total_cpus comes from TotalCpus, deduplicated by machine: 32 + 16.
	// If the dedup were missing we'd get 32+32+16 = 80 instead.
	if got["total_cpus"].(int) != 48 {
		t.Errorf("total_cpus = %v, want 48 (32+16, machine-deduped)", got["total_cpus"])
	}
	if got["total_memory_mb"].(int) != 65536+32768 {
		t.Errorf("total_memory_mb = %v, want %d", got["total_memory_mb"], 65536+32768)
	}
	// Only host-a has GPUs (4 of them).
	if got["total_gpus"].(int) != 4 {
		t.Errorf("total_gpus = %v, want 4", got["total_gpus"])
	}

	// gpu_models breakdown should split the comma-joined string into
	// 4 separate counts (Tesla V100 ×4 from host-a's slot1).
	models, ok := got["gpu_models"].([]map[string]any)
	if !ok || len(models) != 1 {
		t.Fatalf("gpu_models = %v, want one entry for Tesla V100", got["gpu_models"])
	}
	if models[0]["key"] != "Tesla V100" {
		t.Errorf("gpu_models[0].key = %v, want Tesla V100", models[0]["key"])
	}
	if models[0]["count"].(int) != 4 {
		t.Errorf("gpu_models[0].count = %v, want 4", models[0]["count"])
	}

	if !strings.Contains(js, `"constraint":"SlotType =!= \"Dynamic\""`) {
		t.Errorf("constraint not echoed in result: %s", js)
	}
}

// TestMentionsSlotType pins the heuristic for honoring a caller's
// constraint vs. injecting our default. False positives here would
// cause our SlotType filter to silently disappear; false negatives
// would double-AND a constraint and produce confusing results.
func TestMentionsSlotType(t *testing.T) {
	cases := map[string]bool{
		"":                                       false,
		"GPUs > 0":                               false,
		`CUDADeviceName == "NVIDIA A100"`:        false,
		`SlotType == "Static"`:                   true,
		`slottype == "static"`:                   true, // case insensitive
		`PartitionableSlot =?= true`:             true,
		`DynamicSlot =?= false`:                  true,
		`(GPUs > 0) && (SlotType =!= "Dynamic")`: true,
	}
	for input, want := range cases {
		got := mentionsSlotType(input)
		if got != want {
			t.Errorf("mentionsSlotType(%q) = %v, want %v", input, got, want)
		}
	}
}

func mustParseChatAd(t *testing.T, s string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(s)
	if err != nil {
		t.Fatalf("classad.Parse: %v\nsource: %s", err, s)
	}
	return ad
}
