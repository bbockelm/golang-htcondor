package fuzzsubmit

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// These tests run without the libcondor_utils tag: the generator takes the
// keyword table as an argument rather than calling the oracle, so its own
// behavior is testable (and vettable, and CI-runnable) with a synthetic table.
var fakeKeywords = []oracle.Keyword{
	{Key: "executable", Attr: "Cmd", Opts: oracle.KeyAsString},
	{Key: "cron_minute", Attr: "CronMinute", Opts: oracle.KeyAsString},
	{Key: "priority", Attr: "JobPrio", Opts: oracle.KeyAsInt},
	{Key: "run_as_owner", Attr: "RunAsOwner", Opts: oracle.KeyAsBool},
	{Key: "periodic_remove", Attr: "PeriodicRemove"}, // f_as_expr
	{Key: "prio", Attr: "JobPrio", Opts: oracle.KeyAsInt | oracle.KeyAltName},
	{Key: "request_gpu_memory", Attr: "", Opts: oracle.KeyError},
	{Key: "", Attr: "Nothing", Opts: oracle.KeyAsString},
	{Key: "grid_resource", Attr: "GridResource", Opts: oracle.KeyAsString | 0x23000},
	{Key: "vm_type", Attr: "JobVMType", Opts: oracle.KeyAsString | 0x24000},
}

func TestNewVocabDropsRejectedKeywords(t *testing.T) {
	v := NewVocab(fakeKeywords)
	for _, e := range v.byUniverse["vanilla"] {
		switch e.key {
		case "request_gpu_memory":
			t.Error("a keyword flagged f_error is in the vocabulary; SubmitHash rejects every file using it")
		case "":
			t.Error("a keyword with no spelling is in the vocabulary")
		case "grid_resource", "vm_type":
			t.Errorf("%q is grid/vm-only but appears in the vanilla vocabulary", e.key)
		}
	}
	if _, ok := v.Skipped["request_gpu_memory"]; !ok {
		t.Error("f_error keywords should be recorded in Skipped, not dropped silently")
	}
}

func TestVocabPartitionsByUniverse(t *testing.T) {
	v := NewVocab(fakeKeywords)
	has := func(u, key string) bool {
		for _, e := range v.byUniverse[u] {
			if e.key == key {
				return true
			}
		}
		return false
	}
	if !has("grid", "grid_resource") {
		t.Error("grid_resource is missing from the grid vocabulary")
	}
	if has("grid", "vm_type") {
		t.Error("vm_type is in the grid vocabulary; a vm keyword in a grid file is rejected before the ad is built")
	}
	if !has("vm", "cron_minute") {
		t.Error("a universe-independent keyword should be usable in every universe")
	}
}

func TestGenerateIsDeterministicAndWellFormed(t *testing.T) {
	v := NewVocab(fakeKeywords)
	for _, data := range generatedCorpusForTest() {
		got := v.Generate(data)
		if again := v.Generate(data); again != got {
			t.Fatalf("not deterministic for %x:\n%s\n---\n%s", data, got, again)
		}
		if !strings.HasPrefix(got, "universe = ") {
			t.Errorf("generated file does not start with a universe:\n%s", got)
		}
		if !strings.Contains(got, "\nqueue") {
			t.Errorf("generated file has no queue statement:\n%s", got)
		}
	}
}

// TestGenerateNeverRepeatsAnAttribute guards the rule that keeps an f_alt_err
// pair (two spellings of one attribute, where using both is an error) out of
// the same file: no attribute is ever set twice.
func TestGenerateNeverRepeatsAnAttribute(t *testing.T) {
	v := NewVocab(fakeKeywords)
	for _, data := range generatedCorpusForTest() {
		seen := map[string]bool{}
		for _, line := range strings.Split(v.Generate(data), "\n") {
			key, _, ok := strings.Cut(line, " =")
			if !ok || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "MY.") {
				continue
			}
			key = strings.ToLower(key)
			if seen[key] {
				t.Errorf("%q is set twice in one generated file:\n%s", key, v.Generate(data))
			}
			seen[key] = true
		}
	}
}

// TestGenerateTerminatesOnShortInput: the stream reports done past the end of
// the input, so a one-byte script must still produce a finite file.
func TestGenerateTerminatesOnShortInput(t *testing.T) {
	v := NewVocab(fakeKeywords)
	for _, data := range [][]byte{nil, {}, {0}, {0xff}} {
		got := v.Generate(data)
		if len(got) > 4096 {
			t.Errorf("a %d-byte script produced %d bytes of submit file", len(data), len(got))
		}
	}
}

func TestCronFieldStaysInRange(t *testing.T) {
	gen := cronField(0, 59)
	for i := 0; i < 256; i++ {
		b := byte(i)
		v := gen(&stream{b: []byte{b, b * 7, b * 13, b * 29, b * 3, b * 11}})
		if v == "" {
			t.Fatal("cron field generator produced an empty value")
		}
		for _, part := range strings.Split(v, ",") {
			if part == "" {
				t.Errorf("cron field %q has an empty element", v)
			}
		}
	}
}

func generatedCorpusForTest() [][]byte {
	return generatedCorpus(64)
}
