package htcondor

import (
	"context"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// defaultsJobAd builds proc 0 of a submit file with the given params.
func defaultsJobAd(t *testing.T, submit string, params SubmitParams) *classad.ClassAd {
	t.Helper()
	sf, err := ParseSubmitFileWithOptions(strings.NewReader(submit), SubmitParseOptions{Params: params})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	return ad
}

func wantInt(t *testing.T, ad *classad.ClassAd, attr string, want int64) {
	t.Helper()
	got, ok := ad.EvaluateAttrInt(attr)
	if !ok || got != want {
		t.Errorf("%s = %d (ok=%v), want %d", attr, got, ok, want)
	}
}

func wantAbsent(t *testing.T, ad *classad.ClassAd, attr string) {
	t.Helper()
	if e, ok := ad.Lookup(attr); ok {
		t.Errorf("%s = %s, want it unset", attr, e)
	}
}

const defaultsVanilla = "executable = /bin/true\nqueue\n"

// With nothing injected, a job gets HTCondor's built-in defaults -- the
// disk one as condor_submit's expression, not a number standing in for it.
func TestRequestDefaultsBuiltin(t *testing.T) {
	ad := defaultsJobAd(t, defaultsVanilla, nil)
	wantInt(t, ad, "RequestCpus", 1)
	wantInt(t, ad, "RequestMemory", 128)
	wantInt(t, ad, "RequestDisk", 1024*1024)
	wantAbsent(t, ad, "RequestGpus")

	disk, _ := ad.Lookup("RequestDisk")
	if !strings.Contains(disk.String(), "TransferInputSizeMB") {
		t.Errorf("RequestDisk = %s, want the built-in expression over TransferInputSizeMB", disk)
	}
	wantAbsent(t, ad, "TransferInputSizeMB")
}

// The injected values are processed as request_* would be: units scale,
// expressions are kept.
func TestRequestDefaultsFromParams(t *testing.T) {
	ad := defaultsJobAd(t, defaultsVanilla, SubmitParamMap{
		"JOB_DEFAULT_REQUESTCPUS":   "4",
		"job_default_requestmemory": "2GB", // knob names are case-insensitive
		"JOB_DEFAULT_REQUESTDISK":   "10GB",
		"JOB_DEFAULT_REQUESTGPUS":   "1",
	})
	wantInt(t, ad, "RequestCpus", 4)
	wantInt(t, ad, "RequestMemory", 2048)
	wantInt(t, ad, "RequestDisk", 10*1024*1024)
	wantInt(t, ad, "RequestGpus", 1)

	ad = defaultsJobAd(t, defaultsVanilla, SubmitParamMap{
		"JOB_DEFAULT_REQUESTMEMORY": "ifThenElse(JobUniverse == 5, 3000, 100)",
	})
	mem, _ := ad.Lookup("RequestMemory")
	if !strings.Contains(mem.String(), "ifThenElse") {
		t.Errorf("RequestMemory = %s, want the expression stored", mem)
	}
	wantInt(t, ad, "RequestMemory", 3000)
}

// A source that answers "no value" is an answer: the request is left
// unset rather than falling through to the built-in default. "undefined"
// does the same.
func TestRequestDefaultsUnsetAndUndefined(t *testing.T) {
	ad := defaultsJobAd(t, defaultsVanilla, SubmitParamMap{
		"JOB_DEFAULT_REQUESTMEMORY": "",
		"JOB_DEFAULT_REQUESTCPUS":   "undefined",
		"JOB_DEFAULT_REQUESTDISK":   "UNDEFINED",
	})
	wantAbsent(t, ad, "RequestMemory")
	wantAbsent(t, ad, "RequestCpus")
	wantAbsent(t, ad, "RequestDisk")
}

// A knob the params do not know falls back to the built-in default.
func TestRequestDefaultsFallBackPerKnob(t *testing.T) {
	ad := defaultsJobAd(t, defaultsVanilla, SubmitParamMap{"JOB_DEFAULT_REQUESTCPUS": "8"})
	wantInt(t, ad, "RequestCpus", 8)
	wantInt(t, ad, "RequestMemory", 128)
}

// condor_submit reads its configuration, not the submit file, for these
// knobs: a submit file that assigns one sets a macro nothing reads.
func TestRequestDefaultsIgnoreSubmitFileAssignment(t *testing.T) {
	ad := defaultsJobAd(t, "JOB_DEFAULT_REQUESTMEMORY = 9999\n"+defaultsVanilla, nil)
	wantInt(t, ad, "RequestMemory", 128)
}

// The submit file wins over a default, and "undefined" from the user
// leaves the request off -- and out of Requirements, where a clause over
// an unset attribute would keep the job from ever matching.
func TestRequestDefaultsSubmitFileWins(t *testing.T) {
	params := SubmitParamMap{"JOB_DEFAULT_REQUESTMEMORY": "2GB", "JOB_DEFAULT_REQUESTCPUS": "4"}
	ad := defaultsJobAd(t, "request_memory = 1GB\nrequest_cpus = 2\n"+defaultsVanilla, params)
	wantInt(t, ad, "RequestMemory", 1024)
	wantInt(t, ad, "RequestCpus", 2)

	ad = defaultsJobAd(t, "should_transfer_files = YES\nrequest_memory = undefined\nrequest_disk = undefined\n"+defaultsVanilla, params)
	wantAbsent(t, ad, "RequestMemory")
	wantAbsent(t, ad, "RequestDisk")
	req, _ := ad.Lookup("Requirements")
	for _, attr := range []string{"RequestMemory", "RequestDisk"} {
		if strings.Contains(req.String(), attr) {
			t.Errorf("Requirements %s names %s, which the job does not carry", req, attr)
		}
	}
}

// A configured GPU default is a GPU request, so the job must require a
// slot with a GPU, as it would had the user written request_gpus.
func TestRequestDefaultsGpuRequirement(t *testing.T) {
	ad := defaultsJobAd(t, defaultsVanilla, SubmitParamMap{"JOB_DEFAULT_REQUESTGPUS": "1"})
	req, _ := ad.Lookup("Requirements")
	if !strings.Contains(req.String(), "RequestGpus") {
		t.Errorf("Requirements = %s, want a GPU clause for the defaulted GPU request", req)
	}
	ad = defaultsJobAd(t, defaultsVanilla, nil)
	req, _ = ad.Lookup("Requirements")
	if strings.Contains(req.String(), "Gpus") {
		t.Errorf("Requirements = %s names GPUs for a job that requests none", req)
	}
}

// A site default that does not evaluate for this engine's ads -- here
// one written against the DiskUsage condor_submit stamps and this engine
// does not -- is replaced by the built-in expression, so the job can
// still match. One the custom attributes make evaluable is kept.
func TestRequestDiskDefaultMustEvaluate(t *testing.T) {
	params := SubmitParamMap{"JOB_DEFAULT_REQUESTDISK": "DiskUsage * 2"}
	ad := defaultsJobAd(t, defaultsVanilla, params)
	wantInt(t, ad, "RequestDisk", 1024*1024)

	ad = defaultsJobAd(t, "+DiskUsage = 5000\n"+defaultsVanilla, params)
	wantInt(t, ad, "RequestDisk", 10000)
	disk, _ := ad.Lookup("RequestDisk")
	if !strings.Contains(disk.String(), "DiskUsage") {
		t.Errorf("RequestDisk = %s, want the site's expression kept", disk)
	}

	// A +RequestDisk replaces the default outright and is not checked.
	ad = defaultsJobAd(t, "+RequestDisk = Undefined\n"+defaultsVanilla, params)
	if v := ad.EvaluateAttr("RequestDisk"); !v.IsUndefined() {
		t.Errorf("RequestDisk = %v, want the custom attribute's undefined left alone", v)
	}
}

// The universes condor_submit treats specially.
func TestRequestDefaultsUniverseRules(t *testing.T) {
	params := SubmitParamMap{"JOB_DEFAULT_REQUESTCPUS": "4", "JOB_DEFAULT_REQUESTMEMORY": "2GB"}

	ad := defaultsJobAd(t, "universe = parallel\nmachine_count = 2\n"+defaultsVanilla, params)
	wantInt(t, ad, "RequestCpus", 1)

	ad = defaultsJobAd(t, "universe = vm\nvm_type = kvm\nvm_memory = 512\n"+defaultsVanilla, params)
	wantInt(t, ad, "RequestMemory", 512)

	ad = defaultsJobAd(t, "universe = grid\ngrid_resource = batch slurm\n"+defaultsVanilla, params)
	wantAbsent(t, ad, "RequestCpus")
	wantAbsent(t, ad, "RequestMemory")
	wantAbsent(t, ad, "RequestDisk")

	ad = defaultsJobAd(t, "universe = grid\ngrid_resource = condor ce.example.org ce.example.org:9619\n"+defaultsVanilla, params)
	wantInt(t, ad, "RequestCpus", 4)
}

// Every proc gets the defaults, SubmitLate included: there is no cluster
// ad here for the procs to inherit them from.
func TestRequestDefaultsEveryProc(t *testing.T) {
	sf, err := ParseSubmitFileWithOptions(strings.NewReader("executable = /bin/true\nqueue 3\n"),
		SubmitParseOptions{Params: SubmitParamMap{"JOB_DEFAULT_REQUESTMEMORY": "3GB"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := sf.SubmitLate(7)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ProcAds) != 3 {
		t.Fatalf("got %d procs", len(res.ProcAds))
	}
	for _, ad := range res.ProcAds {
		wantInt(t, ad, "RequestMemory", 3072)
	}
}

// The context is how Schedd.Submit and SubmitRemote receive the params.
func TestSubmitParamsContext(t *testing.T) {
	if SubmitParamsFromContext(context.Background()) != nil {
		t.Fatal("a bare context carries params")
	}
	p := SubmitParamMap{"JOB_DEFAULT_REQUESTCPUS": "3"}
	ctx := WithSubmitParams(context.Background(), p)
	got := SubmitParamsFromContext(ctx)
	if v, ok := got.Get("JOB_DEFAULT_REQUESTCPUS"); !ok || v != "3" {
		t.Errorf("params from context = %v, %v", v, ok)
	}
	if WithSubmitParams(ctx, nil) != ctx {
		t.Error("nil params should leave the context alone")
	}
}

// Each request keyword also answers to its job attribute's name, because
// SetRequestResources reads submit_param(SUBMIT_KEY_Request*, ATTR_REQUEST_*).
// A file using that spelling asked for a request condor_submit honours, and
// reading only the lowercase keyword gave the job the configured default
// instead -- a request the submitter never made, which the pool then matched
// and billed them for.
func TestRequestAttributeSpelling(t *testing.T) {
	ad := defaultsJobAd(t, "RequestMemory = 777\nRequestCpus = 6\nRequestDisk = 4096\nRequestGpus = 2\n"+defaultsVanilla, nil)
	wantInt(t, ad, "RequestMemory", 777)
	wantInt(t, ad, "RequestCpus", 6)
	wantInt(t, ad, "RequestDisk", 4096)
	wantInt(t, ad, "RequestGpus", 2)
}

// The keyword's own name is read first, so a file carrying both spellings
// is the keyword's value, not the attribute's.
func TestRequestKeywordOutranksAttributeSpelling(t *testing.T) {
	ad := defaultsJobAd(t, "request_memory = 100\nRequestMemory = 777\n"+defaultsVanilla, nil)
	wantInt(t, ad, "RequestMemory", 100)
}

// "undefined" through the attribute spelling leaves the request off, as it
// does through the keyword.
func TestRequestAttributeSpellingUndefined(t *testing.T) {
	ad := defaultsJobAd(t, "RequestMemory = undefined\n"+defaultsVanilla, nil)
	wantAbsent(t, ad, "RequestMemory")
}

// A submit file that says nothing about transfer gets IF_NEEDED, as
// SetTransferFiles does. YES would make the job transfer its files even
// onto a machine sharing the submitter's filesystem, and the generated
// Requirements reads this value to decide whether to offer that machine
// the choice at all.
func TestShouldTransferFilesDefaultsToIfNeeded(t *testing.T) {
	ad := defaultsJobAd(t, defaultsVanilla, nil)
	got, ok := ad.EvaluateAttrString("ShouldTransferFiles")
	if !ok || got != "IF_NEEDED" {
		t.Errorf("ShouldTransferFiles = %q (ok=%v), want IF_NEEDED", got, ok)
	}
}

// ON_EXIT_OR_EVICT cannot work with IF_NEEDED, so a file that asks for the
// first and leaves the second alone gets YES rather than the error a file
// naming both would get.
func TestOnExitOrEvictPromotesDefaultToYes(t *testing.T) {
	ad := defaultsJobAd(t, "when_to_transfer_output = ON_EXIT_OR_EVICT\n"+defaultsVanilla, nil)
	got, ok := ad.EvaluateAttrString("ShouldTransferFiles")
	if !ok || got != "YES" {
		t.Errorf("ShouldTransferFiles = %q (ok=%v), want YES", got, ok)
	}
}
