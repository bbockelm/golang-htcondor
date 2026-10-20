package appolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// fakeSchedd answers DC_CONFIG_VAL from a map, the way daemon core does:
// an unknown knob is not an error, it is "not defined".
type fakeSchedd struct {
	mu       sync.Mutex
	values   map[string]string
	errs     map[string]error
	down     bool
	asked    []string
	calls    atomic.Int64
	inFlight atomic.Int64
	maxSeen  atomic.Int64
	delay    time.Duration
}

func newFake(values map[string]string) *fakeSchedd {
	up := map[string]string{}
	for k, v := range values {
		up[strings.ToUpper(k)] = v
	}
	return &fakeSchedd{values: up, errs: map[string]error{}}
}

func (f *fakeSchedd) ConfigVal(_ context.Context, name string) (string, bool, error) {
	f.calls.Add(1)
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		m := f.maxSeen.Load()
		if n <= m || f.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, name)
	if f.down {
		return "", false, errors.New("connection refused")
	}
	if err := f.errs[strings.ToUpper(name)]; err != nil {
		return "", false, err
	}
	v, ok := f.values[strings.ToUpper(name)]
	if !ok {
		return "", false, nil
	}
	return v, true, nil
}

// builtins are HTCondor's defaults for the knobs that have them, as a
// schedd reports them when its configuration leaves them alone.
func builtins() map[string]string {
	out := map[string]string{}
	for _, name := range staticKnobs() {
		if v, ok := config.BuiltinDefault(name); ok {
			out[name] = v
		}
	}
	out["JOB_EPOCH_HISTORY"] = "/var/lib/condor/spool/epoch_history"
	return out
}

func with(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func fetchReport(t *testing.T, values map[string]string, opts RenderOptions) (*Report, *fakeSchedd) {
	t.Helper()
	f := newFake(values)
	snap, err := NewCache().Get(context.Background(), "ap1.example.org", f)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return Render(snap, opts), f
}

func findEntry(t *testing.T, r *Report, group, name string) Entry {
	t.Helper()
	for _, g := range r.Groups {
		if g.Name != group {
			continue
		}
		for _, e := range g.Entries {
			if e.Name == name {
				return e
			}
		}
		t.Fatalf("group %s has no entry %s", group, name)
	}
	t.Fatalf("no group %s", group)
	return Entry{}
}

// Only allowlisted knobs are ever asked for: the static list, and names
// formed from a *_NAMES list with the suffixes the schedd itself reads.
// A configuration is full of paths and secrets; one more knob read is
// one more thing that can leak.
func TestOnlyAllowlistedKnobsAreRead(t *testing.T) {
	_, f := fetchReport(t, with(builtins(), map[string]string{
		"SUBMIT_REQUIREMENT_NAMES":   "MinMem",
		"JOB_TRANSFORM_NAMES":        "Docker",
		"SYSTEM_PERIODIC_HOLD_NAMES": "Runtime",
		"SPOOL":                      "/var/lib/condor/spool",
	}), RenderOptions{})

	allowed := map[string]bool{}
	for _, n := range staticKnobs() {
		allowed[n] = true
	}
	for _, n := range []string{
		"SUBMIT_REQUIREMENT_MINMEM", "SUBMIT_REQUIREMENT_MINMEM_REASON", "SUBMIT_REQUIREMENT_MINMEM_IS_WARNING",
		"JOB_TRANSFORM_DOCKER",
		"SYSTEM_PERIODIC_HOLD_RUNTIME", "SYSTEM_PERIODIC_HOLD_RUNTIME_REASON", "SYSTEM_PERIODIC_HOLD_RUNTIME_SUBCODE",
	} {
		allowed[n] = true
	}
	seen := map[string]bool{}
	for _, n := range f.asked {
		if !allowed[strings.ToUpper(n)] {
			t.Errorf("asked the schedd for %s, which is not on the allowlist", n)
		}
		seen[strings.ToUpper(n)] = true
	}
	for n := range allowed {
		if !seen[n] {
			t.Errorf("never asked for %s", n)
		}
	}
}

// The knobs this package reports exist in the HTCondor configuration
// HTCondor ships, where HTCondor ships one; this catches a misspelled
// name, which would otherwise report "unset" forever.
func TestStaticKnobsWithBuiltinDefaultsAreSpelledAsHTCondorDoes(t *testing.T) {
	for _, name := range []string{
		"MAX_JOBS_PER_SUBMISSION", "MAX_JOBS_PER_OWNER", "MAX_JOBS_SUBMITTED", "MAX_RUNNING_SCHEDULER_JOBS_PER_OWNER",
		"JOB_DEFAULT_REQUESTCPUS", "JOB_DEFAULT_REQUESTMEMORY", "JOB_DEFAULT_REQUESTDISK",
		"SYSTEM_MAX_RELEASES", "MAX_TRANSFER_INPUT_MB", "MAX_TRANSFER_OUTPUT_MB",
		"MAX_CONCURRENT_UPLOADS", "MAX_CONCURRENT_DOWNLOADS",
		"DAGMAN_MAX_JOBS_IDLE", "DAGMAN_MAX_JOBS_SUBMITTED", "DAGMAN_MAX_PRE_SCRIPTS", "DAGMAN_MAX_POST_SCRIPTS",
		"SCHEDD_ALLOW_LATE_MATERIALIZE", "START_SCHEDULER_UNIVERSE", "JOB_EPOCH_HISTORY",
	} {
		if _, ok := config.BuiltinDefault(name); !ok {
			t.Errorf("%s has no built-in default; is it spelled as HTCondor spells it?", name)
		}
	}
}

// An access point left at HTCondor's defaults reports nothing as
// changed, and each group says what that means.
func TestBuiltinDefaultsReportNothingChanged(t *testing.T) {
	r, _ := fetchReport(t, builtins(), RenderOptions{})
	for _, g := range r.Groups {
		for _, e := range g.Entries {
			if e.NonDefault {
				t.Errorf("%s = %q reported as changed from the default", e.Name, e.Value)
			}
			if e.Unknown {
				t.Errorf("%s reported unknown", e.Name)
			}
			if e.Description == "" {
				t.Errorf("%s has no description", e.Name)
			}
		}
	}
	if e := findEntry(t, r, GroupSubmissionLimits, "MAX_JOBS_PER_SUBMISSION"); !strings.Contains(e.Description, "20000") {
		t.Errorf("MAX_JOBS_PER_SUBMISSION: %s", e.Description)
	}
	if e := findEntry(t, r, GroupSubmissionLimits, "MAX_JOBS_SUBMITTED"); !strings.Contains(e.Description, "no limit") {
		t.Errorf("MAX_JOBS_SUBMITTED at INT_MAX should read as no limit: %s", e.Description)
	}
	if e := findEntry(t, r, GroupSubmitRequirements, "SUBMIT_REQUIREMENT_NAMES"); e.Set ||
		!strings.Contains(e.Description, "No submit requirements") {
		t.Errorf("SUBMIT_REQUIREMENT_NAMES: %+v", e)
	}
	if e := findEntry(t, r, GroupRequestDefaults, "JOB_DEFAULT_REQUESTGPUS"); e.Set ||
		!strings.Contains(e.Description, "no GPUs") {
		t.Errorf("JOB_DEFAULT_REQUESTGPUS: %+v", e)
	}
	if e := findEntry(t, r, GroupFeatures, "SCHEDD_ENABLE_SSH_TO_JOB"); !strings.Contains(e.Description, "allows ssh") ||
		!strings.Contains(e.Description, "ENABLE_SSH_TO_JOB") {
		t.Errorf("unset SCHEDD_ENABLE_SSH_TO_JOB is on, and the execute node can still refuse: %s", e.Description)
	}
}

// A site value is reported as changed, with what it means.
func TestSiteValuesAreMarked(t *testing.T) {
	r, _ := fetchReport(t, with(builtins(), map[string]string{
		"MAX_JOBS_PER_SUBMISSION":              "5000",
		"MAX_RUNNING_SCHEDULER_JOBS_PER_OWNER": "10",
		"JOB_DEFAULT_REQUESTMEMORY":            "2048",
		"SCHEDD_ALLOW_LATE_MATERIALIZE":        "True", // the default, spelled differently
		"MAX_TRANSFER_INPUT_MB":                "1024",
		"MAX_CONCURRENT_UPLOADS":               "10",
		"SCHEDD_ENABLE_SSH_TO_JOB":             "false",
	}), RenderOptions{})

	for _, c := range []struct {
		group, name, want string
		changed           bool
	}{
		{GroupSubmissionLimits, "MAX_JOBS_PER_SUBMISSION", "at most 5000 jobs", true},
		{GroupSubmissionLimits, "MAX_RUNNING_SCHEDULER_JOBS_PER_OWNER", "workflows", true},
		{GroupRequestDefaults, "JOB_DEFAULT_REQUESTMEMORY", "2048 MiB", true},
		{GroupFeatures, "SCHEDD_ALLOW_LATE_MATERIALIZE", "max_materialize", false},
		{GroupFileTransfer, "MAX_TRANSFER_INPUT_MB", "1024 MB", true},
		{GroupFileTransfer, "MAX_CONCURRENT_UPLOADS", "At most 10", true},
		{GroupFeatures, "SCHEDD_ENABLE_SSH_TO_JOB", "refuses ssh", true},
	} {
		e := findEntry(t, r, c.group, c.name)
		if e.NonDefault != c.changed {
			t.Errorf("%s: non_default = %v, want %v", c.name, e.NonDefault, c.changed)
		}
		if !strings.Contains(e.Description, c.want) {
			t.Errorf("%s: description %q does not say %q", c.name, e.Description, c.want)
		}
	}
	text := r.Text(DefaultTTL)
	if !strings.Contains(text, "- MAX_JOBS_PER_SUBMISSION = 5000 [site]:") {
		t.Errorf("text does not mark the site value:\n%s", text)
	}
	if !strings.Contains(text, "- MAX_JOBS_PER_OWNER = 100000:") {
		t.Errorf("text marks or omits a default value:\n%s", text)
	}
}

// Submit requirements lead with the message, which is written for people,
// and show the expression; a warning-only requirement says so; a name
// with no definition is reported as ignored.
func TestSubmitRequirements(t *testing.T) {
	r, _ := fetchReport(t, with(builtins(), map[string]string{
		"SUBMIT_REQUIREMENT_NAMES":              "MinMem, NoStandard Modules Ghost",
		"SUBMIT_REQUIREMENT_MinMem":             "RequestMemory >= 512",
		"SUBMIT_REQUIREMENT_MinMem_REASON":      `"Request at least 512 MB of memory"`,
		"SUBMIT_REQUIREMENT_NoStandard":         "JobUniverse != 1",
		"SUBMIT_REQUIREMENT_Modules":            `! unresolved(Requirements, "HAS_MODULES")`,
		"SUBMIT_REQUIREMENT_Modules_REASON":     `strcat("Job ", ClusterId, " needs HAS_MODULES")`,
		"SUBMIT_REQUIREMENT_Modules_IS_WARNING": "true",
	}), RenderOptions{})

	names := findEntry(t, r, GroupSubmitRequirements, "SUBMIT_REQUIREMENT_NAMES")
	if !names.NonDefault || !strings.Contains(names.Description, "MinMem, NoStandard, Modules, Ghost") {
		t.Errorf("names: %+v", names)
	}
	minMem := findEntry(t, r, GroupSubmitRequirements, "SUBMIT_REQUIREMENT_MinMem")
	if !strings.HasPrefix(minMem.Description, `A job is refused with the message "Request at least 512 MB of memory" unless `+"`RequestMemory >= 512`") {
		t.Errorf("MinMem: %s", minMem.Description)
	}
	if minMem.Extra["reason"] != "Request at least 512 MB of memory" || minMem.Extra["is_warning"] != false {
		t.Errorf("MinMem extra: %v", minMem.Extra)
	}
	if e := findEntry(t, r, GroupSubmitRequirements, "SUBMIT_REQUIREMENT_NoStandard"); !strings.Contains(e.Description, `names the requirement "NoStandard"`) {
		t.Errorf("NoStandard: %s", e.Description)
	}
	mod := findEntry(t, r, GroupSubmitRequirements, "SUBMIT_REQUIREMENT_Modules")
	if !strings.Contains(mod.Description, "accepted, with a warning") || !strings.Contains(mod.Description, "computed from the job") {
		t.Errorf("Modules: %s", mod.Description)
	}
	if e := findEntry(t, r, GroupSubmitRequirements, "SUBMIT_REQUIREMENT_Ghost"); e.Set || !strings.Contains(e.Description, "ignores it") {
		t.Errorf("Ghost: %+v", e)
	}
}

// Transforms are summarized, never dumped.
func TestTransformsAreSummarizedNotDumped(t *testing.T) {
	secret := "SET SecretToken \"hunter2\""
	r, _ := fetchReport(t, with(builtins(), map[string]string{
		"JOB_TRANSFORM_NAMES": "AssignGroup SL6ToDocker Legacy",
		"JOB_TRANSFORM_AssignGroup": "EVALSET AcctGroup = userMap(\"Groups\",Owner,AcctGroup)\n" +
			"EVALSET AccountingGroup = join(\".\",AcctGroup,Owner)\n" + secret,
		"JOB_TRANSFORM_SL6ToDocker": "REQUIREMENTS JobUniverse==5 && WantSL6 && DockerImage =?= undefined\n" +
			"SET WantDocker = true\nSET DockerImage = \"SL6\"",
		"JOB_TRANSFORM_Legacy": "[ Requirements = JobUniverse == 5; set_WantDocker = true; ]",
	}), RenderOptions{})

	group := findEntry(t, r, GroupJobTransforms, "JOB_TRANSFORM_AssignGroup")
	if !strings.Contains(group.Description, "Applies to every job") ||
		!strings.Contains(group.Description, "AcctGroup, AccountingGroup") {
		t.Errorf("AssignGroup: %s", group.Description)
	}
	docker := findEntry(t, r, GroupJobTransforms, "JOB_TRANSFORM_SL6ToDocker")
	if !strings.Contains(docker.Description, "JobUniverse==5 && WantSL6") || !strings.Contains(docker.Value, "SET WantDocker, DockerImage") {
		t.Errorf("SL6ToDocker: %+v", docker)
	}
	legacy := findEntry(t, r, GroupJobTransforms, "JOB_TRANSFORM_Legacy")
	if !strings.HasPrefix(legacy.Description, "Could not summarize") {
		t.Errorf("Legacy: %s", legacy.Description)
	}

	raw, _ := json.Marshal(r.Structured())
	for _, leak := range []string{"hunter2", "userMap(", "SL6\\\""} {
		if strings.Contains(string(raw), leak) || strings.Contains(r.Text(0), leak) {
			t.Errorf("transform text %q leaked into the report", leak)
		}
	}
}

// Hold, remove and release policies, named and unnamed, lead with the
// reason a job will carry.
func TestHoldPolicy(t *testing.T) {
	r, _ := fetchReport(t, with(builtins(), map[string]string{
		"SYSTEM_PERIODIC_HOLD_NAMES":           "Runtime",
		"SYSTEM_PERIODIC_HOLD_Runtime":         "JobStatus == 2 && time() - JobCurrentStartDate > 72*3600",
		"SYSTEM_PERIODIC_HOLD_Runtime_REASON":  `"Job ran longer than 72 hours"`,
		"SYSTEM_PERIODIC_HOLD_Runtime_SUBCODE": "42",
		"SYSTEM_PERIODIC_HOLD":                 "false",
		"SYSTEM_PERIODIC_REMOVE":               "JobStatus == 5 && time() - EnteredCurrentStatus > 30*86400",
		"SYSTEM_MAX_RELEASES":                  "3",
	}), RenderOptions{})

	rt := findEntry(t, r, GroupHoldPolicy, "SYSTEM_PERIODIC_HOLD_Runtime")
	if !strings.HasPrefix(rt.Description, `A job is put on hold (HoldReasonCode 26) with the reason "Job ran longer than 72 hours" when `) ||
		!strings.Contains(rt.Description, "HoldReasonSubCode is `42`") {
		t.Errorf("Runtime: %s", rt.Description)
	}
	if e := findEntry(t, r, GroupHoldPolicy, "SYSTEM_PERIODIC_HOLD"); !strings.Contains(e.Description, "never applies") {
		t.Errorf("trivial hold: %s", e.Description)
	}
	if e := findEntry(t, r, GroupHoldPolicy, "SYSTEM_PERIODIC_REMOVE"); !strings.HasPrefix(e.Description, "A job is removed from the queue when") {
		t.Errorf("remove: %s", e.Description)
	}
	if e := findEntry(t, r, GroupHoldPolicy, "SYSTEM_MAX_RELEASES"); !e.NonDefault || !strings.Contains(e.Description, "more than 3 times") {
		t.Errorf("max releases: %+v", e)
	}
}

// A DAGMan throttle this server overrides for every workflow reports the
// value that applies.
func TestDAGManEffectiveValue(t *testing.T) {
	r, _ := fetchReport(t, builtins(), RenderOptions{DagmanEnv: map[string]string{
		"_CONDOR_DAGMAN_MAX_JOBS_IDLE": "50",
		"CONDOR_CONFIG":                "/etc/condor/condor_config",
	}})
	e := findEntry(t, r, GroupDAGMan, "DAGMAN_MAX_JOBS_IDLE")
	if e.Value != "1000" || e.Effective != "50" || !strings.Contains(e.Description, "at most 50 idle") {
		t.Errorf("idle: %+v", e)
	}
	if e := findEntry(t, r, GroupDAGMan, "DAGMAN_MAX_JOBS_SUBMITTED"); e.Effective != "" ||
		!strings.Contains(e.Description, "No limit") || !strings.Contains(e.Description, "max_jobs") {
		t.Errorf("submitted: %+v", e)
	}
}

// JOB_EPOCH_HISTORY is a path on the access point: the report says
// whether it is set and never where it points.
func TestEpochHistoryPathNeverReported(t *testing.T) {
	r, _ := fetchReport(t, builtins(), RenderOptions{})
	e := findEntry(t, r, GroupFeatures, "JOB_EPOCH_HISTORY")
	if !e.Set || e.Value != "enabled" || e.NonDefault {
		t.Errorf("epoch history: %+v", e)
	}
	raw, _ := json.Marshal(r.Structured())
	if strings.Contains(string(raw), "/var/lib/condor") || strings.Contains(r.Text(0), "/var/lib/condor") {
		t.Error("the epoch history path leaked")
	}

	vals := builtins()
	delete(vals, "JOB_EPOCH_HISTORY")
	r, _ = fetchReport(t, vals, RenderOptions{})
	if e := findEntry(t, r, GroupFeatures, "JOB_EPOCH_HISTORY"); e.Set || !e.NonDefault ||
		!strings.Contains(e.Description, "query_job_epochs finds nothing") {
		t.Errorf("unset epoch history: %+v", e)
	}
}

// Token services and templates, which depend on more than one knob.
func TestCredentialAndTemplateFeatures(t *testing.T) {
	r, _ := fetchReport(t, with(builtins(), map[string]string{
		"LOCAL_CREDMON_PROVIDER_NAMES": "scitokens",
		"SUBMIT_TEMPLATE_NAMES":        "GPUJob, Short",
	}), RenderOptions{})
	if e := findEntry(t, r, GroupFeatures, "SUBMIT_ADD_LOCAL_CREDMON_PROVIDERS"); e.Set || e.NonDefault ||
		!strings.Contains(e.Description, "Every job gets tokens for scitokens") {
		t.Errorf("add providers: %+v", e)
	}
	if e := findEntry(t, r, GroupFeatures, "SUBMIT_TEMPLATE_NAMES"); !strings.Contains(e.Description, "GPUJob, Short") ||
		!strings.Contains(e.Description, "do not expand them") {
		t.Errorf("templates: %s", e.Description)
	}
}

// One knob the schedd will not answer is reported unknown; the rest of
// the report stands.
func TestOneFailingKnobIsUnknown(t *testing.T) {
	f := newFake(builtins())
	f.errs["MAX_TRANSFER_INPUT_MB"] = errors.New("permission denied")
	snap, err := NewCache().Get(context.Background(), "ap1", f)
	if err != nil {
		t.Fatalf("one knob failing failed the reading: %v", err)
	}
	r := Render(snap, RenderOptions{})
	e := findEntry(t, r, GroupFileTransfer, "MAX_TRANSFER_INPUT_MB")
	if !e.Unknown || e.Set || !strings.Contains(e.Description, "permission denied") {
		t.Errorf("failing knob: %+v", e)
	}
	if e := findEntry(t, r, GroupFileTransfer, "MAX_TRANSFER_OUTPUT_MB"); e.Unknown {
		t.Error("a neighbour of the failing knob is unknown too")
	}
}

// An unreachable schedd fails the reading, after one attempt rather than
// one per knob.
func TestUnreachableScheddFailsFast(t *testing.T) {
	f := newFake(nil)
	f.down = true
	_, err := NewCache().Get(context.Background(), "ap1", f)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v", err)
	}
	if n := f.calls.Load(); n != 1 {
		t.Errorf("asked an unreachable schedd %d times, want 1", n)
	}
}

// A reading is served until the TTL, then made again; a failed refresh
// serves the previous reading rather than nothing.
func TestCacheTTLAndStaleOnFailure(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	c := NewCache(WithTTL(10*time.Minute), WithClock(func() time.Time { return now }))
	f := newFake(builtins())
	ctx := context.Background()

	first, err := c.Get(ctx, "ap1", f)
	if err != nil {
		t.Fatal(err)
	}
	per := f.calls.Load()
	now = now.Add(9 * time.Minute)
	if _, err := c.Get(ctx, "AP1", f); err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != per {
		t.Errorf("read again inside the TTL (%d calls, want %d); keys should ignore case", f.calls.Load(), per)
	}

	now = now.Add(2 * time.Minute)
	f.mu.Lock()
	f.down = true
	f.mu.Unlock()
	got, err := c.Get(ctx, "ap1", f)
	if err != nil || got != first {
		t.Errorf("a failed refresh returned %v, %v; want the previous reading", got, err)
	}
	if f.calls.Load() == per {
		t.Error("did not try to refresh past the TTL")
	}

	f.mu.Lock()
	f.down = false
	f.values["MAX_JOBS_PER_OWNER"] = "7"
	f.mu.Unlock()
	got, err = c.Get(ctx, "ap1", f)
	if err != nil || got.Get("MAX_JOBS_PER_OWNER").Raw != "7" {
		t.Errorf("after recovery: %v, %v", got.Get("MAX_JOBS_PER_OWNER"), err)
	}
}

// Concurrent callers share one reading, and it opens no more connections
// at once than the cache allows.
func TestConcurrentCallersShareOneReading(t *testing.T) {
	f := newFake(with(builtins(), map[string]string{"SUBMIT_REQUIREMENT_NAMES": "A B C D E F G H I J"}))
	f.delay = 2 * time.Millisecond
	c := NewCache(WithConcurrency(3))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), "ap1", f); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	want := int64(len(staticKnobs()) + 10*3)
	if n := f.calls.Load(); n != want {
		t.Errorf("%d config reads for 20 concurrent callers, want one reading's %d", n, want)
	}
	if m := f.maxSeen.Load(); m > 3 {
		t.Errorf("%d reads in flight at once, want at most 3", m)
	}
}

// A caller who gives up does not cancel the reading the others wait on.
func TestCallerCancelDoesNotCancelTheReading(t *testing.T) {
	f := newFake(builtins())
	f.delay = 5 * time.Millisecond
	c := NewCache()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Get(ctx, "ap1", f); err == nil {
		t.Fatal("a cancelled caller with nothing cached got an answer")
	}
	snap, err := c.Get(context.Background(), "ap1", f)
	if err != nil || snap == nil {
		t.Fatalf("the reading did not survive the first caller: %v", err)
	}
}

// The *_NAMES lists are bounded: a runaway list must not become a
// connection per name.
func TestNamesListIsBounded(t *testing.T) {
	var names []string
	for i := 0; i < maxNames+5; i++ {
		names = append(names, fmt.Sprintf("R%d", i))
	}
	r, f := fetchReport(t, with(builtins(), map[string]string{"SUBMIT_REQUIREMENT_NAMES": strings.Join(names, " ")}),
		RenderOptions{})
	if n := f.calls.Load(); n != int64(len(staticKnobs())+maxNames*3) {
		t.Errorf("%d reads", n)
	}
	if e := findEntry(t, r, GroupSubmitRequirements, "SUBMIT_REQUIREMENT_NAMES"); !strings.Contains(e.Description, "5 more") {
		t.Errorf("truncation not reported: %s", e.Description)
	}
}

// The submit engine's request defaults: the access point's answer where
// it gave one -- an unset knob included -- and the local configuration
// only where it could not be asked.
func TestSubmitParamsLayering(t *testing.T) {
	local := config.NewEmpty()
	local.Set("JOB_DEFAULT_REQUESTMEMORY", "4096")
	local.Set("JOB_DEFAULT_REQUESTGPUS", "2")

	snap := &Snapshot{values: map[string]Value{
		"JOB_DEFAULT_REQUESTMEMORY": {Raw: "1024", Set: true, Asked: true},
		"JOB_DEFAULT_REQUESTGPUS":   {Asked: true}, // the access point leaves it unset
		"JOB_DEFAULT_REQUESTCPUS":   {Err: errors.New("denied"), Asked: true},
	}}
	p := SubmitParams(snap, local)
	for _, c := range []struct {
		name, want string
		ok         bool
	}{
		{"JOB_DEFAULT_REQUESTMEMORY", "1024", true},
		{"JOB_DEFAULT_REQUESTGPUS", "", true},
		{"JOB_DEFAULT_REQUESTCPUS", "1", true}, // local, which carries the built-in default
	} {
		if v, ok := p.Get(c.name); v != c.want || ok != c.ok {
			t.Errorf("%s = %q, %v; want %q, %v", c.name, v, ok, c.want, c.ok)
		}
	}

	if v, ok := SubmitParams(nil, local).Get("JOB_DEFAULT_REQUESTMEMORY"); v != "4096" || !ok {
		t.Errorf("no reading: %q, %v", v, ok)
	}
	if _, ok := SubmitParams(nil, nil).Get("JOB_DEFAULT_REQUESTMEMORY"); ok {
		t.Error("no reading and no local configuration should leave the engine to its built-in defaults")
	}
}

// SubmitContext never fails a submission: with the schedd down it hands
// back the local values, and says why.
func TestSubmitContextFallsBack(t *testing.T) {
	local := config.NewEmpty()
	local.Set("JOB_DEFAULT_REQUESTMEMORY", "4096")
	f := newFake(nil)
	f.down = true
	ctx, err := NewCache().SubmitContext(context.Background(), "ap1", f, local)
	if err == nil {
		t.Error("the failed lookup was not reported")
	}
	p := htcondor.SubmitParamsFromContext(ctx)
	if v, _ := p.Get("JOB_DEFAULT_REQUESTMEMORY"); v != "4096" {
		t.Errorf("fallback = %q", v)
	}

	f = newFake(with(builtins(), map[string]string{"JOB_DEFAULT_REQUESTMEMORY": "2GB"}))
	ctx, err = NewCache().SubmitContext(context.Background(), "ap1", f, local)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := htcondor.SubmitParamsFromContext(ctx).Get("JOB_DEFAULT_REQUESTMEMORY"); v != "2GB" {
		t.Errorf("access point value = %q", v)
	}
}
