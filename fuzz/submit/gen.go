package fuzzsubmit

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// The submit-file generator.
//
// Mutating bytes almost never produces a submit file that reaches semantics:
// `cron_minute` wants cron field syntax, `grid_resource` wants a grid type and
// its arguments, `request_memory` wants a size. A keyword whose value never
// parses is a keyword the differential comparison never sees, so the seed
// corpus exercised 17 of HTCondor's 258 submit keywords.
//
// This generator takes the fuzzer's bytes as a script -- which keyword to emit
// next, which shape of value, which queue statement -- and the vocabulary from
// oracle.Keywords(), which is the table the linked SubmitHash itself uses. A
// keyword added upstream therefore enters the generator with no change here.
//
// Generation is a pure function of the input bytes: a reproducer is the bytes.

// stream turns the fuzzer's bytes into the generator's decisions. Past the end
// of the input it yields zeros and reports done, so a short input makes a short
// submit file and generation always terminates.
type stream struct {
	b []byte
	i int
}

func (s *stream) u8() byte {
	if s.i >= len(s.b) {
		s.i++
		return 0
	}
	v := s.b[s.i]
	s.i++
	return v
}

// intn returns a value in [0,n). n must be positive.
func (s *stream) intn(n int) int {
	if n <= 1 {
		return 0
	}
	v := int(s.u8())
	if n > 256 {
		v = v<<8 | int(s.u8())
	}
	return v % n
}

// done reports whether the input is spent. Decisions past this point are all
// zeros, so the generator stops adding to the file rather than emitting the
// same keyword forever.
func (s *stream) done() bool { return s.i >= len(s.b) }

func pick[T any](s *stream, xs []T) T {
	var zero T
	if len(xs) == 0 {
		return zero
	}
	return xs[s.intn(len(xs))]
}

// vocabEntry is one generatable submit keyword: its spelling, the attribute it
// sets (so two spellings of the same attribute are never emitted together), the
// universe it only means something in, and how to build a value for it.
type vocabEntry struct {
	key  string
	attr string
	opts int
	// universe is the one this keyword belongs to, "" when it applies
	// anywhere. Taken from the keyword's f_special group, which is how
	// submit_utils.cpp itself partitions grid/vm/java/parallel.
	universe string
	gen      func(*stream) string
}

// Vocab is the generator's submit vocabulary, derived at runtime from
// HTCondor's own keyword table rather than written down here.
type Vocab struct {
	// byUniverse[u] are the keywords usable in universe u, including the
	// universe-independent ones.
	byUniverse map[string][]vocabEntry
	// Universes are the universes the generator picks between.
	Universes []string
	// Skipped records keywords left out of the vocabulary and why, so the
	// exclusions are visible rather than silent.
	Skipped map[string]string
}

// excluded are keywords deliberately kept out of the vocabulary. Each reason is
// about the COMPARISON being meaningless, not about the keyword being hard.
var excluded = map[string]string{
	// Both read the host environment, and only the C++ side is allowed to:
	// the Go parser runs with AllowLocalAccess off (see GoMakeAds), so the two
	// sides would differ by the contents of the fuzzer's own environment.
	"getenv":  "reads the host environment; the Go side runs with AllowLocalAccess off",
	"get_env": "reads the host environment; the Go side runs with AllowLocalAccess off",
	// SubmitHash opens and parses the proxy, so the result depends on what is
	// on the fuzzing host rather than on the submit file.
	"x509userproxy": "reads and validates an X.509 proxy file off the host",
}

// The f_special group ids, masked out of a keyword's flag word.
// submit_utils.cpp packs the group as f_special (0x20000) plus a number in
// 0x1F000; the group is what says a keyword is grid-only, vm-only and so on.
// Only the ones that restrict a keyword to a universe are named here.
const (
	specialMask     = 0x3F000
	specialGrid     = 0x20000 + 0x03000
	specialVM       = 0x20000 + 0x04000
	specialJava     = 0x20000 + 0x05000
	specialParallel = 0x20000 + 0x0D000
)

// NewVocab builds the generator's vocabulary from HTCondor's keyword table.
//
// Three groups are dropped: keywords flagged f_error, which SubmitHash rejects
// outright (request_gpu_memory, request_gpus_memory); keywords with no spelling;
// and the host-environment pair above. Alternate spellings (f_alt_name) are
// KEPT -- they are real submit syntax and worth testing -- but no two keywords
// setting the same attribute are ever emitted into one file, which is also what
// keeps an f_alt_err pair (using both spellings is an error) from being written
// together.
func NewVocab(kws []oracle.Keyword) *Vocab {
	v := &Vocab{byUniverse: map[string][]vocabEntry{}, Skipped: map[string]string{}}
	seen := map[string]bool{}
	var entries []vocabEntry
	for _, kw := range kws {
		switch {
		case kw.Key == "":
			continue
		// f_error alone disables a keyword. f_error WITH f_alt_name is
		// f_alt_err, which means something else entirely: the keyword is a
		// valid alternate spelling, and only using BOTH spellings is an
		// error. Treating it as disabled would drop java_vm_args,
		// tool_daemon_args and concurrency_limits_expr from the vocabulary.
		case kw.Opts&oracle.KeyError != 0 && kw.Opts&oracle.KeyAltName == 0:
			v.Skipped[kw.Key] = "f_error: SubmitHash rejects this keyword"
			continue
		}
		if why, bad := excluded[strings.ToLower(kw.Key)]; bad {
			v.Skipped[kw.Key] = why
			continue
		}
		if seen[strings.ToLower(kw.Key)] {
			continue // the table lists a few keywords twice
		}
		seen[strings.ToLower(kw.Key)] = true

		e := vocabEntry{key: kw.Key, attr: kw.Attr, opts: kw.Opts}
		if alias, ok := aliasOf[strings.ToLower(kw.Key)]; ok {
			e.attr = alias
		}
		switch kw.Opts & specialMask {
		case specialGrid:
			e.universe = "grid"
		case specialVM:
			e.universe = "vm"
		case specialJava:
			e.universe = "java"
		case specialParallel:
			e.universe = "parallel"
		}
		e.gen = valueGen(kw)
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	v.Universes = []string{"vanilla", "vanilla", "vanilla", "scheduler", "local",
		"container", "docker", "grid", "vm", "java", "parallel"}
	for _, u := range v.Universes {
		if _, ok := v.byUniverse[u]; ok {
			continue
		}
		var list []vocabEntry
		for _, e := range entries {
			if e.universe == "" || e.universe == u {
				list = append(list, e)
			}
		}
		v.byUniverse[u] = list
	}
	return v
}

// aliasOf names the keyword an alternate spelling belongs to, for the few
// alternates HTCondor's table gives no attribute of their own. Everything else
// is grouped by its attribute, which is what keeps two spellings of one setting
// -- and so an f_alt_err pair, where using both is an error -- out of one file.
//
//nolint:gosec // G101: submit keyword names, not secrets
var aliasOf = map[string]string{
	"arguments2":   "Args",
	"environment2": "env",
	"get_env":      "getenv",
	"use_scitoken": "use_scitokens",
}

// universePrelude is what a universe needs before its own keywords mean
// anything. Without it SubmitHash rejects the file ("grid universe requires
// grid_resource") and the keywords in that family are never compared.
func universePrelude(u string) []string {
	switch u {
	case "grid":
		return []string{"grid_resource = batch slurm"}
	case "vm":
		return []string{"vm_type = kvm", "vm_memory = 512", "vm_disk = d.img:vda:w"}
	case "java":
		// Java universe takes the class to run as its arguments, and
		// SubmitHash rejects the file outright without them.
		return []string{"jar_files = app.jar", "arguments = MyClass"}
	case "parallel":
		return []string{"machine_count = 2"}
	case "container":
		return []string{"container_image = docker://busybox"}
	case "docker":
		return []string{"docker_image = debian:12"}
	}
	return nil
}

// maxKeywords caps one generated file. Past a couple of dozen assignments a
// file stops teaching anything new and only slows the oracle down.
const maxKeywords = 24

// Generate turns the fuzzer's bytes into a submit file. It is a pure function
// of data: the same bytes always produce the same text, so a failing input
// reproduces from the bytes alone.
func (v *Vocab) Generate(data []byte) string {
	s := &stream{b: data}
	var b strings.Builder

	u := pick(s, v.Universes)
	pool := v.byUniverse[u]
	if len(pool) == 0 {
		return "queue\n"
	}

	b.WriteString("universe = " + u + "\n")
	b.WriteString("executable = " + executableFor(u, s) + "\n")
	for _, line := range universePrelude(u) {
		b.WriteString(line + "\n")
	}

	// usedAttr keeps two spellings of one attribute out of the same file; for
	// the handful of keywords that set no single attribute, the key stands in.
	usedAttr := map[string]bool{"cmd": true}
	for _, line := range universePrelude(u) {
		if k, _, ok := strings.Cut(line, " ="); ok {
			usedAttr[strings.ToLower(k)] = true
		}
	}

	for n := 0; n < maxKeywords && !s.done(); n++ {
		e := pick(s, pool)
		id := strings.ToLower(e.attr)
		if id == "" {
			id = strings.ToLower(e.key)
		}
		if usedAttr[id] || usedAttr[strings.ToLower(e.key)] {
			continue
		}
		usedAttr[id] = true
		usedAttr[strings.ToLower(e.key)] = true
		for _, dep := range keywordDeps[strings.ToLower(e.key)] {
			k, _, _ := strings.Cut(dep, " =")
			if usedAttr[strings.ToLower(k)] {
				continue
			}
			usedAttr[strings.ToLower(k)] = true
			b.WriteString(dep + "\n")
		}
		b.WriteString(e.key + " = " + e.gen(s) + "\n")
	}

	// A macro definition and a custom attribute are not keywords, but they are
	// how real submit files are written and they exercise expansion.
	switch s.intn(4) {
	case 0:
		b.WriteString("MyMacro = 7\n+Custom = $(MyMacro)\n")
	case 1:
		b.WriteString("MY.Custom = \"c\"\n")
	}

	b.WriteString(queueStatement(s))
	return b.String()
}

func executableFor(u string, s *stream) string {
	if u == "java" {
		return "Main"
	}
	return pick(s, []string{"/bin/sleep", "/bin/true", "./run.sh", "prog"})
}

// queueStatement keeps the queue line mostly plain. A file whose queue
// statement is itself a known divergence (`queue 2 in (a b)`) would hide
// whatever the keywords above it did, so the interesting forms are rare.
func queueStatement(s *stream) string {
	switch s.intn(10) {
	case 0:
		return "queue " + strconv.Itoa(s.intn(4)) + "\n"
	case 1:
		return "queue x in (a, b)\n"
	case 2:
		return "queue x, y in (a, b)\n"
	default:
		return "queue\n"
	}
}

// ---------------------------------------------------------------------------
// Value generators.
//
// valueGen picks how to spell a value for one keyword. Name-directed
// generators come first, because they are the ones that produce values with
// internal structure (cron fields, grid resources, sizes with units); the
// keyword's declared type is the fallback for everything else.

func valueGen(kw oracle.Keyword) func(*stream) string {
	key := strings.ToLower(kw.Key)
	if g, ok := byName[key]; ok {
		return g
	}
	if g := byFamily(key, kw); g != nil {
		return g
	}
	return byType(kw)
}

// byName are the keywords whose values have a syntax of their own. These are
// the ones random bytes cannot reach: a wrong-shaped value is rejected before
// the comparison happens.
var byName = map[string]func(*stream) string{
	// --- cron (the motivating family) ---
	"cron_minute":       cronField(0, 59),
	"cron_hour":         cronField(0, 23),
	"cron_day_of_month": cronField(1, 31),
	"cron_month":        cronField(1, 12),
	"cron_day_of_week":  cronField(0, 7),

	// --- deferral / cron timing: seconds, and an absolute epoch ---
	"cron_window":         seconds,
	"cron_prep_time":      seconds,
	"deferral_window":     seconds,
	"deferral_prep_time":  seconds,
	"cronwindow":          seconds,
	"cronpreptime":        seconds,
	"deferral_time":       epochTime,
	"kill_sig_timeout":    seconds,
	"job_lease_duration":  seconds,
	"job_max_vacate_time": seconds,

	// --- grid ---
	"grid_resource":                     gridResource,
	"remote_grid_resource":              gridResource,
	"remote_remote_grid_resource":       gridResource,
	"batch_runtime":                     seconds,
	"delegatejobgsicredentialslifetime": seconds,

	// --- sizes with units ---
	"request_memory":         size,
	"request_disk":           size,
	"stack_size":             sizeKB,
	"buffer_size":            sizeKB,
	"buffer_block_size":      sizeKB,
	"max_transfer_input_mb":  sizeMB,
	"max_transfer_output_mb": sizeMB,
	"gpus_minimum_memory":    sizeMB,
	"request_cpus":           smallCount,
	"request_gpus":           smallCount,
	"vm_vcpus":               smallCount,
	"machine_count":          smallCount,
	"node_count":             smallCount,
	"nodecount":              smallCount,

	// --- enumerations: a value outside the set is rejected ---
	"notification":            enum("Always", "Complete", "Error", "Never"),
	"when_to_transfer_output": enum("ON_EXIT", "ON_EXIT_OR_EVICT", "ON_SUCCESS"),
	// NO contradicts every transfer_* keyword in the same file, and SubmitHash
	// rejects the contradiction, so it is listed once among five entries
	// rather than one of three: still generated, but not in a third of files.
	"should_transfer_files": enum("YES", "IF_NEEDED", "YES", "IF_NEEDED", "YES", "NO"),
	"kill_sig":              enum("SIGTERM", "SIGKILL", "SIGUSR1", "15"),
	"remove_kill_sig":       enum("SIGTERM", "SIGKILL", "9"),
	"hold_kill_sig":         enum("SIGTERM", "SIGQUIT"),
	// Only kvm: xen and vmware need their own required keywords, and without
	// them SubmitHash rejects the file before any vm keyword is compared.
	"vm_type":             enum("kvm"),
	"vm_networking_type":  enum("nat", "bridge"),
	"docker_pull_policy":  enum("always", "missing"),
	"docker_network_type": enum("host", "none", "bridge"),
	"transfer_container":  boolean,

	// --- structured strings ---
	"environment":             environment,
	"transfer_output_remaps":  quoted("out.txt = final.txt ; err.txt = final.err"),
	"file_remaps":             quoted("a.txt = b.txt"),
	"transfer_plugins":        quoted("http=/usr/libexec/condor/curl_plugin"),
	"concurrency_limits":      enum("lic", "lic:2, db:3", "a, b, c"),
	"concurrency_limits_expr": quoted("strcat(\\\"lic\\\", \\\":2\\\")"),
	"vm_disk":                 enum("d.img:vda:w", "a.img:vda:w, b.img:vdb:r"),
	"notify_user":             enum("someone@example.com", "root@localhost"),
	"accounting_group":        identifier,
	"accounting_group_user":   identifier,
	"project_name":            identifier,
	"batch_name":              identifier,
	"jobset":                  identifier,
	"dag_node_name":           identifier,
	"primary_unix_group":      identifier,
	"container_image":         containerImage,
	"docker_image":            enum("debian:12", "docker://alpine:3.19", "registry.example.com/x/y:1"),
	"checkpoint_destination":  enum("s3://bucket/prefix", "file:///tmp/ckpt"),
	"cuda_version":            enum("11.2", "12.0"),
	"aws_region":              enum("us-east-1", "eu-west-2"),
	"ec2_ami_id":              enum("ami-0123456789abcdef0", "ami-dead"),
	"ec2_instance_type":       enum("m1.small", "t3.micro"),
	"gce_machine_type":        enum("n1-standard-1", "e2-medium"),
	"azure_size":              enum("Standard_D2s_v3", "Standard_A1"),
	"azure_location":          enum("westus2", "eastus"),
	"arc_rte":                 enum("ENV/PROXY", "ENV/PROXY, APPS/HEP/ATLAS"),

	// --- attribute-name lists ---
	"job_ad_information_attrs": attrList,
	"job_machine_attrs":        attrList,
	"email_attributes":         attrList,
	"submit_event_notes_attrs": attrList,
	"ulog_execute_attrs":       attrList,

	// --- exit codes and signals ---
	"success_exit_code":    exitCode,
	"checkpoint_exit_code": exitCode,
	"noop_job_exit_code":   exitCode,
	"noop_job_exit_signal": exitCode,
	"core_size":            func(s *stream) string { return strconv.Itoa(s.intn(4) * 1024) },

	// --- reason strings must be string-valued ClassAd expressions ---
	"on_exit_hold_reason":  quoted("exit code says so"),
	"periodic_hold_reason": quoted("held by policy"),

	// Shapes the per-keyword sweep showed SubmitHash rejecting for the value
	// the keyword's declared type alone would have produced.
	"allow_arguments_v1":               boolean, // listed twice upstream, once as a string
	"allow_environment_v1":             boolean,
	"use_scitoken":                     enum("false"), // true needs a token the oracle cannot read
	"use_scitokens":                    enum("false"),
	"use_x509userproxy":                enum("false"),
	"buffer_files":                     quoted("a.txt = b.txt"),
	"environment2":                     enum(`"A=1 B=2"`, `"ONE=1 TWO='a b'"`, `""`),
	"java_vm_args":                     enum(`"-Xmx128m -Xms64m"`, `"-server"`),
	"java_vm_arguments2":               enum(`"-Xmx128m -Xms64m"`, `"-server"`),
	"image_size":                       enum("1", "1024", "65536"), // must be positive
	"vm_memory":                        enum("128", "512", "4096"), // megabytes, not a size string
	"job_machine_attrs_history_length": exitCode,                   // a small count; UINT_MAX is rejected
	"output_destination":               enum("file:///tmp/out"),
	"ec2_ebs_volumes":                  enum("vol-35bcc15e:hda1", "vol-35bcc15e:hda1,vol-35bcc16f:hda2"),
}

// keywordDeps are keywords SubmitHash rejects unless a companion keyword is
// also set. Emitting the companion alongside is what lets the dependent
// keyword reach the ad instead of aborting the parse.
var keywordDeps = map[string][]string{
	"ec2_ebs_volumes": {"ec2_availability_zone = us-east-1a"},
}

// byFamily catches keywords whose name follows a pattern, so a new sibling
// upstream (another ec2_*, another *_files) gets a sensible value without an
// edit here.
func byFamily(key string, kw oracle.Keyword) func(*stream) string {
	// A keyword's declared type wins over its name: vm_vnc and
	// transfer_container read as the vm_/transfer_ families but are booleans,
	// and a path there is rejected before the ad is built.
	if kw.Opts&oracle.KeyTypeMask == oracle.KeyAsBool {
		return boolean
	}
	switch {
	case strings.HasSuffix(key, "_files") || strings.HasSuffix(key, "_input") ||
		strings.HasSuffix(key, "_output") || key == "transfer_common_input":
		return fileList
	case strings.HasSuffix(key, "_file") || strings.HasSuffix(key, "_dir") ||
		strings.HasSuffix(key, "userproxy") || key == "log" || key == "starter_log":
		return path
	case strings.HasPrefix(key, "retry_request_memory"):
		return size
	case strings.HasPrefix(key, "gpus_m"):
		// gpus_minimum_capability / gpus_maximum_capability are CUDA compute
		// capabilities: a real like 8.0, not an integer.
		return enum("3.5", "8.0", "9.0")
	case strings.HasPrefix(key, "xen_"), strings.HasPrefix(key, "vm_"):
		return enum("x", "./vmfile", "a b")
	case strings.HasPrefix(key, "ec2_"), strings.HasPrefix(key, "gce_"),
		strings.HasPrefix(key, "azure_"), strings.HasPrefix(key, "batch_"),
		strings.HasPrefix(key, "tool_daemon_"):
		return enum("x", "a b", "a,b")
	}
	return nil
}

// byType is the fallback: the shape the keyword's own flag word declares. The
// value type is the low five bits, and the absence of all of them is f_as_expr
// -- a full ClassAd expression -- which is why expr is the default here.
func byType(kw oracle.Keyword) func(*stream) string {
	switch kw.Opts & oracle.KeyTypeMask {
	case oracle.KeyAsBool:
		return boolean
	case oracle.KeyAsInt:
		return integer
	case oracle.KeyAsUint:
		return unsigned
	case oracle.KeyAsString:
		return str
	case oracle.KeyAsList:
		return list
	default:
		return expr
	}
}

// cronField generates one field of a cron schedule over [lo,hi]: the forms
// SubmitHash's own parser accepts -- `*`, a value, a range, a step, and comma
// lists of those.
func cronField(lo, hi int) func(*stream) string {
	span := hi - lo + 1
	return func(s *stream) string {
		one := func() string {
			a := lo + s.intn(span)
			switch s.intn(6) {
			case 0:
				return "*"
			case 1:
				return strconv.Itoa(a)
			case 2:
				b := a + s.intn(hi-a+1)
				return fmt.Sprintf("%d-%d", a, b)
			case 3:
				b := a + s.intn(hi-a+1)
				return fmt.Sprintf("%d-%d/%d", a, b, 1+s.intn(4))
			case 4:
				return fmt.Sprintf("*/%d", 1+s.intn(6))
			default:
				return fmt.Sprintf("%d-%d", lo, hi)
			}
		}
		n := 1 + s.intn(3)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = one()
		}
		return strings.Join(parts, ",")
	}
}

func gridResource(s *stream) string {
	return pick(s, []string{
		"batch slurm",
		"batch pbs",
		"batch lsf queue1",
		"condor submit.example.com cm.example.com",
		"arc https://arc.example.com:443/arex",
	})
}

// size spells a memory/disk request the way submit files do: a bare number of
// megabytes, a quoted quantity with a unit suffix, or an expression.
func size(s *stream) string {
	return pick(s, []string{"128", "1024", "2048",
		`"2 GB"`, `"512 MB"`, `"1G"`, `"100K"`, `"4T"`,
		"2 * 1024", "RequestMemory"})
}

func sizeKB(s *stream) string  { return pick(s, []string{"0", "1024", "65536", `"64 MB"`}) }
func sizeMB(s *stream) string  { return pick(s, []string{"0", "1", "100", "4096"}) }
func seconds(s *stream) string { return pick(s, []string{"0", "1", "60", "3600", "86400"}) }
func epochTime(s *stream) string {
	return pick(s, []string{"1700000000", "(time() + 3600)", "2000000000"})
}
func smallCount(s *stream) string { return strconv.Itoa(1 + s.intn(4)) }
func exitCode(s *stream) string   { return strconv.Itoa(s.intn(256)) }

func boolean(s *stream) string {
	return pick(s, []string{"true", "false", "True", "False", "1", "0", "yes", "no"})
}

func integer(s *stream) string {
	return pick(s, []string{"0", "1", "-1", "42", "2147483647", "-2147483648"})
}

func unsigned(s *stream) string {
	return pick(s, []string{"0", "1", "7", "4294967295"})
}

func str(s *stream) string {
	return pick(s, []string{"x", "a b", `"quoted"`, "with,comma", "UPPER", "a.b-c_d"})
}

func list(s *stream) string {
	return pick(s, []string{"a", "a, b", "a b c", "a,b , c", `"a, b"`})
}

func fileList(s *stream) string {
	return pick(s, []string{"a.txt", "a.txt, b.txt", "./sub/a.txt, /abs/b.txt",
		"dir/", "http://example.com/x.dat, a.txt"})
}

func path(s *stream) string {
	return pick(s, []string{"f.txt", "./f.txt", "/tmp/f.txt", "sub/f.txt", "out.$(Process)"})
}

func identifier(s *stream) string {
	return pick(s, []string{"group_a", "grp.sub", "user1", "Proj-1"})
}

func containerImage(s *stream) string {
	return pick(s, []string{"./img.sif", "docker://alpine:3.19", "/cvmfs/x/img.sif"})
}

func attrList(s *stream) string {
	return pick(s, []string{"JobStatus", "JobStatus, Owner", "Owner,ClusterId,ProcId"})
}

func environment(s *stream) string {
	return pick(s, []string{
		`"A=1 B=2"`,
		`"ONE=1 TWO='a b'"`,
		"A=1;B=2",
		`""`,
	})
}

func enum(vals ...string) func(*stream) string {
	return func(s *stream) string { return pick(s, vals) }
}

func quoted(v string) func(*stream) string {
	return func(*stream) string { return `"` + v + `"` }
}

// expr generates a small ClassAd expression. f_as_expr is the default type in
// the keyword table, so this is the most-used generator: periodic_*, on_exit_*,
// rank, the retry_* family and everything else with no type bit set.
func expr(s *stream) string {
	leaf := func() string {
		return pick(s, []string{"0", "1", "42", "true", "false", "undefined",
			"JobStatus", "ExitCode", "NumJobStarts", "RequestMemory",
			"MemoryUsage", `"str"`, "time()", "$(Process)", "$(ClusterId)"})
	}
	switch s.intn(6) {
	case 0:
		return leaf()
	case 1:
		return "(" + leaf() + " " + pick(s, []string{"==", "!=", ">", "<", ">=", "<=", "=?=", "=!="}) + " " + leaf() + ")"
	case 2:
		return "(" + leaf() + " " + pick(s, []string{"+", "-", "*", "/", "%"}) + " " + leaf() + ")"
	case 3:
		return "((" + leaf() + " > " + leaf() + ") " + pick(s, []string{"&&", "||"}) + " (" + leaf() + " < " + leaf() + "))"
	case 4:
		return "ifThenElse(" + leaf() + ", " + leaf() + ", " + leaf() + ")"
	default:
		return "!(" + leaf() + ")"
	}
}

// generatedCorpus is a fixed set of generator scripts. The bytes come from a
// counter run through a mixing step rather than a PRNG, so the corpus is the
// same on every machine and every Go version.
func generatedCorpus(n int) [][]byte {
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		x := uint64(i)*0x9e3779b97f4a7c15 + 0x6a09e667f3bcc909
		b := make([]byte, 8+i%48)
		for j := range b {
			x ^= x >> 30
			x *= 0xbf58476d1ce4e5b9
			x ^= x >> 27
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], x)
			b[j] = tmp[j%8]
		}
		out = append(out, b)
	}
	return out
}
