package fuzzsubmit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// hostDerived are attributes whose value comes from the clock, the machine or
// the account running the parse rather than from the submit file. The two sides
// cannot agree on them by construction -- the C++ oracle is pinned to a fixed
// submit time and user, and the Go parser reads the real clock -- so they are
// never compared. This list must stay SHORT and justified: every name here is a
// hole in the oracle.
var hostDerived = map[string]string{
	"qdate":                "submit time; the oracle is pinned to a fixed clock",
	"enteredcurrentstatus": "submit time",
	"condorversion":        "version of the binary that parsed the file",
	"condorplatform":       "platform of the binary that parsed the file",
	"submitversion":        "version of the binary that parsed the file",
	"filesystemdomain":     "the parsing host's FILESYSTEM_DOMAIN",
	"owner":                "the account running the parse",
	"user":                 "the account running the parse",
	"globaljobid":          "embeds the schedd name and submit time",
	// These four are computed by stat()ing the executable, which the oracle
	// deliberately does not do (setDisableFileChecks), so neither side has a
	// meaningful value to compare.
	"diskusage":           "stat of the executable",
	"executablesize":      "stat of the executable",
	"imagesize":           "stat of the executable",
	"transferinputsizemb": "stat of the input files",
}

// knownDivergent are attributes the two parsers genuinely disagree about today.
// Each entry is a finding, not an excuse: the reason says what the difference
// is, so the list reads as the inventory of Go/C++ submit drift. Removing an
// entry is how a fix gets locked in -- see TestKnownDivergencesStillDiverge,
// which fails when one of these starts agreeing.
var knownDivergent = map[string]string{
	"shouldtransferfiles": `C++ defaults to "IF_NEEDED", Go to "YES". Changes whether the job transfers files when it lands on a machine sharing a filesystem.`,
	"requirements":        `different expressions entirely: C++ pins TARGET.Arch/OpSys to the submitting machine's values and adds Disk and FileSystemDomain||HasFileTransfer clauses; Go emits "isnt undefined" for Arch/OpSys and adds a TARGET.Cpus clause.`,
	"rank":                `C++ emits the real 0.0, Go the integer 0. Same value, different ClassAd type.`,

	// Attributes only the C++ side produces. Most are per-job bookkeeping
	// counters the schedd would otherwise fill in, but several change behavior.
	"environment":              "C++ always sets it (empty when unspecified); Go omits it when the submit file says nothing.",
	"jobleaseduration":         "C++ sets JobLeaseDuration (2400 by default, from JOB_DEFAULT_LEASE_DURATION); Go omits it. A job ad with no lease tells the schedd not to hold the claim across a disconnect.",
	"jobprio":                  "C++ defaults JobPrio to 0; Go omits it.",
	"jobnotification":          "C++ defaults it; Go omits it.",
	"leavejobinqueue":          "C++ defaults it to false; Go omits it.",
	"mytype":                   `C++ sets MyType = "Job"; Go omits it.`,
	"targettype":               `C++ sets TargetType = "Machine"; Go omits it.`,
	"exitstatus":               "C++ defaults it to 0; Go omits it.",
	"exitbysignal":             "C++ defaults it to false; Go omits it.",
	"currenthosts":             "C++ defaults it to 0; Go omits it.",
	"jobsubmitmethod":          "C++ records how the job was submitted; Go omits it.",
	"numckpts":                 "C++ zeroes the checkpoint counters; Go omits them.",
	"numjobcompletions":        "C++ zeroes the completion counter; Go omits it.",
	"lastsuspensiontime":       "C++ zeroes the suspension counters; Go omits them.",
	"totalsuspensions":         "C++ zeroes the suspension counters; Go omits them.",
	"committedtime":            "C++ zeroes the accounting counters; Go omits them.",
	"committedslottime":        "C++ zeroes the accounting counters; Go omits them.",
	"committedsuspensiontime":  "C++ zeroes the accounting counters; Go omits them.",
	"cumulativeslottime":       "C++ zeroes the accounting counters; Go omits them.",
	"cumulativesuspensiontime": "C++ zeroes the accounting counters; Go omits them.",
	"cumulativeremotesyscpu":   "C++ zeroes the accounting counters; Go omits them.",
	"cumulativeremoteusercpu":  "C++ zeroes the accounting counters; Go omits them.",
	"remotesyscpu":             "C++ zeroes the accounting counters; Go omits them.",
	"remoteusercpu":            "C++ zeroes the accounting counters; Go omits them.",
	"remotewallclocktime":      "C++ zeroes the accounting counters; Go omits them.",

	"args":          `empty arguments: C++ emits Arguments (V2 syntax), Go emits Args (V1). The attribute NAME differs, which changes how the starter splits them.`,
	"arguments":     `the other half of the Args/Arguments naming split above.`,
	"requestcpus":   "when the submit file does not say, Go synthesizes RequestCpus=1; C++ sets nothing and lets the negotiator apply the pool default.",
	"requestmemory": "when the submit file does not say, Go synthesizes RequestMemory=128; C++ sets nothing.",

	// Attributes only the Go side produces.
	"transferexecutable": "Go always sets it; C++ only when the submit file asks.",
	"emailattributes":    "Go sets it; C++ has no such attribute here.",
	"jobruncount":        "Go sets it; C++ does not.",
	"requestdisk":        "C++ puts a MAX(...) expression on the cluster ad; Go emits its own value on the proc.",
	"requestgpumemory":   "Go turns request_gpu_memory into RequestGpuMemory; C++ lists request_gpu_memory as a disallowed keyword (f_error in prunable_keywords), warns that gpus_minimum_memory was probably meant, and sets no attribute.",
}

// knownDivergentGenerated is the inventory the keyword-table generator added
// (see gen.go). The hand-written seed corpus reached 17 of HTCondor's 258
// submit keywords; generating files from the keyword table reached most of the
// rest, and these are what the comparison found there. They are divided three
// ways by what the difference IS:
//
//   - the Go parser has no code for the keyword, so the setting is silently
//     dropped from the job;
//   - the Go parser writes the SUBMIT KEYWORD's name as the attribute name
//     where HTCondor writes the job attribute (VM_Memory vs JobVMMemory,
//     CronWindow vs DeferralWindow). The ad looks populated and nothing reads
//     it. Both halves of such a pair are listed, under each name;
//   - both sides write the attribute and the VALUES differ.
//
// Kept separate from knownDivergent above so the provenance of a finding stays
// visible; record() consults both.
//
// gosec flags this map for "hardcoded credentials": the keys are ClassAd
// attribute names, several of which are named after cloud credentials.
//
//nolint:gosec // G101: attribute names, not secrets
var knownDivergentGenerated = map[string]string{
	"allowedexecuteduration":            "the Go parser does not implement `allowed_execute_duration`: C++ sets this attribute, Go sets nothing.",
	"allowedjobduration":                "the Go parser does not implement `allowed_job_duration`: C++ sets this attribute, Go sets nothing.",
	"bufferblocksize":                   "the Go parser does not implement `buffer_block_size`: C++ sets this attribute, Go sets nothing.",
	"bufferfiles":                       "the Go parser does not implement `buffer_files`: C++ sets this attribute, Go sets nothing.",
	"buffersize":                        "the Go parser does not implement `buffer_size`: C++ sets this attribute, Go sets nothing.",
	"checkpointdestination":             "the Go parser does not implement `checkpoint_destination`: C++ sets this attribute, Go sets nothing.",
	"commoninputfiles":                  "the Go parser does not implement `transfer_common_input`: C++ sets this attribute, Go sets nothing.",
	"containerimage":                    "once C++ decides to transfer the image it rewrites ContainerImage to the image's basename, which is what the file transfer will put in the sandbox; Go stores the path as written, and in any universe, so the starter is told to run a path the sandbox does not have.",
	"containerimagefullpath":            "C++ keeps the submit-side path here when it rewrites ContainerImage to a basename; it is what late materialization reads to build each proc's input transfer list. Go sets nothing, so a transferred image has no record of where it came from.",
	"containerimagesource":              "C++ records where the container image comes from (local/docker/transfer); Go has no equivalent.",
	"containeriscommon":                 "the Go parser does not implement `container_is_common`: C++ sets this attribute, Go sets nothing.",
	"containerservicenames":             "Go sets ContainerServiceNames whatever the universe; C++ only honours `container_service_names` for a container job.",
	"coresize":                          "the Go parser does not implement `core_size`: C++ sets this attribute, Go sets nothing.",
	"cudaversion":                       "the Go parser does not implement `cuda_version`: C++ sets this attribute, Go sets nothing.",
	"dagmanjobid":                       "the Go parser does not implement `dagman_job_id`: C++ sets this attribute, Go sets nothing.",
	"dagmannodeslog":                    "the Go parser does not implement `dagman_log`: C++ sets this attribute, Go sets nothing.",
	"dagnodename":                       "the Go parser does not implement `dag_node_name`: C++ sets this attribute, Go sets nothing.",
	"delegatejobgsicredentialslifetime": "the Go parser does not implement `DelegateJobGSICredentialsLifetime`: C++ sets this attribute, Go sets nothing.",
	"dockerimage":                       "Go sets DockerImage whatever the universe; C++ only honours `docker_image` for a container or docker job.",
	"dockersendcredentials":             "the Go parser does not implement `docker_send_credentials`: C++ sets this attribute, Go sets nothing.",
	"dontencryptinputfiles":             "same verbatim-vs-canonicalized split as EncryptInputFiles.",
	"dontencryptoutputfiles":            "same verbatim-vs-canonicalized split as EncryptInputFiles.",
	"encryptexecutedirectory":           "the Go parser does not implement `encrypt_execute_directory`: C++ sets this attribute, Go sets nothing.",
	"encryptinputfiles":                 "C++ stores the f_as_string value verbatim; Go canonicalizes it by stripping the space after each comma. The inverse of the ConcurrencyLimits case.",
	"encryptoutputfiles":                "same verbatim-vs-canonicalized split as EncryptInputFiles.",
	"env":                               "empty-ish or V1 environments: Go emits Env (V1), C++ emits Environment (V2). The attribute NAME differs, which changes how the starter splits it -- the same split as Args/Arguments.",
	"eraseoutputanderroronrestart":      "the Go parser does not implement `erase_output_and_error_on_restart`: C++ sets this attribute, Go sets nothing.",
	"fileremaps":                        "C++ strips the surrounding quotes (f_strip_quotes); Go keeps them inside the string, so the stored remap text has literal quotes around it.",
	"gpusmaxcapability":                 "the Go parser does not implement `gpus_maximum_capability`: C++ sets this attribute, Go sets nothing.",
	"gpusmincapability":                 "the Go parser does not implement `gpus_minimum_capability`: C++ sets this attribute, Go sets nothing.",
	"gpusminmemory":                     "the Go parser does not implement `gpus_minimum_memory`: C++ sets this attribute, Go sets nothing.",
	"gpusminruntime":                    "the Go parser does not implement `gpus_minimum_runtime`: C++ sets this attribute, Go sets nothing.",
	"holdkillsig":                       "the Go parser does not implement `hold_kill_sig`: C++ sets this attribute, Go sets nothing.",
	"isnoopjob":                         "the Go parser does not implement `noop_job`: C++ sets this attribute, Go sets nothing.",
	"jarfiles":                          "the Go parser does not implement `jar_files`: C++ sets this attribute, Go sets nothing.",
	"javavmargs":                        "the Go parser does not implement `java_vm_args` / `java_vm_arguments`: C++ sets this attribute, Go sets nothing.",
	"javavmarguments":                   "C++ records the V2 spelling of the Java VM arguments as well; Go records neither form.",
	"jobbatchid":                        "the Go parser does not implement `batch_id`: C++ sets this attribute, Go sets nothing.",
	"jobleaseduration":                  "C++ raises a short `job_lease_duration` to its 20-second floor; Go stores whatever was written.",
	"jobrequiressandbox":                "C++ derives it from the transfer settings; Go does not.",
	"jobsetname":                        "the Go parser does not implement `jobset`: C++ sets this attribute, Go sets nothing.",
	"jobstarterdebug":                   "the Go parser does not implement `starter_debug`: C++ sets this attribute, Go sets nothing.",
	"jobstarterlog":                     "the Go parser does not implement `starter_log`: C++ sets this attribute, Go sets nothing.",
	"keepclaimidle":                     "the Go parser does not implement `keep_claim_idle`: C++ sets this attribute, Go sets nothing.",
	"killsig":                           "the Go parser does not implement `kill_sig`: C++ sets this attribute, Go sets nothing. C++ keeps the signal NAME as a string (SIGTERM); Go converts it to the number 15.",
	"lastmatchlistlength":               "the Go parser does not implement `match_list_length`: C++ sets this attribute, Go sets nothing.",
	"manifestdesired":                   "the Go parser does not implement `manifest`: C++ sets this attribute, Go sets nothing.",
	"manifestdir":                       "the Go parser does not implement `manifest_dir`: C++ sets this attribute, Go sets nothing.",
	"maxjobretirementtime":              "the Go parser does not implement `max_job_retirement_time`: C++ sets this attribute, Go sets nothing.",
	"mountunderscratch":                 "C++ keeps `mount_under_scratch` as the string it was given; Go coerces it to a boolean.",
	"nextjobstartdelay":                 "the Go parser does not implement `next_job_start_delay`: C++ sets this attribute, Go sets nothing.",
	"niceuser":                          "Go writes NiceUser even when `nice_user` is false; C++ omits it.",
	"noopjobexitcode":                   "the Go parser does not implement `noop_job_exit_code`: C++ sets this attribute, Go sets nothing.",
	"noopjobexitsignal":                 "the Go parser does not implement `noop_job_exit_signal`: C++ sets this attribute, Go sets nothing.",
	"onexitholdreason":                  "C++ strips the surrounding quotes; Go keeps them inside the string.",
	"onexitholdsubcode":                 "the Go parser does not implement `on_exit_hold_subcode`: C++ sets this attribute, Go sets nothing.",
	"outputdestination":                 "the Go parser does not implement `output_destination`: C++ sets this attribute, Go sets nothing.",
	"outputdirectory":                   "the Go parser does not implement `output_directory`: C++ sets this attribute, Go sets nothing.",
	"parallelscriptshadow":              "the Go parser does not implement `parallel_script_shadow`: C++ sets this attribute, Go sets nothing.",
	"parallelscriptstarter":             "the Go parser does not implement `parallel_script_starter`: C++ sets this attribute, Go sets nothing.",
	"periodicholdreason":                "C++ strips the surrounding quotes; Go keeps them inside the string.",
	"periodicholdsubcode":               "the Go parser does not implement `periodic_hold_subcode`: C++ sets this attribute, Go sets nothing.",
	"periodicvacate":                    "the Go parser does not implement `periodic_vacate`: C++ sets this attribute, Go sets nothing.",
	"primaryunixgroup":                  "the Go parser does not implement `primary_unix_group`: C++ sets this attribute, Go sets nothing.",
	"projectname":                       "the Go parser does not implement `project_name`: C++ sets this attribute, Go sets nothing.",
	"remote_gridresource":               "the Go parser does not implement `Remote_grid_resource`: C++ sets this attribute, Go sets nothing.",
	"remote_remote_gridresource":        "the Go parser does not implement `Remote_Remote_grid_resource`: C++ sets this attribute, Go sets nothing.",
	"removekillsig":                     "same name-vs-number conversion as KillSig.",
	"requiregpus":                       "C++ derives RequireGPUs from the gpus_minimum_*/gpus_maximum_* keywords; Go drops those keywords.",
	"scheddinterval":                    "a cron_* schedule makes C++ write ScheddInterval so the deferral clause of its generated Requirements can read it; Go generates neither that clause nor the attribute. Tied to the Requirements divergence above, not to the cron attributes, which now agree.",
	"scitokensfile":                     "the Go parser does not implement `scitokens_file`: C++ sets this attribute, Go sets nothing.",
	"skipifdataflow":                    "the Go parser does not implement `skip_if_dataflow`: C++ sets this attribute, Go sets nothing.",
	"stacksize":                         "the Go parser does not implement `stack_size`: C++ sets this attribute, Go sets nothing.",
	"streamerr":                         "the Go parser does not implement `stream_error`: C++ sets this attribute, Go sets nothing.",
	"streamin":                          "the Go parser does not implement `stream_input`: C++ sets this attribute, Go sets nothing.",
	"streamout":                         "the Go parser does not implement `stream_output`: C++ sets this attribute, Go sets nothing.",
	"submiteventnotes":                  "the Go parser does not implement `submit_event_notes`: C++ sets this attribute, Go sets nothing.",
	"submiteventnotesattrs":             "the Go parser does not implement `submit_event_notes_attrs`: C++ sets this attribute, Go sets nothing.",
	"submiteventusernotes":              "the Go parser does not implement `submit_event_user_notes`: C++ sets this attribute, Go sets nothing.",
	"suspendjobatexec":                  "the Go parser does not implement `suspend_job_at_exec`: C++ sets this attribute, Go sets nothing.",
	"tooldaemonargs":                    "the Go parser does not implement `tool_daemon_args` / `tool_daemon_arguments` / `tool_daemon_arguments2`: C++ sets this attribute, Go sets nothing.",
	"tooldaemoncmd":                     "the Go parser does not implement `tool_daemon_cmd`: C++ sets this attribute, Go sets nothing.",
	"tooldaemonerror":                   "the Go parser does not implement `tool_daemon_error`: C++ sets this attribute, Go sets nothing.",
	"tooldaemoninput":                   "the Go parser does not implement `tool_daemon_input`: C++ sets this attribute, Go sets nothing.",
	"tooldaemonoutput":                  "the Go parser does not implement `tool_daemon_output`: C++ sets this attribute, Go sets nothing.",
	"transfercheckpoint":                "the Go parser does not implement `transfer_checkpoint_files`: C++ sets this attribute, Go sets nothing.",
	"transfercontainer":                 "the Go parser does not implement `transfer_container`: C++ sets this attribute, Go sets nothing.",
	"transfererr":                       "`stream_error`/`transfer_error`: same disagreement as TransferIn.",
	"transferin":                        "`stream_input`/`transfer_input`: C++ and Go disagree on the boolean, so one of them streams stdin and the other transfers it.",
	"transferinput":                     "the Go parser drops most of the keywords that feed TransferInput, and where it does write it, a filename containing a space is split away rather than kept as one entry.",
	"transferout":                       "`stream_output`/`transfer_output`: same disagreement as TransferIn.",
	"transferoutput":                    "the Go parser does not implement `TransferOutputFiles` / `transfer_output_files`: C++ sets this attribute, Go sets nothing.",
	"transferoutputremaps":              "C++ keeps the remap string verbatim; Go rewrites it, dropping the spaces around = and ;.",
	"transformonevict":                  "the Go parser does not implement `on_evict_checks`, the other writer of this attribute, so it cannot be compared file by file. What the memory retry family writes to it IS checked against the oracle, in TestOnEvictMemoryTransformMatchesOracle.",
	"userlogexecuteeventattrs":          "the Go parser does not implement `ulog_execute_attrs`: C++ sets this attribute, Go sets nothing.",
	"userlogusexml":                     "the Go parser does not implement `log_xml`: C++ sets this attribute, Go sets nothing.",
	"wantftoncheckpoint":                "when_to_transfer_output = ON_SUCCESS makes C++ set WantFTOnCheckpoint and rewrite WhenToTransferOutput to ON_EXIT; Go stores ON_SUCCESS and sets nothing else.",
	"wantgracefulremoval":               "an undefined expression stays undefined in C++; Go coerces it to false.",
	"wantioproxy":                       "the Go parser does not implement `want_io_proxy`: C++ sets this attribute, Go sets nothing.",
	"wantjobnetworking":                 "the Go parser does not implement `want_job_networking`: C++ sets this attribute, Go sets nothing.",
	"wantparallelscheduling":            "the Go parser does not implement `WantParallelScheduling`: C++ sets this attribute, Go sets nothing.",
	"wanttransferpluginmethods":         "C++ derives the plugin method list from transfer_plugins; Go stores only TransferPlugins.",
	"whentotransferoutput":              "Go always writes WhenToTransferOutput, including when `should_transfer_files = NO` leaves C++ with none, and keeps ON_SUCCESS where C++ rewrites it to ON_EXIT.",
}

// knownDivergentPrefix covers families of attributes whose names are not fixed,
// so they cannot be listed by name. Checked after knownDivergent.
//
// Empty: the one family that was here, Request<Tag> from a generic
// request_<tag> command, now agrees. Keeping the entry would have gone on
// excusing every Request* attribute the Go side failed to produce, which is
// the whole class of bug the fix was for.
var knownDivergentPrefix = []struct {
	prefix string
	reason string
}{}

// Divergence is one attribute the two sides disagree about.
type Divergence struct {
	Ad   AdKey
	Attr string
	Cpp  string // "" when absent
	Go   string // "" when absent
	Kind string // "only-cpp", "only-go" or "value"
}

func (d Divergence) String() string {
	switch d.Kind {
	case "only-cpp":
		return fmt.Sprintf("%s %s: only C++ has it (=%s)", d.Ad, d.Attr, d.Cpp)
	case "only-go":
		return fmt.Sprintf("%s %s: only Go has it (=%s)", d.Ad, d.Attr, d.Go)
	default:
		return fmt.Sprintf("%s %s: cpp=%s go=%s", d.Ad, d.Attr, d.Cpp, d.Go)
	}
}

// Compare returns the divergences between the two sides that are neither
// host-derived nor already known, plus the subset of known ones that showed up
// (so a test can tell when a known divergence has been FIXED).
//
// Only ads both sides produced are compared attribute by attribute; a missing
// ad is reported on its own, since comparing its attributes would bury the
// bigger fact that one side made a different number of jobs.
func Compare(cpp, goAds Ads) (fresh []Divergence, seenKnown map[string]bool) {
	seenKnown = make(map[string]bool)

	cppKeys, goKeys := cpp.Keys(), goAds.Keys()
	if len(cppKeys) != len(goKeys) {
		return []Divergence{{
			Attr: "#procs",
			Kind: "value",
			Cpp:  fmt.Sprint(adKeyList(cppKeys)),
			Go:   fmt.Sprint(adKeyList(goKeys)),
		}}, seenKnown
	}

	for _, key := range cppKeys {
		c := cpp.ByKey[key]
		g, ok := goAds.ByKey[key]
		if !ok {
			fresh = append(fresh, Divergence{Ad: key, Attr: "#ad", Kind: "only-cpp"})
			continue
		}
		// The universe comes from the C++ ad: it is the side that decides
		// what the universe means, and a Go bug that drops JobUniverse must
		// not also hand itself an excuse.
		universe, _ := universeOf(c)

		for _, n := range namesFold(c) {
			cv, _ := lookupFold(c, n)
			gv, present := lookupFold(g, n)
			switch {
			case !present:
				record(&fresh, seenKnown, universe, Divergence{Ad: key, Attr: n, Cpp: cv, Kind: "only-cpp"})
			case !sameValue(cv, gv):
				record(&fresh, seenKnown, universe, Divergence{Ad: key, Attr: n, Cpp: cv, Go: gv, Kind: "value"})
			}
		}
		for _, n := range namesFold(g) {
			if _, present := lookupFold(c, n); !present {
				gv, _ := lookupFold(g, n)
				record(&fresh, seenKnown, universe, Divergence{Ad: key, Attr: n, Go: gv, Kind: "only-go"})
			}
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].String() < fresh[j].String() })
	return fresh, seenKnown
}

// knownDivergentInUniverse excuses an attribute only inside one job universe.
//
// It exists so a quirk of a single universe cannot excuse that attribute
// everywhere. Putting "cmd" in knownDivergent would have undone the Cmd/UserLog
// path comparison, which is the whole point of having it compared.
var knownDivergentInUniverse = map[int]map[string]string{
	universeJava: {
		"cmd": "for universe = java C++ replaces Cmd with the JVM from param(\"JAVA\") and passes the submitted class through Args; Go leaves the resolved executable in Cmd, so the job would run the class file instead of a JVM.",
	},
}

// universeJava is CONDOR_UNIVERSE_JAVA (condor_includes/condor_universe.h).
const universeJava = 10

// universeOf reports the JobUniverse an ad resolves to. The attribute is an
// integer literal in both parsers' output, so no evaluation is needed.
func universeOf(attrs map[string]string) (int, bool) {
	v, ok := lookupFold(attrs, "JobUniverse")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

func record(fresh *[]Divergence, seenKnown map[string]bool, universe int, d Divergence) {
	attr := strings.ToLower(d.Attr)
	if byAttr, ok := knownDivergentInUniverse[universe]; ok {
		if _, known := byAttr[attr]; known {
			seenKnown[attr] = true
			return
		}
	}
	if _, skip := hostDerived[attr]; skip {
		return
	}
	if _, known := knownDivergent[attr]; known {
		seenKnown[attr] = true
		return
	}
	if _, known := knownDivergentGenerated[attr]; known {
		seenKnown[attr] = true
		return
	}
	// Prefix families only excuse an attribute the Go side never produced. If
	// both sides produce one and the VALUES differ, that is a fresh finding
	// about an attribute Go does understand, and it must not be swallowed here.
	if d.Kind == "only-cpp" {
		for _, kp := range knownDivergentPrefix {
			if strings.HasPrefix(attr, kp.prefix) {
				seenKnown[kp.prefix+"*"] = true
				return
			}
		}
	}
	*fresh = append(*fresh, d)
}

func adKeyList(keys []AdKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.String())
	}
	return out
}
