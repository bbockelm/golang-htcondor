package dagman

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultDagmanPath is where condor_dagman lives in a package install.
//
// condor_submit_dag resolves this with which() on the submitting machine,
// which is not available to us: this server submits to a schedd it does
// not share a filesystem with. The RPM installs it under %_bindir and the
// Debian package under usr/bin, so this is right for a packaged access
// point and wrong for a tarball or a relocated install -- which is what
// SubmitOptions.BinDir is for. Operators can still override DagmanPath
// outright.
const DefaultDagmanPath = "/usr/bin/condor_dagman"

// DefaultDagmanPATH is the PATH given to DAGMan, and through it to every
// PRE/POST script.
//
// condor_submit_dag solves this with `getenv = PATH,...`, which cannot
// work here twice over: getenv captures the SUBMITTING process's
// environment, and this server's environment is a container somewhere
// else, not the access point's. The schedd gives a scheduler-universe job
// only what the job ad carries (Scheduler::start_sched_universe_job
// merges the ad's Env and adds nothing from its own), so an unset PATH
// means scripts fail with ENOENT on their first command.
//
// CONDOR_CONFIG is deliberately NOT set: unset, DAGMan finds the access
// point's own configuration in the usual place, which is what a remote
// submitter wants. A site whose access point keeps it elsewhere sets
// ExtraEnv.
//
// HOME, USER and TZ are NOT set either, and deliberately cannot be: the
// schedd gives a scheduler-universe job only what the job ad carries, and
// this server has no way to know the owner's home directory or login name
// on an access point it does not share a filesystem with. Guessing would
// be worse than leaving them unset -- a wrong HOME sends every tool's
// dot-file lookup somewhere that is not the user's. PRE/POST scripts must
// therefore not rely on HOME, USER or TZ; a script that needs one has to
// be given it through ExtraEnv or work it out itself.
//
// /usr/sbin is deliberately absent: every HTCondor tool a script would
// call installs to bindir.
const DefaultDagmanPATH = "/usr/bin:/bin:/usr/local/bin"

// SubmitOptions is what varies between one DAGMan submission and another.
type SubmitOptions struct {
	// DagName is the DAG description file, as it will be named in the
	// spool directory.
	DagName string
	// DagmanPath is the access point's condor_dagman. Defaults to
	// BinDir + "/condor_dagman" when BinDir is set, and to
	// DefaultDagmanPath otherwise.
	DagmanPath string
	// BinDir is the access point's $(BIN), discovered by the caller by
	// asking the schedd for it (DC_CONFIG_VAL "BIN"). It is what makes a
	// tarball or relocated install work without an operator setting
	// anything: it supplies both condor_dagman's directory and the front
	// of DAGMan's PATH, so PRE/POST scripts find condor_submit and the
	// rest of the tools from the same install DAGMan came from.
	//
	// DefaultDagmanPath remains the fallback for a packaged install (RPM
	// %_bindir, Debian usr/bin). An explicit DagmanPath wins over both.
	BinDir string
	// CondorVersion is the version string handed to DAGMan as
	// -CsdVersion, and it is OPTIONAL.
	//
	// It must be the ACCESS POINT's version if it is given at all.
	// Passing this library's own compatibility version is a false claim
	// about the AP: DAGMan compares it against its own binary, and a site
	// running DAGMAN_USE_STRICT = 3 treats any mismatch as fatal.
	//
	// Left empty, no -CsdVersion is passed and DAGMan initialises
	// csdVersion to its OWN version (dagman_main.cpp), which is exactly
	// the right answer when we do not know the AP's. Only a SUPPLIED
	// value that DAGMan cannot parse is fatal.
	CondorVersion string
	// InputFiles is transfer_input_files for the manager job: the DAG,
	// the node submit descriptions, the scripts, and every node's own
	// inputs. Computed by Analyze rather than supplied by hand, because
	// a file missing from this list is silently dropped at spool time.
	InputFiles []string
	// BatchName sets JobBatchName, which is how the workflow shows up in
	// condor_q -batch.
	BatchName string
	// MaxIdle, MaxJobs, MaxPre, MaxPost throttle DAGMan. Zero means
	// unset.
	MaxIdle, MaxJobs, MaxPre, MaxPost int
	// DisablePort mirrors the access point's DAGMAN_DISABLE_PORT. When
	// set, DAGMan is started with "-p 0" and the job ad does NOT carry
	// IsDaemonCore, so the schedd sets up no command socket. A site that
	// configures DAGMAN_DISABLE_PORT and gets a submit file that asks for
	// a port anyway ends up with a DAGMan that cannot be reached and a
	// schedd that thinks it can.
	DisablePort bool
	// ConfigFile is a per-DAG DAGMan configuration file, as named in the
	// spool directory. It is passed through _CONDOR_DAGMAN_CONFIG_FILE,
	// which is the ONLY way DAGMan reads one (dagman_utils.cpp): a DAG's
	// own CONFIG line is parsed by condor_submit_dag, not by DAGMan, so a
	// workflow whose CONFIG file is merely transferred is silently
	// ignored.
	ConfigFile string
	// ExtraEnv is additional environment for DAGMan itself, merged into
	// the environment line (HTTP_API_DAGMAN_ENVIRONMENT). An access point
	// whose configuration is not in the default place needs CONDOR_CONFIG
	// here; a site whose scripts need credentials needs
	// BEARER_TOKEN_FILE.
	ExtraEnv map[string]string
	// Append is extra submit-file text, inserted before queue.
	Append string
}

// SubmitFile builds the scheduler-universe submit file that runs one
// DAGMan instance, the same job condor_submit_dag would have written.
//
// Three lines differ from what condor_submit_dag generates, all because
// this submission is remote and spooled:
//
//   - transfer_executable = false. This is load-bearing. The schedd
//     rewrites a spooled job's file paths to basenames, but skips the
//     executable when this is false (qmgmt.cpp, rewriteSpooledJobAd), so
//     condor_dagman keeps its absolute path while everything else
//     collapses into the spool directory.
//   - should_transfer_files / when_to_transfer_output are explicit, so
//     the spooling path is taken.
//   - every file name is a basename. The spool directory is flat, and
//     DAGMan runs with its working directory set there, so relative
//     names in the DAG resolve correctly and absolute ones would not.
func SubmitFile(opt SubmitOptions) (string, error) {
	if strings.TrimSpace(opt.DagName) == "" {
		return "", fmt.Errorf("DagName is required")
	}
	if strings.ContainsAny(opt.DagName, "/\\") {
		return "", fmt.Errorf("DagName %q must be a bare file name: the spool directory is flat", opt.DagName)
	}
	binDir := strings.TrimRight(strings.TrimSpace(opt.BinDir), "/")
	exe := opt.DagmanPath
	if exe == "" {
		if binDir != "" {
			exe = binDir + "/condor_dagman"
		} else {
			exe = DefaultDagmanPath
		}
	}
	path := DefaultDagmanPATH
	if binDir != "" {
		path = binDir + ":" + DefaultDagmanPATH
	}

	base := strings.TrimSuffix(opt.DagName, ".dag")
	var b strings.Builder
	p := func(format string, args ...interface{}) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	p("# Generated by the HTCondor API server for %s", opt.DagName)
	p("universe    = scheduler")
	p("executable  = %s", exe)
	p("transfer_executable = false")
	p("output      = %s.lib.out", base)
	p("error       = %s.lib.err", base)
	p("log         = %s.dagman.log", base)
	p("remove_kill_sig = SIGUSR1")

	// Removing the DAGMan job removes the node jobs it submitted.
	// $(Cluster), not condor_submit_dag's $(cluster): macro names are
	// case-insensitive in HTCondor, but this submit file is expanded by
	// this project's own submit library, and the capitalised spelling is
	// the one every version of it resolves.
	p(`My.OtherJobRemoveRequirements = "DAGManJobId =?= $(Cluster)"`)
	// Ask the schedd for a command port, so condor_dagman can be talked
	// to (halt, and the tools that query a running DAG). This is
	// condor_submit_dag's default; an access point that sets
	// DAGMAN_DISABLE_PORT wants the opposite, which the caller passes as
	// DisablePort.
	if !opt.DisablePort {
		p("My.IsDaemonCore = True")
	}

	// Requeue DAGMan if it dies abnormally or the access point reboots,
	// rather than losing a part-finished workflow.
	p("on_exit_remove = (ExitSignal =?= 11 || (ExitCode =!= UNDEFINED && ExitCode >= 0 && ExitCode <= 2))")

	if opt.BatchName != "" {
		p(`My.JobBatchName = %s`, quote(opt.BatchName))
	}

	// -p 0 runs DAGMan without a command socket, and has to come before
	// the other DaemonCore arguments, as condor_submit_dag writes it.
	var args []string
	if opt.DisablePort {
		args = append(args, "-p", "0")
	}
	args = append(args, "-f", "-l", ".")
	args = append(args, "-Lockfile", base+".dag.lock")
	args = append(args, "-Dag", opt.DagName)
	if opt.MaxIdle > 0 {
		args = append(args, "-MaxIdle", fmt.Sprint(opt.MaxIdle))
	}
	if opt.MaxJobs > 0 {
		args = append(args, "-MaxJobs", fmt.Sprint(opt.MaxJobs))
	}
	if opt.MaxPre > 0 {
		args = append(args, "-MaxPre", fmt.Sprint(opt.MaxPre))
	}
	if opt.MaxPost > 0 {
		args = append(args, "-MaxPost", fmt.Sprint(opt.MaxPost))
	}
	if opt.CondorVersion != "" {
		args = append(args, "-CsdVersion", opt.CondorVersion)
	}
	p("arguments = %s", argsV2(args))

	env := map[string]string{
		"_CONDOR_DAGMAN_LOG":     base + ".dagman.out",
		"_CONDOR_MAX_DAGMAN_LOG": "0",
		"PATH":                   path,
	}
	if opt.ConfigFile != "" {
		env["_CONDOR_DAGMAN_CONFIG_FILE"] = opt.ConfigFile
	}
	for k, v := range opt.ExtraEnv {
		env[k] = v
	}
	p("environment = %s", envString(env))

	p("should_transfer_files = YES")
	p("when_to_transfer_output = ON_EXIT")
	if len(opt.InputFiles) > 0 {
		files := append([]string(nil), opt.InputFiles...)
		sort.Strings(files)
		p("transfer_input_files = %s", strings.Join(files, ","))
	}

	if strings.TrimSpace(opt.Append) != "" {
		p("%s", strings.TrimRight(opt.Append, "\n"))
	}
	p("queue")
	return b.String(), nil
}

// argsV2 renders an argument list in submit-file "new syntax": the whole
// list in double quotes, each argument single-quoted if it contains
// whitespace, with doubled quotes to escape.
func argsV2(args []string) string {
	var parts []string
	for _, a := range args {
		a = strings.ReplaceAll(a, `"`, `""`)
		if strings.ContainsAny(a, " \t") {
			a = "'" + strings.ReplaceAll(a, "'", "''") + "'"
		}
		parts = append(parts, a)
	}
	return `"` + strings.Join(parts, " ") + `"`
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// envString renders an environment in submit-file "new syntax": the whole
// set in double quotes, space separated, with a value containing spaces
// wrapped in single quotes. Sorted, so the same inputs always produce the
// same submit file.
func envString(env map[string]string) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := strings.ReplaceAll(env[k], `"`, `""`)
		if strings.ContainsAny(v, " \t") {
			v = "'" + strings.ReplaceAll(v, "'", "''") + "'"
		}
		parts = append(parts, k+"="+v)
	}
	return `"` + strings.Join(parts, " ") + `"`
}
