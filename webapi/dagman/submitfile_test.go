package dagman

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

func TestSubmitFileShape(t *testing.T) {
	got, err := SubmitFile(SubmitOptions{
		DagName:       "wf.dag",
		CondorVersion: "$CondorVersion: 25.4.0 BuildID: test $",
		InputFiles:    []string{"wf.dag", "a.sub"},
		BatchName:     "my workflow",
		MaxIdle:       10,
	})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}

	for _, want := range []string{
		// DAGMan is a scheduler-universe job: it runs on the access point,
		// not on an execute node.
		"universe    = scheduler",
		// Load-bearing. The schedd rewrites a spooled job's file paths to
		// basenames but skips the executable when this is false, which is
		// what lets condor_dagman keep its absolute path while the
		// workflow collapses into the spool directory.
		"transfer_executable = false",
		// Without this the spooling path is not taken and Iwd is never
		// rewritten to the spool directory, so DAGMan starts somewhere the
		// workflow is not.
		"should_transfer_files = YES",
		// Removing the DAGMan job has to remove the node jobs too.
		"DAGManJobId =?= $(Cluster)",
		"-Dag wf.dag",
		"-Lockfile wf.dag.lock",
		"-MaxIdle 10",
		"transfer_input_files = a.sub,wf.dag",
		"queue",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("submit file is missing %q:\n%s", want, got)
		}
	}

	if !strings.Contains(got, `My.JobBatchName = "my workflow"`) {
		t.Errorf("batch name not set:\n%s", got)
	}
}

// TestSubmitFileVersionIsOptional pins the version argument's contract.
//
// -CsdVersion must be the ACCESS POINT's version. We usually do not know it,
// and passing this library's own compatibility version instead is a false
// claim that a site running DAGMAN_USE_STRICT = 3 treats as fatal. Omitted
// entirely, DAGMan initialises csdVersion to its own version
// (dagman_main.cpp), which is the right answer -- only a SUPPLIED value it
// cannot parse is fatal.
func TestSubmitFileVersionIsOptional(t *testing.T) {
	got, err := SubmitFile(SubmitOptions{DagName: "wf.dag"})
	if err != nil {
		t.Fatalf("SubmitFile with no CondorVersion: %v", err)
	}
	if strings.Contains(got, "-CsdVersion") {
		t.Errorf("an empty CondorVersion still emitted -CsdVersion:\n%s", got)
	}

	got, err = SubmitFile(SubmitOptions{DagName: "wf.dag", CondorVersion: "$CondorVersion: 25.4.0 BuildID: test $"})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	if n := strings.Count(got, "-CsdVersion"); n != 1 {
		t.Errorf("-CsdVersion appears %d times, want 1:\n%s", n, got)
	}
	// The version string contains spaces, so it has to survive argument
	// quoting as ONE argument or DAGMan reads a truncated version.
	if !strings.Contains(got, "-CsdVersion '$CondorVersion: 25.4.0 BuildID: test $'") {
		t.Errorf("the -CsdVersion argument was not quoted as one argument:\n%s", got)
	}
}

// TestSubmitFileDisablePort covers an access point configured with
// DAGMAN_DISABLE_PORT. condor_submit_dag then passes "-p 0" AND omits
// My.IsDaemonCore; doing one without the other leaves a schedd expecting a
// command socket that DAGMan never opens.
func TestSubmitFileDisablePort(t *testing.T) {
	on, err := SubmitFile(SubmitOptions{DagName: "wf.dag", DisablePort: true})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	if !strings.Contains(on, "-p 0 -f -l .") {
		t.Errorf("DisablePort did not put -p 0 before the other DaemonCore arguments:\n%s", on)
	}
	if strings.Contains(on, "IsDaemonCore") {
		t.Errorf("DisablePort still asked the schedd for a command port:\n%s", on)
	}

	off, err := SubmitFile(SubmitOptions{DagName: "wf.dag"})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	if strings.Contains(off, "-p 0") {
		t.Errorf("-p 0 emitted without DisablePort:\n%s", off)
	}
	if !strings.Contains(off, "My.IsDaemonCore = True") {
		t.Errorf("the default lost its command port:\n%s", off)
	}
}

// TestSubmitFileConfigFile pins the only channel a per-DAG DAGMan config
// has. DAGMan reads it from _CONDOR_DAGMAN_CONFIG_FILE and nowhere else: a
// DAG's own CONFIG line is interpreted by condor_submit_dag, so a config
// file that is merely transferred into the spool is silently ignored.
func TestSubmitFileConfigFile(t *testing.T) {
	got, err := SubmitFile(SubmitOptions{DagName: "wf.dag", ConfigFile: "wf.dag.config"})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	if !strings.Contains(got, "_CONDOR_DAGMAN_CONFIG_FILE=wf.dag.config") {
		t.Errorf("ConfigFile did not reach the environment:\n%s", got)
	}

	none, err := SubmitFile(SubmitOptions{DagName: "wf.dag"})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	if strings.Contains(none, "_CONDOR_DAGMAN_CONFIG_FILE") {
		t.Errorf("an empty ConfigFile was emitted anyway:\n%s", none)
	}
}

// TestSubmitFileBinDir covers the access point's $(BIN), which the caller
// learns from the schedd. It has to supply both condor_dagman's location and
// the front of DAGMan's PATH, so PRE/POST scripts find condor_submit from
// the same install DAGMan came from -- and an explicit DagmanPath still wins.
func TestSubmitFileBinDir(t *testing.T) {
	t.Run("bindir supplies both", func(t *testing.T) {
		got, err := SubmitFile(SubmitOptions{DagName: "wf.dag", BinDir: "/opt/condor/bin"})
		if err != nil {
			t.Fatalf("SubmitFile: %v", err)
		}
		if !strings.Contains(got, "executable  = /opt/condor/bin/condor_dagman") {
			t.Errorf("BinDir did not locate condor_dagman:\n%s", got)
		}
		if !strings.Contains(got, "PATH=/opt/condor/bin:"+DefaultDagmanPATH) {
			t.Errorf("BinDir was not prepended to PATH:\n%s", got)
		}
	})
	t.Run("explicit path wins", func(t *testing.T) {
		got, err := SubmitFile(SubmitOptions{
			DagName:    "wf.dag",
			BinDir:     "/opt/condor/bin",
			DagmanPath: "/usr/local/libexec/condor_dagman",
		})
		if err != nil {
			t.Fatalf("SubmitFile: %v", err)
		}
		if !strings.Contains(got, "executable  = /usr/local/libexec/condor_dagman") {
			t.Errorf("an explicit DagmanPath was overridden by BinDir:\n%s", got)
		}
		if !strings.Contains(got, "PATH=/opt/condor/bin:"+DefaultDagmanPATH) {
			t.Errorf("BinDir should still lead PATH:\n%s", got)
		}
	})
	t.Run("no bindir", func(t *testing.T) {
		got, err := SubmitFile(SubmitOptions{DagName: "wf.dag"})
		if err != nil {
			t.Fatalf("SubmitFile: %v", err)
		}
		if !strings.Contains(got, "executable  = "+DefaultDagmanPath) {
			t.Errorf("packaged-install fallback lost:\n%s", got)
		}
		if !strings.Contains(got, "PATH="+DefaultDagmanPATH+" ") && !strings.Contains(got, "PATH="+DefaultDagmanPATH+`"`) {
			t.Errorf("default PATH lost:\n%s", got)
		}
	})
}

func TestSubmitFileRejectsAPathDagName(t *testing.T) {
	// The spool directory is flat. A name with a directory in it would be
	// rewritten to its basename by the schedd, and the -Dag argument would
	// then point somewhere that does not exist.
	_, err := SubmitFile(SubmitOptions{DagName: "sub/wf.dag", CondorVersion: "v"})
	if err == nil {
		t.Fatal("SubmitFile accepted a DagName with a directory")
	}
	if !strings.Contains(err.Error(), "flat") {
		t.Errorf("error does not explain why: %v", err)
	}
}

func TestSubmitFileOmitsUnsetThrottles(t *testing.T) {
	got, err := SubmitFile(SubmitOptions{DagName: "wf.dag", CondorVersion: "v"})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	for _, unwanted := range []string{"-MaxIdle", "-MaxJobs", "-MaxPre", "-MaxPost", "JobBatchName"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("unset option %q was emitted anyway:\n%s", unwanted, got)
		}
	}
}

// TestSubmitFileProducesACorrectJobAd checks the generated submit file the
// way the schedd sees it: as a job ad.
//
// Every other test here string-matches the submit text, which is why two
// real bugs survived them. The submit text said
// `DAGManJobId =?= $(cluster)` and the ad held `DAGManJobId =?= `, because
// macro expansion was case-sensitive; the submit text said
// `on_exit_remove = (...)` and the ad held that text as a STRING, which the
// policy evaluator does not treat as a boolean, so DAGMan was removed
// instead of requeued. Neither is visible above the ad.
// dagmanJobAd builds the submit file for opt and hands back the job ad the
// schedd would actually receive, which is the only place the bugs below are
// visible.
func dagmanJobAd(t *testing.T, opt SubmitOptions) *classad.ClassAd {
	t.Helper()
	text, err := SubmitFile(opt)
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	sf, err := htcondor.ParseSubmitFile(strings.NewReader(text))
	if err != nil {
		t.Fatalf("the generated submit file does not parse: %v\n%s", err, text)
	}
	res, err := sf.Submit(42)
	if err != nil {
		t.Fatalf("Submit: %v\n%s", err, text)
	}
	if len(res.ProcAds) != 1 {
		t.Fatalf("got %d procs, want 1\n%s", len(res.ProcAds), text)
	}
	return res.ProcAds[0]
}

func testSubmitOptions() SubmitOptions {
	return SubmitOptions{
		DagName:       "wf.dag",
		CondorVersion: "$CondorVersion: 25.4.0 BuildID: test $",
		InputFiles:    []string{"wf.dag", "a.sub"},
		BatchName:     "my workflow",
	}
}

func TestSubmitFileProducesACorrectJobAd(t *testing.T) {
	ad := dagmanJobAd(t, testSubmitOptions())

	if u, ok := ad.EvaluateAttrInt("JobUniverse"); !ok || u != 7 {
		t.Errorf("JobUniverse = %v (ok=%v), want 7 (scheduler)", u, ok)
	}

	// The macro has to have expanded, and the attribute is a STRING here:
	// the schedd parses its text when the DAGMan job is removed
	// (Scheduler::removeOtherJobs).
	if s, ok := ad.EvaluateAttrString("OtherJobRemoveRequirements"); !ok {
		expr, _ := ad.Lookup("OtherJobRemoveRequirements")
		t.Errorf("OtherJobRemoveRequirements is not a string: %v", expr)
	} else if s != "DAGManJobId =?= 42" {
		t.Errorf("OtherJobRemoveRequirements = %q, want %q: the cluster macro did not expand",
			s, "DAGManJobId =?= 42")
	}

	// on_exit_remove is what requeues DAGMan after an abnormal exit. It
	// must be an expression; as a string the policy evaluator
	// (user_job_policy.cpp) does not see a number and falls through to
	// REMOVE.
	expr, ok := ad.Lookup("OnExitRemove")
	if !ok {
		t.Fatal("OnExitRemove is missing")
	}
	if strings.HasPrefix(expr.String(), `"`) {
		t.Errorf("OnExitRemove = %s: stored as a string literal", expr)
	}
	if _, isString := ad.EvaluateAttrString("OnExitRemove"); isString {
		t.Error("OnExitRemove evaluates to a string, not a boolean")
	}
	_ = ad.Set("ExitCode", int64(1))
	if v, isBool := ad.EvaluateAttrBool("OnExitRemove"); !isBool {
		t.Error("OnExitRemove does not evaluate to a boolean given an ExitCode")
	} else if !v {
		t.Error("OnExitRemove is false for a normal exit code: DAGMan would be requeued forever")
	}

	if v, ok := ad.EvaluateAttrBool("IsDaemonCore"); !ok || !v {
		t.Errorf("IsDaemonCore = %v (ok=%v), want true: DAGMan gets no command socket", v, ok)
	}
}

// TestSubmitFileJobAdEnvironmentAndArguments is the rest of the ad-level
// check: the two attributes whose submit-file spelling is quoted and whose ad
// value must not be.
func TestSubmitFileJobAdEnvironmentAndArguments(t *testing.T) {
	ad := dagmanJobAd(t, testSubmitOptions())

	// The environment reaches the ad as its contents, not as the quoted
	// submit-file rendering: a leading double quote would become part of
	// the first variable's name.
	env, ok := ad.EvaluateAttrString("Environment")
	if !ok {
		e, _ := ad.Lookup("Environment")
		t.Fatalf("Environment is not a string: %v", e)
	}
	if strings.HasPrefix(env, `"`) || strings.HasSuffix(env, `"`) {
		t.Errorf("Environment kept its submit-file quoting: %q", env)
	}
	if !strings.Contains(env, "_CONDOR_DAGMAN_LOG=wf.dagman.out") {
		t.Errorf("Environment = %q, missing _CONDOR_DAGMAN_LOG", env)
	}

	// The schedd rewrites a spooled job's file paths to basenames but
	// skips the executable when transfer_executable is false, which is
	// what lets condor_dagman keep its absolute path.
	if v, ok := ad.EvaluateAttrBool("TransferExecutable"); !ok || v {
		t.Errorf("TransferExecutable = %v (ok=%v), want false", v, ok)
	}
	if cmd, ok := ad.EvaluateAttrString("Cmd"); !ok || cmd != DefaultDagmanPath {
		t.Errorf("Cmd = %q (ok=%v), want %q", cmd, ok, DefaultDagmanPath)
	}

	// -CsdVersion survived argument quoting as exactly one value.
	args, ok := ad.EvaluateAttrString("Arguments")
	if !ok {
		args, ok = ad.EvaluateAttrString("Args")
	}
	if !ok {
		t.Fatal("job ad has neither Arguments nor Args")
	}
	tokens := splitArgsV2(args)
	var versions []string
	for i, tok := range tokens {
		if tok == "-CsdVersion" && i+1 < len(tokens) {
			versions = append(versions, tokens[i+1])
		}
	}
	if len(versions) != 1 {
		t.Fatalf("Arguments = %q parsed to %q: want exactly one -CsdVersion value, got %d",
			args, tokens, len(versions))
	}
	if versions[0] != "$CondorVersion: 25.4.0 BuildID: test $" {
		t.Errorf("-CsdVersion = %q: the version was truncated by argument quoting (Arguments = %q)",
			versions[0], args)
	}
}

// splitArgsV2 undoes HTCondor's "new syntax" argument quoting: arguments are
// separated by whitespace outside single quotes, whitespace inside them is
// literal, and a doubled single quote is one literal quote. The library is
// free to quote a single embedded space rather than the whole argument
// (`a:' '$b` and `'a: $b'` are the same one argument), so the tokens are what
// this test can assert on, not the rendered text.
func splitArgsV2(s string) []string {
	s = strings.TrimSpace(s)
	var out []string
	var cur strings.Builder
	inQuote, started := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			if inQuote && i+1 < len(s) && s[i+1] == '\'' {
				cur.WriteByte('\'')
				i++
				continue
			}
			inQuote = !inQuote
			started = true
		case !inQuote && (c == ' ' || c == '\t'):
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

// TestSubmitFileJobAdSetJobAttr: each SET_JOB_ATTR value reaches the ad
// with the TYPE the DAG wrote, which is the whole reason the value is
// emitted verbatim. Re-quoting it would make 17 the string "17", and a
// policy expression that compares it to a number would silently stop
// matching.
func TestSubmitFileJobAdSetJobAttr(t *testing.T) {
	opt := testSubmitOptions()
	opt.JobAttrs = []JobAttr{
		{Name: "DagLabel", Value: `"set-from-dag"`},
		{Name: "DagNumber", Value: "17"},
		{Name: "DagExpr", Value: "DagNumber + 1"},
		// Refused: the guard is in the emitter as well as in the
		// analysis, so a caller that skipped Analyze cannot break the
		// removal semantics either.
		{Name: "OtherJobRemoveRequirements", Value: `"False"`},
	}
	ad := dagmanJobAd(t, opt)

	if s, ok := ad.EvaluateAttrString("DagLabel"); !ok || s != "set-from-dag" {
		expr, _ := ad.Lookup("DagLabel")
		t.Errorf("DagLabel = %v (string=%v), want the string set-from-dag", expr, ok)
	}
	if n, ok := ad.EvaluateAttrInt("DagNumber"); !ok || n != 17 {
		expr, _ := ad.Lookup("DagNumber")
		t.Errorf("DagNumber = %v (int=%v), want 17 as a number", expr, ok)
	}
	if n, ok := ad.EvaluateAttrInt("DagExpr"); !ok || n != 18 {
		expr, _ := ad.Lookup("DagExpr")
		t.Errorf("DagExpr = %v (int=%v), want the expression to evaluate to 18", expr, ok)
	}
	if s, ok := ad.EvaluateAttrString("OtherJobRemoveRequirements"); !ok || s != "DAGManJobId =?= 42" {
		t.Errorf("OtherJobRemoveRequirements = %q (string=%v): the DAG overwrote it", s, ok)
	}
}

// TestSubmitFileJobAdEnvSet: an ENV SET variable reaches the manager
// job's Environment, and the operator's own configuration still wins
// over it -- a workflow must not be able to redirect CONDOR_CONFIG or
// BEARER_TOKEN_FILE by writing one line of DAG.
func TestSubmitFileJobAdEnvSet(t *testing.T) {
	opt := testSubmitOptions()
	opt.EnvSet = map[string]string{"DAG_TEST_VAR": "hello", "CONDOR_CONFIG": "/from/the/dag"}
	opt.ExtraEnv = map[string]string{"CONDOR_CONFIG": "/from/the/operator"}
	ad := dagmanJobAd(t, opt)

	env, ok := ad.EvaluateAttrString("Environment")
	if !ok {
		e, _ := ad.Lookup("Environment")
		t.Fatalf("Environment is not a string: %v", e)
	}
	if !strings.Contains(env, "DAG_TEST_VAR=hello") {
		t.Errorf("Environment = %q, missing the ENV SET variable", env)
	}
	if !strings.Contains(env, "CONDOR_CONFIG=/from/the/operator") {
		t.Errorf("Environment = %q: the DAG overrode the operator's configuration", env)
	}
	if strings.Contains(env, "/from/the/dag") {
		t.Errorf("Environment = %q still carries the DAG's CONDOR_CONFIG", env)
	}
	// The generated defaults are still there: ENV SET adds to the
	// environment, it does not replace it.
	if !strings.Contains(env, "_CONDOR_DAGMAN_LOG=wf.dagman.out") {
		t.Errorf("Environment = %q lost _CONDOR_DAGMAN_LOG", env)
	}
}
