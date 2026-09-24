package httpserver

import (
	"strings"
	"testing"
)

// A JupyterLab job showed up in the queue as a bare jupyter-launch.sh
// among the user's real work, with nothing saying what it was.
func TestJupyterSubmitNamesTheBatch(t *testing.T) {
	got := buildJupyterSubmitFile(jupyterSubmitArgs{InstanceID: "a1b2c3d4e5f60718", Image: "img"})
	if !strings.Contains(got, "batch_name = htcondor-api-jupyter-a1b2c3d4e5f6") {
		t.Errorf("no batch name, or not the session's:\n%s", got)
	}
	// `batch_name` is the spelling the in-process submit parser reads;
	// `job_batch_name` is silently dropped.
	if strings.Contains(got, "job_batch_name") {
		t.Error("job_batch_name is not a submit command")
	}
}

// The ceiling is the schedd's, so it holds whatever the sandbox, the
// helper or the browser are doing.
func TestJupyterMaxLifetimeIsEnforcedBySchedd(t *testing.T) {
	got := buildJupyterSubmitFile(jupyterSubmitArgs{InstanceID: "x", MaxLifetimeSec: 3600})
	if !strings.Contains(got, "periodic_remove") {
		t.Fatalf("no ceiling on the session:\n%s", got)
	}
	// Measured from JobStartDate, not QDate: time spent queued waiting
	// for a slot is not part of anyone's session.
	if !strings.Contains(got, "JobStartDate") || strings.Contains(got, "QDate") {
		t.Errorf("the ceiling should run from JobStartDate:\n%s", got)
	}
	// An expression that is UNDEFINED for a job that has not started
	// yet is not the same as false, so the guard has to be there.
	if !strings.Contains(got, "JobStartDate =!= UNDEFINED") {
		t.Errorf("unguarded JobStartDate reference:\n%s", got)
	}
	if !strings.Contains(got, "3600") {
		t.Errorf("the configured limit did not reach the expression:\n%s", got)
	}
}

// Zero is how an operator turns the ceiling off, and must not emit a
// malformed expression that removes the job immediately.
func TestJupyterMaxLifetimeOffEmitsNothing(t *testing.T) {
	if got := jupyterPeriodicRemove(0); got != "" {
		t.Errorf("jupyterPeriodicRemove(0) = %q, want no expression", got)
	}
	if got := buildJupyterSubmitFile(jupyterSubmitArgs{InstanceID: "x"}); strings.Contains(got, "periodic_remove") {
		t.Errorf("a ceiling was emitted with none configured:\n%s", got)
	}
}

// The case the whole thing exists for: a tab left open with nobody at
// it. That tab holds a connection to its kernel, and JupyterLab skips
// connected kernels when culling unless told otherwise -- so without
// cull_connected the one session this is meant to reap is exactly the
// one that survives.
func TestJupyterCullsKernelsEvenWithAnOpenTab(t *testing.T) {
	got := jupyterIdleFlags(1800)
	for _, want := range []string{
		"--MappingKernelManager.cull_idle_timeout=1800",
		"--MappingKernelManager.cull_connected=True",
		"--ServerApp.shutdown_no_activity_timeout=1800",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
	// The flag is shutdown_no_activity_timeout. The similarly-named
	// shutdown_no_activity_delay does not exist, and JupyterLab does
	// not fail on an unknown --ServerApp option loudly enough for that
	// to be noticed.
	if strings.Contains(got, "shutdown_no_activity_delay") {
		t.Error("that option does not exist; the timeout is shutdown_no_activity_timeout")
	}
}

func TestJupyterIdleFlagsOffEmitNothing(t *testing.T) {
	if got := jupyterIdleFlags(0); got != "" {
		t.Errorf("jupyterIdleFlags(0) = %q, want nothing", got)
	}
}

// The launcher has to actually pass them, not merely be able to build
// them.
func TestJupyterLaunchScriptPassesTheIdleFlags(t *testing.T) {
	script := buildJupyterLaunchScript(jupyterLaunchScriptArgs{
		UpstreamURL:          "wss://example/x",
		BaseURL:              "/proxy/x/",
		AllowOrigin:          "https://example",
		KernelIdleTimeoutSec: 900,
	})
	if !strings.Contains(script, "cull_connected=True") {
		t.Errorf("the launcher does not pass the culling options:\n%s", script)
	}
}
