//go:build integration

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/appolicy"
)

// TestAccessPointPolicyIntegration reads a real schedd's configuration
// over DC_CONFIG_VAL and submits through submit_job, so both halves meet
// HTCondor itself: the reply forms daemon core uses for set, defaulted
// and unknown knobs, and a job that omits request_* taking the access
// point's defaults rather than the built-in ones.
func TestAccessPointPolicyIntegration(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (forks a real HTCondor)")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH")
	}

	harness := htcondor.SetupCondorHarnessWithConfig(t, `
JOB_DEFAULT_REQUESTMEMORY = 777
JOB_DEFAULT_REQUESTCPUS = 2
MAX_JOBS_PER_SUBMISSION = 50
SUBMIT_REQUIREMENT_NAMES = NotHuge
SUBMIT_REQUIREMENT_NotHuge = RequestMemory < 100000
SUBMIT_REQUIREMENT_NotHuge_REASON = "Ask for less than 100 GB"
JOB_TRANSFORM_NAMES = Tag
JOB_TRANSFORM_Tag @=end
   SET PolicyTagged true
@end
`)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	schedd := locateSchedd(t, harness)

	ctx, cancel := context.WithTimeout(
		htcondor.WithAuthenticatedUser(context.Background(), currentUserForTest(t)), 3*time.Minute)
	defer cancel()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{schedd: schedd, logger: logger, apPolicy: appolicy.NewCache()}

	params, _ := json.Marshal(map[string]any{"name": "get_access_point_policy", "arguments": map[string]any{}})
	res, err := server.handleCallTool(ctx, params)
	if err != nil {
		t.Fatalf("get_access_point_policy: %v", err)
	}
	text := skillResultText(t, res)
	t.Logf("policy:\n%s", text)
	for _, want := range []string{
		"- MAX_JOBS_PER_SUBMISSION = 50 [site]:",
		"- JOB_DEFAULT_REQUESTMEMORY = 777 [site]:",
		// Left at HTCondor's default, which the schedd reports.
		"- MAX_JOBS_PER_OWNER = 100000:",
		// Unknown to param_info, so the schedd answers with nothing.
		"- JOB_DEFAULT_REQUESTGPUS: Not set",
		`A job is refused with the message "Ask for less than 100 GB" unless`,
		"- JOB_TRANSFORM_Tag [site]: Applies to every job. It sets PolicyTagged.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("policy lacks %q", want)
		}
	}
	out, err := toSDKResult(res)
	if err != nil {
		t.Fatal(err)
	}
	validateStructured(t, "get_access_point_policy", out.StructuredContent)

	subRes, err := server.toolSubmitJob(ctx, map[string]interface{}{
		"submit_file": "executable = /bin/sleep\narguments = 1\ntransfer_executable = false\nqueue\n",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	cluster, ok := subRes.(map[string]interface{})["metadata"].(map[string]interface{})["cluster_id"].(int)
	if !ok {
		t.Fatalf("no cluster_id in %+v", subRes)
	}
	defer func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		_, _ = schedd.RemoveJobsByID(cctx, []string{fmt.Sprintf("%d.0", cluster)}, "test cleanup")
	}()

	ads, _, err := schedd.QueryWithOptions(ctx, fmt.Sprintf("ClusterId == %d", cluster),
		&htcondor.QueryOptions{Projection: []string{"RequestMemory", "RequestCpus", "RequestDisk", "PolicyTagged"}})
	if err != nil || len(ads) != 1 {
		t.Fatalf("query: %d ads, %v", len(ads), err)
	}
	if v, _ := ads[0].EvaluateAttrInt("RequestMemory"); v != 777 {
		t.Errorf("RequestMemory = %d, want the access point's 777", v)
	}
	if v, _ := ads[0].EvaluateAttrInt("RequestCpus"); v != 2 {
		t.Errorf("RequestCpus = %d, want the access point's 2", v)
	}
	if v := ads[0].EvaluateAttr("RequestDisk"); !v.IsNumber() {
		t.Errorf("RequestDisk = %v at the schedd, which matches no slot", v)
	}
	if v, _ := ads[0].EvaluateAttrBool("PolicyTagged"); !v {
		t.Error("the transform the policy reported did not run")
	}
}
