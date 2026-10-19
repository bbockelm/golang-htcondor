//go:build integration

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Job resource-usage samples in multi-AP mode, end to end: the same
// stack TestMultiAPEndToEnd builds, with each spoke sampling its
// schedd's jobs into job_metrics and the hub federating job_metrics. A
// job with the same id runs on both APs, and the API reads its samples
// from the hub, per AP.
//
// The hub's job_metrics federation is newer than the htcondordb CI
// pins. A hub without it refuses the table at startup, which a probe
// finds before the stack is built; and a hub that runs but publishes no
// JobMetrics* attributes in federation_sources has nothing for the API
// to read. Either way the test skips, saying so. It runs once
// HTCONDORDB_BINARY names an htcondordb that federates job_metrics.
func TestMultiAPJobMetricsEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (runs two schedds, three htcondordb daemons and an API server)")
	}
	bin := htcondordbBinary(t)
	if os.Geteuid() == 0 {
		t.Skip("schedd sync refuses to run as root; run this test as an ordinary user")
	}
	if ok, why := hubFederatesJobMetrics(t, bin); !ok {
		t.Skipf("the federation hub (%s) cannot federate job_metrics: %s. "+
			"Set HTCONDORDB_BINARY to an htcondordb that federates job_metrics to run this test", bin, why)
	}
	started := time.Now()
	s := startMultiAPStackWith(t, bin, multiAPStackOptions{
		spoke: func(string) string { return "HTCONDORDB_JOB_METRICS = true\n" },
		hub:   "HTCONDORDB_FEDERATE_TABLES = jobs history syncstatus job_metrics\n",
	})

	// The gate: both APs' federation_sources rows, read through the API
	// server's own snapshot, and whether they carry the job_metrics
	// stream. Waited for before convergence, which a hub that cannot
	// federate the table may never reach.
	hub := s.srv.multi.svc.Hub
	var rows []multiap.Source
	waitFor(t, "the hub's federation_sources rows for both APs", 90*time.Second, func() bool {
		rows = hub.Active().Sources()
		return len(rows) == 2
	})
	for _, src := range rows {
		if !src.Tables[multiap.TableJobMetrics] {
			t.Skipf("the federation hub (%s) publishes no JobMetrics* attributes in federation_sources for %s: "+
				"this htcondordb predates job_metrics federation, so there is nothing to test against yet. "+
				"Set HTCONDORDB_BINARY to an htcondordb that federates job_metrics to run this test", bin, src.Schedd)
		}
	}
	s.waitList(t, "both APs' jobs to reach the API through the hub, with both APs fresh", 90*time.Second,
		s.me, func(l e2eList) bool {
			for _, k := range e2eMine {
				if !containsJob(l.keys(), k) {
					return false
				}
			}
			return l.Sources.APs == 2 && l.Sources.Fresh == 2
		})
	t.Logf("stack up in %s", time.Since(started).Round(time.Second))

	jobs := e2eRunSameIDOnBothAPs(t, s)
	m := &e2eMetrics{s: s}
	for _, phase := range []struct {
		name string
		run  func(*testing.T, *e2eMetrics, [2]apJob)
	}{
		{"each AP's samples reach the API through the hub", e2eMetricsArrive},
		{"one job's samples come from its AP alone", e2eMetricsOneJob},
		{"a bare id on both APs is a conflict naming both", e2eMetricsBareID},
		{"grouping by ScheddName and by job keeps the APs apart", e2eMetricsGroupBy},
		{"another user reads none of them", e2eMetricsOtherUser},
	} {
		t.Run(phase.name, func(t *testing.T) { phase.run(t, m, jobs) })
	}
	if n := s.srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times in multi-AP mode", n)
	}
	t.Logf("total %s", time.Since(started).Round(time.Second))
}

// hubFederatesJobMetrics starts bin as a hub with one static spoke
// (nothing there to reach) federating job_metrics, and reports whether
// it accepts the table.
//
// The answer is the hub's own word, not a timing: a hub that accepts its
// tables logs "running as a federation hub" naming them, once it has
// validated them; an older one exits saying it cannot federate the
// table. Its address file proves nothing -- it is written before the
// tables are validated.
func hubFederatesJobMetrics(t *testing.T, bin string) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := fmt.Sprintf(`
LOG = %[1]s
HTCONDORDB_DIR = %[1]s
HTCONDORDB_ADDRESS_FILE = %[1]s/addr
HTCONDORDB_ADVERTISE = false
HTCONDORDB_FEDERATE_SPOKES = probe
HTCONDORDB_FEDERATE_SPOKE_PROBE_ADDRESS = <127.0.0.1:1>
HTCONDORDB_FEDERATE_SPOKE_PROBE_SCHEDD = probe@127.0.0.1
HTCONDORDB_FEDERATE_TABLES = jobs syncstatus job_metrics
`, dir)
	cfgPath := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-listen", "127.0.0.1:0") //nolint:gosec // test binary from HTCONDORDB_BINARY
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+cfgPath)
	outPath := filepath.Join(dir, "output")
	out, err := os.Create(outPath) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", bin, err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	defer func() { _ = cmd.Process.Kill(); <-exited }()
	// Everything the daemon wrote: its output and its log files.
	said := func() string {
		var b strings.Builder
		files, _ := filepath.Glob(filepath.Join(dir, "*Log"))
		for _, f := range append([]string{outPath}, files...) {
			if c, err := os.ReadFile(f); err == nil { //nolint:gosec // the test's own files
				b.Write(c)
			}
		}
		return b.String()
	}
	accepted := func(text string) bool {
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "running as a federation hub") && strings.Contains(line, "job_metrics") {
				return true
			}
		}
		return false
	}
	for {
		select {
		case <-exited:
			text := said()
			if accepted(text) {
				t.Fatalf("%s accepted job_metrics and then exited:\n%s", bin, text)
			}
			msg := ""
			for _, line := range strings.Split(text, "\n") {
				if strings.Contains(line, "cannot federate") {
					msg = strings.TrimSpace(line)
				}
			}
			if msg == "" {
				t.Fatalf("%s exited at startup without saying it cannot federate job_metrics:\n%s", bin, text)
			}
			return false, msg
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-exited
			t.Fatalf("%s as a job_metrics hub neither started nor exited in 30s:\n%s", bin, said())
		case <-time.After(100 * time.Millisecond):
			if accepted(said()) {
				return true, ""
			}
		}
	}
}

// e2eRunSameIDOnBothAPs runs one short job on each AP under the same
// cluster.proc, one after the other on the pool's one slot, and waits
// for both to leave the queue: a job's last sample is its run's end.
func e2eRunSameIDOnBothAPs(t *testing.T, s *multiAPStack) [2]apJob {
	t.Helper()
	// ap1 is at 3, ap2 at 2: removed fillers bring ap2 level.
	next1 := s.lastCluster(t, e2eAP1).cluster + 1
	for s.lastCluster(t, e2eAP2).cluster+1 < next1 {
		s.submit(t, e2eAP2, "")
		filler := s.lastCluster(t, e2eAP2)
		s.condorQuiet("condor_rm", "-name", filler.schedd, filler.local())
		if filler.cluster+1 >= next1 {
			break
		}
	}
	var jobs [2]apJob
	for i, ap := range []string{e2eAP1, e2eAP2} {
		s.submit(t, ap, "arguments = 15\n+E2ERun = true\n")
		jobs[i] = s.lastCluster(t, ap)
		if jobs[i].cluster != next1 {
			t.Fatalf("the job on %s is %s, want cluster %d on both APs", ap, jobs[i], next1)
		}
		k := jobs[i]
		t.Cleanup(func() { s.condorQuiet("condor_rm", "-name", k.schedd, k.local()) })
	}
	for _, k := range jobs {
		waitFor(t, k.String()+" to run and finish", 4*time.Minute, func() bool {
			st := s.scheddAttr(t, k.schedd, k, "JobStatus")
			return st == "" || st == "4"
		})
	}
	return jobs
}

type e2eMetrics struct{ s *multiAPStack }

// metricsResp is a multi-AP metrics answer as the e2e reads it.
type metricsResp struct {
	Enabled bool             `json:"enabled"`
	Columns []metricsColumn  `json:"columns"`
	Rows    [][]string       `json:"rows"`
	Job     *metricsJob      `json:"job"`
	Sources *multiap.Sources `json:"sources"`
}

func (m *e2eMetrics) query(t *testing.T, as string, q url.Values) (int, metricsResp, string) {
	t.Helper()
	code, body := m.s.get(t, as, "/api/v1/metrics/job_metrics?"+q.Encode())
	var r metricsResp
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatalf("decoding %s: %v", body, err)
		}
	}
	return code, r, body
}

func (m *e2eMetrics) ok(t *testing.T, as string, q url.Values) metricsResp {
	t.Helper()
	code, r, body := m.query(t, as, q)
	if code != http.StatusOK || !r.Enabled {
		t.Fatalf("%s as %s = %d %s, want an enabled answer", q.Encode(), as, code, body)
	}
	return r
}

// perJob is the sample count by AP and cluster.proc.
func perJob(r metricsResp) map[apJob]int {
	out := map[apJob]int{}
	for _, row := range r.Rows {
		if len(row) != 4 {
			continue
		}
		var k apJob
		k.schedd = strings.Trim(row[0], `"`)
		_, _ = fmt.Sscan(row[1], &k.cluster)
		_, _ = fmt.Sscan(row[2], &k.proc)
		var n int
		_, _ = fmt.Sscan(row[3], &n)
		out[k] += n
	}
	return out
}

var e2eByJob = url.Values{"group_by": {"ClusterId,ProcId"}, "agg": {"count:*"}}

func e2eMetricsArrive(t *testing.T, m *e2eMetrics, jobs [2]apJob) {
	waitFor(t, "samples of both runs to reach the hub", 2*time.Minute, func() bool {
		got := perJob(m.ok(t, m.s.me, e2eByJob))
		return got[jobs[0]] > 0 && got[jobs[1]] > 0
	})
	r := m.ok(t, m.s.me, e2eByJob)
	if r.Sources == nil || r.Sources.APs != 2 {
		t.Fatalf("sources = %+v", r.Sources)
	}
	for _, d := range r.Sources.Degraded {
		if strings.Contains(d.Reason, multiap.TableJobMetrics) {
			t.Errorf("%s is degraded for job_metrics with both streams up: %+v", d.Schedd, d)
		}
	}
}

func e2eMetricsOneJob(t *testing.T, m *e2eMetrics, jobs [2]apJob) {
	all := perJob(m.ok(t, m.s.me, e2eByJob))
	for _, k := range jobs {
		r := m.ok(t, m.s.me, url.Values{"job_id": {k.String()}, "group_by": {"RunInstanceID"},
			"bucket": {"900"}, "agg": {"count:*,max:MemoryUsage"}})
		if r.Job == nil || r.Job.Schedd != k.schedd || r.Job.Cluster != k.cluster || r.Job.Proc != k.proc {
			t.Errorf("%s: job = %+v", k, r.Job)
		}
		n := 0
		for _, row := range r.Rows {
			var c int
			_, _ = fmt.Sscan(row[2], &c)
			n += c
		}
		if n != all[k] {
			t.Errorf("%s: %d samples, want that AP's %d (the other AP's %d are not its)", k, n, all[k], all[jobs[0]]+all[jobs[1]]-all[k])
		}
	}
}

func e2eMetricsBareID(t *testing.T, m *e2eMetrics, jobs [2]apJob) {
	code, _, body := m.query(t, m.s.me, url.Values{"job_id": {jobs[0].local()}, "agg": {"count:*"}})
	if code != http.StatusConflict || !strings.Contains(body, jobs[0].String()) || !strings.Contains(body, jobs[1].String()) {
		t.Errorf("bare %s = %d %s, want 409 naming both APs' job", jobs[0].local(), code, body)
	}
}

func e2eMetricsGroupBy(t *testing.T, m *e2eMetrics, jobs [2]apJob) {
	r := m.ok(t, m.s.me, e2eByJob)
	if len(r.Columns) == 0 || r.Columns[0].Name != multiap.AttrScheddName {
		t.Errorf("columns = %+v, want ScheddName first", r.Columns)
	}
	byJob := perJob(r)
	r = m.ok(t, m.s.me, url.Values{"group_by": {"ScheddName"}, "agg": {"count:*"}})
	perAP := map[string]int{}
	for _, row := range r.Rows {
		var n int
		_, _ = fmt.Sscan(row[1], &n)
		perAP[strings.Trim(row[0], `"`)] = n
	}
	for _, k := range jobs {
		if perAP[k.schedd] < byJob[k] || byJob[k] == 0 {
			t.Errorf("%s: %d samples per AP, %d for its job", k.schedd, perAP[k.schedd], byJob[k])
		}
	}
}

func e2eMetricsOtherUser(t *testing.T, m *e2eMetrics, jobs [2]apJob) {
	for _, q := range []url.Values{
		{"group_by": {"ScheddName"}, "agg": {"count:*"}},
		{"group_by": {"ScheddName"}, "agg": {"count:*"}, "constraint": {fmt.Sprintf("User =!= %q || true", e2eOther)}},
	} {
		if r := m.ok(t, e2eOther, q); len(r.Rows) != 0 {
			t.Errorf("%s read %v (%s), want none of %s's samples", e2eOther, r.Rows, q.Encode(), m.s.me)
		}
	}
	// Naming the job outright reads nothing either: an ungrouped count
	// is one row, and it is zero.
	if code, r, body := m.query(t, e2eOther, url.Values{"job_id": {jobs[1].String()}, "agg": {"count:*"}}); code == http.StatusOK {
		for _, row := range r.Rows {
			if len(row) != 1 || row[0] != "0" {
				t.Errorf("%s read %s's %s: %s", e2eOther, m.s.me, jobs[1], body)
			}
		}
	}
}
