package utilization

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"
)

// What an epoch-aware memory estimate costs.
//
// Today one read answers the Utilization page: a projected, newest-first
// scan of the `history` archive. Per-attempt requests live only in
// `epoch_history`, so an estimate that accounts for a retry at a different
// RequestMemory has to reach a second table. These benchmarks price the
// three ways of doing that against the one-table read they would replace,
// over a real connection and at the read size the page actually uses.
//
//	go test ./utilization/ -run '^$' -bench EpochJoin -benchtime 1x -timeout 30m

// epochFixtureJobs is utilizationDefaultLimit, the window one analysis
// reads. EPOCHBENCH_JOBS shrinks it for a smoke run.
var epochFixtureJobs = func() int {
	if v := os.Getenv("EPOCHBENCH_JOBS"); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			return n
		}
	}
	return 50000
}()

// attemptsFor is how many run instances job i had: a long tail of retries
// over a population that mostly runs once, which is what a pool with
// retry_request_memory in use looks like.
func attemptsFor(i int) int {
	switch {
	case i%100 < 85:
		return 1
	case i%100 < 97:
		return 2
	default:
		return 3
	}
}

// historyAdText is one completed-job record at the width a real one has:
// every attribute Projection() reads, plus filler to ~80 attributes.
func historyAdText(i int) string {
	cluster, proc := 1000000+i/100, i%100
	owner := fmt.Sprintf("user%02d", i%40)
	wall := 600 + i%7200
	req := 1024 * (1 + i%8)
	starts := attemptsFor(i)
	rss := 1024 * (300 + i%900)
	held := 0
	if starts > 1 {
		held = 34
	}
	q := 1760000000 + i
	done := q + wall
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("ClusterId = %d", cluster)
	w("ProcId = %d", proc)
	w("Owner = %q", owner)
	w("User = %q", owner+"@example.org")
	w("GlobalJobId = %q", fmt.Sprintf("ap2001.example.org#%d.%d#1", cluster, proc))
	w("JobBatchName = %q", fmt.Sprintf("batch-%d", i%40))
	w("Cmd = %q", fmt.Sprintf("/home/%s/bin/prog%d.sh", owner, i%40))
	w("Args = %q", fmt.Sprintf("--in data%d.root --out out%d.root", i, i))
	w("JobUniverse = 5")
	w("QDate = %d", q)
	w("CompletionDate = %d", done)
	w("EnteredHistoryTime = %d", done)
	w("EnteredCurrentStatus = %d", done)
	w("JobStartDate = %d", q+10)
	w("JobCurrentStartDate = %d", q+10)
	w("JobStatus = 4")
	w("ExitCode = 0")
	w("ExitBySignal = false")
	w("RequestMemory = %d", req)
	w("RequestCpus = %d", 1+i%4)
	w("RequestDisk = 1048576")
	w("RequestGPUs = 0")
	w("MemoryUsage = ((ResidentSetSize + 1023) / 1024)")
	w("ResidentSetSize = %d", rss)
	w("ResidentSetSize_RAW = %d", rss)
	w("DiskUsage = 204800")
	w("DiskUsage_RAW = 198000")
	w("RemoteWallClockTime = %d.0", wall)
	w("RemoteUserCpu = %d.0", wall*8/10)
	w("RemoteSysCpu = %d.0", wall/20)
	w("CumulativeRemoteUserCpu = %d.0", wall*8/10)
	w("CumulativeRemoteSysCpu = %d.0", wall/20)
	w("CommittedTime = %d", wall)
	w("NumJobStarts = %d", starts)
	w("NumHoldsByReason = [ MemoryExceeded = %d ]", starts-1)
	w("HoldReasonCode = 0")
	w("HoldReasonSubCode = 0")
	w("LastHoldReasonCode = %d", held)
	w("LastHoldReasonSubCode = 0")
	w("VacateReasonCode = 0")
	w("VacateReasonSubCode = 0")
	// Filler to a realistic ~80-attribute record. A history ad carries
	// machine attributes, transfer counters and policy expressions the
	// analysis never reads, and they are bytes the read pays for.
	for k := range 36 {
		w("MachineAttrFiller%d = %q", k, fmt.Sprintf("value-%d-%d", i%17, k))
	}
	return b.String()
}

// epochAdText is one EPOCH record: the shadow writes the whole job ad at
// the end of a run instance, so it is as wide as a history record. run is
// the RunInstanceID and inForce the RequestMemory that run held.
func epochAdText(i, run, inForce int) string {
	base := historyAdText(i)
	// The per-attempt request replaces the final one, and the record gains
	// its epoch identity.
	base = strings.Replace(base, fmt.Sprintf("RequestMemory = %d\n", 1024*(1+i%8)),
		fmt.Sprintf("RequestMemory = %d\n", inForce), 1)
	wall := 600 + i%7200
	return base + fmt.Sprintf("RunInstanceID = %d\nEpochAdType = \"EPOCH\"\nEpochWriteDate = %d\nNumShadowStarts = %d\n",
		run, 1760000000+i+wall, run+1)
}

// spawnAdText is the SPAWN record the shadow writes at the start of a run.
// SPAWN_JOB_ATTRS filters it down to a handful of attributes by default,
// so it is narrow -- and it is a row the epoch read still has to skip.
func spawnAdText(i, run int) string {
	cluster, proc := 1000000+i/100, i%100
	return fmt.Sprintf(`ClusterId = %d
ProcId = %d
Owner = "user%02d"
NumShadowStarts = %d
ShadowBirthdate = %d
RunInstanceID = %d
EpochAdType = "SPAWN"
EpochWriteDate = %d
`, cluster, proc, i%40, run+1, 1760000000+i, run, 1760000000+i)
}

// epochRequest is the RequestMemory in force for run instance run of job i:
// the start, doubled after each memory hold, which is what a
// retry_request_memory formula does.
func epochRequest(i, run int) int {
	req := 1024 * (1 + i%8)
	for range run {
		req *= 2
	}
	return req
}

type epochFixture struct {
	dir        string
	addr       string
	attrs      map[string]string
	jobs       int
	epochRows  int
	historyMiB float64
	epochMiB   float64
}

var (
	fixtureOnce sync.Once
	fixture     *epochFixture
)

// buildFixture loads both archives once and serves them over loopback TCP
// for the rest of the process. One store, shared by every arm.
func buildFixture(b *testing.B) *epochFixture {
	b.Helper()
	fixtureOnce.Do(func() {
		dir := b.TempDir()
		cat, err := db.OpenCatalog(dir)
		if err != nil {
			b.Fatalf("open catalog: %v", err)
		}
		// The archive configuration htcondordb creates these tables with:
		// Owner categorical, ClusterId a value index, the event time zoned.
		hist, err := cat.CreateArchiveTable("history", db.ArchiveConfig{
			CategoricalAttrs: []string{"Owner"},
			ValueAttrs:       []string{"ClusterId"},
			ZoneAttrs:        []string{"CompletionDate", "EnteredHistoryTime"},
		})
		if err != nil {
			b.Fatalf("create history: %v", err)
		}
		epoch, err := cat.CreateArchiveTable("epoch_history", db.ArchiveConfig{
			CategoricalAttrs: []string{"Owner"},
			ValueAttrs:       []string{"ClusterId"},
			ZoneAttrs:        []string{"EpochWriteDate", "EnteredHistoryTime"},
		})
		if err != nil {
			b.Fatalf("create epoch_history: %v", err)
		}
		f := &epochFixture{dir: dir, jobs: epochFixtureJobs}
		for i := range epochFixtureJobs {
			text := historyAdText(i)
			f.historyMiB += float64(len(text))
			if err := hist.AppendOld(text); err != nil {
				b.Fatalf("append history: %v", err)
			}
			for run := range attemptsFor(i) {
				for _, t := range []string{spawnAdText(i, run), epochAdText(i, run, epochRequest(i, run))} {
					f.epochMiB += float64(len(t))
					f.epochRows++
					if err := epoch.AppendOld(t); err != nil {
						b.Fatalf("append epoch: %v", err)
					}
				}
			}
		}
		f.historyMiB /= 1 << 20
		f.epochMiB /= 1 << 20

		rpc := dbrpc.NewServerCatalog(cat)
		var lc net.ListenConfig
		ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatalf("listen: %v", err)
		}
		go func() {
			for {
				c, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				go func() { _ = rpc.ServeConn(dbrpc.NewStreamConn(c)) }()
			}
		}()
		f.addr = ln.Addr().String()
		f.attrs = rpc.SessionAttrs()
		fixture = f
	})
	return fixture
}

func dialFixture(b *testing.B, f *epochFixture) *dbrpc.Client {
	b.Helper()
	var d net.Dialer
	c, err := d.DialContext(context.Background(), "tcp", f.addr)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	cl := dbrpc.NewClient(dbrpc.NewStreamConn(c), dbrpc.WithPeerSessionAttrs(f.attrs))
	b.Cleanup(func() { _ = cl.Close() })
	return cl
}

// epochProjection is what the epoch side has to carry for a per-attempt
// memory estimate: which job, which run, what it asked for, what it
// reached, how long it ran and why it stopped.
func epochProjection() []string {
	return []string{"ClusterId", "ProcId", "RunInstanceID", "RequestMemory",
		"MemoryUsage", "ResidentSetSize", "RemoteWallClockTime", "HoldReasonCode", "EpochWriteDate"}
}

// windowScope is the predicate the page actually sends: the history
// window. Every fixture row is inside it, so the read is the full 50k --
// which is what utilizationDefaultLimit is sized for.
const windowScope = `EnteredHistoryTime > 1700000000`

// BenchmarkEpochJoinArms prices the four ways of answering the page.
func BenchmarkEpochJoinArms(b *testing.B) {
	f := buildFixture(b)
	ctx := context.Background()
	b.Logf("fixture: %d history rows (%.1f MiB of text), %d epoch rows (%.1f MiB)",
		f.jobs, f.historyMiB, f.epochRows, f.epochMiB)

	limit := epochFixtureJobs
	histConstraint := windowScope
	epochConstraint := windowScope + ` && EpochAdType == "EPOCH"`

	// A: today. One projected read of history.
	b.Run("A-history-only", func(b *testing.B) {
		cl := dialFixture(b, f)
		for b.Loop() {
			rows, bytes := 0, 0
			err := cl.QueryRawProjectStream(ctx, "history", histConstraint, Projection(), limit,
				func(row string) bool { rows++; bytes += len(row); return true })
			if err != nil {
				b.Fatalf("history read: %v", err)
			}
			b.ReportMetric(float64(rows), "rows")
			b.ReportMetric(float64(bytes)/(1<<20), "MiB")
		}
	})

	// B: two reads, paired on the client.
	b.Run("B-two-reads-client-pair", func(b *testing.B) {
		cl := dialFixture(b, f)
		for b.Loop() {
			rows, bytes := 0, 0
			err := cl.QueryRawProjectStream(ctx, "history", histConstraint, Projection(), limit,
				func(row string) bool { rows++; bytes += len(row); return true })
			if err != nil {
				b.Fatalf("history read: %v", err)
			}
			eRows := 0
			err = cl.QueryRawProjectStream(ctx, "epoch_history", epochConstraint, epochProjection(), 4*limit,
				func(row string) bool { eRows++; bytes += len(row); return true })
			if err != nil {
				b.Fatalf("epoch read: %v", err)
			}
			b.ReportMetric(float64(rows+eRows), "rows")
			b.ReportMetric(float64(bytes)/(1<<20), "MiB")
		}
	})

	// C: one server-side LEFT join, rows streamed out.
	b.Run("C-server-join", func(b *testing.B) {
		cl := dialFixture(b, f)
		spec := db.JoinSpec{
			Kind:  db.JoinLeft,
			Left:  db.JoinSide{Table: "history", Alias: "h", Constraint: histConstraint, Project: Projection()},
			Right: db.JoinSide{Table: "epoch_history", Alias: "e", Constraint: epochConstraint, Project: epochProjection()},
			Cond:  []string{"h.ClusterId == e.ClusterId", "h.ProcId == e.ProcId"},
			Equi: []db.JoinEqui{
				{Left: "ClusterId", Right: "ClusterId"},
				{Left: "ProcId", Right: "ProcId"},
			},
		}
		for b.Loop() {
			rows, bytes := 0, 0
			err := cl.Join(ctx, dbrpc.JoinRequest{Spec: spec}, func(row string) bool {
				rows++
				bytes += len(row)
				return true
			})
			if err != nil {
				b.Fatalf("join: %v", err)
			}
			b.ReportMetric(float64(rows), "rows")
			b.ReportMetric(float64(bytes)/(1<<20), "MiB")
		}
	})

	// D: the same join with the history side narrowed to the few
	// attributes a memory estimate needs, instead of the whole page's
	// projection. What the join ships is the left side repeated once per
	// attempt, so this is the knob that decides what it costs.
	b.Run("D-server-join-narrow-left", func(b *testing.B) {
		cl := dialFixture(b, f)
		narrow := []string{"ClusterId", "ProcId", "Owner", "RequestMemory", "MemoryUsage",
			"RemoteWallClockTime", "NumJobStarts", "JobStatus"}
		spec := db.JoinSpec{
			Kind:  db.JoinLeft,
			Left:  db.JoinSide{Table: "history", Alias: "h", Constraint: histConstraint, Project: narrow},
			Right: db.JoinSide{Table: "epoch_history", Alias: "e", Constraint: epochConstraint, Project: epochProjection()},
			Cond:  []string{"h.ClusterId == e.ClusterId", "h.ProcId == e.ProcId"},
			Equi: []db.JoinEqui{
				{Left: "ClusterId", Right: "ClusterId"},
				{Left: "ProcId", Right: "ProcId"},
			},
		}
		for b.Loop() {
			rows, bytes := 0, 0
			err := cl.Join(ctx, dbrpc.JoinRequest{Spec: spec}, func(row string) bool {
				rows++
				bytes += len(row)
				return true
			})
			if err != nil {
				b.Fatalf("join: %v", err)
			}
			b.ReportMetric(float64(rows), "rows")
			b.ReportMetric(float64(bytes)/(1<<20), "MiB")
		}
	})

	// E: the same narrow join, with the epoch side cut to the records that
	// can change the answer. A job's first attempt ran at the request the
	// history record still shows for a job that never grew; what only
	// epochs can say is what a RERUN asked for, and that is RunInstanceID
	// > 0 -- 15% of the jobs here and a sixth of the epoch rows.
	b.Run("E-server-join-retries-only", func(b *testing.B) {
		cl := dialFixture(b, f)
		narrow := []string{"ClusterId", "ProcId", "Owner", "RequestMemory", "MemoryUsage",
			"RemoteWallClockTime", "NumJobStarts", "JobStatus"}
		spec := db.JoinSpec{
			Kind: db.JoinLeft,
			Left: db.JoinSide{Table: "history", Alias: "h", Constraint: windowScope, Project: narrow},
			Right: db.JoinSide{Table: "epoch_history", Alias: "e",
				Constraint: windowScope + ` && EpochAdType == "EPOCH" && RunInstanceID > 0`,
				Project:    epochProjection()},
			Cond: []string{"h.ClusterId == e.ClusterId", "h.ProcId == e.ProcId"},
			Equi: []db.JoinEqui{
				{Left: "ClusterId", Right: "ClusterId"},
				{Left: "ProcId", Right: "ProcId"},
			},
		}
		for b.Loop() {
			rows, bytes := 0, 0
			err := cl.Join(ctx, dbrpc.JoinRequest{Spec: spec}, func(row string) bool {
				rows++
				bytes += len(row)
				return true
			})
			if err != nil {
				b.Fatalf("join: %v", err)
			}
			b.ReportMetric(float64(rows), "rows")
			b.ReportMetric(float64(bytes)/(1<<20), "MiB")
		}
	})

	// F: the feature without a join. The page's read is untouched, and a
	// second projected read brings back only the rerun records. The client
	// pairs them on (ClusterId, ProcId), which is a map of 50k keys.
	b.Run("F-two-reads-retries-only", func(b *testing.B) {
		cl := dialFixture(b, f)
		for b.Loop() {
			rows, bytes := 0, 0
			err := cl.QueryRawProjectStream(ctx, "history", histConstraint, Projection(), limit,
				func(row string) bool { rows++; bytes += len(row); return true })
			if err != nil {
				b.Fatalf("history read: %v", err)
			}
			err = cl.QueryRawProjectStream(ctx, "epoch_history",
				windowScope+` && EpochAdType == "EPOCH" && RunInstanceID > 0`, epochProjection(), 4*limit,
				func(row string) bool { rows++; bytes += len(row); return true })
			if err != nil {
				b.Fatalf("epoch read: %v", err)
			}
			b.ReportMetric(float64(rows), "rows")
			b.ReportMetric(float64(bytes)/(1<<20), "MiB")
		}
	})

	// G: the join given its best shape. An INNER join may exchange its
	// sides, so the planner can hash the 9,000 rerun records and stream
	// history against them instead of hashing all 118,000 epoch rows. It
	// answers for the retried jobs only, so it is an ADDITION to arm A,
	// not a replacement -- which is the point: a join cannot carry the
	// 85% of jobs that have no rerun without paying for them.
	b.Run("G-inner-join-retries-only", func(b *testing.B) {
		cl := dialFixture(b, f)
		spec := db.JoinSpec{
			Kind: db.JoinInner,
			Left: db.JoinSide{Table: "history", Alias: "h", Constraint: windowScope, Project: Projection()},
			Right: db.JoinSide{Table: "epoch_history", Alias: "e",
				Constraint: windowScope + ` && EpochAdType == "EPOCH" && RunInstanceID > 0`,
				Project:    epochProjection()},
			Cond: []string{"h.ClusterId == e.ClusterId", "h.ProcId == e.ProcId"},
			Equi: []db.JoinEqui{
				{Left: "ClusterId", Right: "ClusterId"},
				{Left: "ProcId", Right: "ProcId"},
			},
		}
		for b.Loop() {
			rows, bytes := 0, 0
			err := cl.Join(ctx, dbrpc.JoinRequest{Spec: spec}, func(row string) bool {
				rows++
				bytes += len(row)
				return true
			})
			if err != nil {
				b.Fatalf("join: %v", err)
			}
			b.ReportMetric(float64(rows), "rows")
			b.ReportMetric(float64(bytes)/(1<<20), "MiB")
		}
	})

	// H: arm F with the two reads issued concurrently on two connections,
	// which is what the handler would actually do. The epoch read is a
	// fifth of the history read, so it finishes inside it and the page
	// waits on the read it already waits on.
	b.Run("H-two-reads-retries-only-parallel", func(b *testing.B) {
		histCl, epochCl := dialFixture(b, f), dialFixture(b, f)
		for b.Loop() {
			var wg sync.WaitGroup
			var hRows, eRows int
			var hBytes, eBytes int
			var hErr, eErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				hErr = histCl.QueryRawProjectStream(ctx, "history", histConstraint, Projection(), limit,
					func(row string) bool { hRows++; hBytes += len(row); return true })
			}()
			go func() {
				defer wg.Done()
				eErr = epochCl.QueryRawProjectStream(ctx, "epoch_history",
					windowScope+` && EpochAdType == "EPOCH" && RunInstanceID > 0`, epochProjection(), 4*limit,
					func(row string) bool { eRows++; eBytes += len(row); return true })
			}()
			wg.Wait()
			if hErr != nil || eErr != nil {
				b.Fatalf("reads: %v / %v", hErr, eErr)
			}
			b.ReportMetric(float64(hRows+eRows), "rows")
			b.ReportMetric(float64(hBytes+eBytes)/(1<<20), "MiB")
		}
	})
}

// BenchmarkEpochJoinDecode adds the decode the page actually pays: arm A
// and arm C, each through the Decoder that turns rows into Jobs.
func BenchmarkEpochJoinDecode(b *testing.B) {
	f := buildFixture(b)
	ctx := context.Background()
	limit := epochFixtureJobs

	b.Run("A-history-only", func(b *testing.B) {
		cl := dialFixture(b, f)
		for b.Loop() {
			dec := NewDecoder(0)
			n := 0
			err := cl.QueryRawProjectStream(ctx, "history", windowScope, Projection(), limit,
				func(row string) bool { n++; dec.Row(row); return true })
			if err != nil {
				b.Fatalf("history read: %v", err)
			}
			chunks, _ := dec.Finish()
			b.ReportMetric(float64(Count(chunks)), "jobs")
		}
	})

	b.Run("C-server-join-parse", func(b *testing.B) {
		cl := dialFixture(b, f)
		spec := db.JoinSpec{
			Kind:  db.JoinLeft,
			Left:  db.JoinSide{Table: "history", Alias: "h", Constraint: windowScope, Project: Projection()},
			Right: db.JoinSide{Table: "epoch_history", Alias: "e", Constraint: windowScope + ` && EpochAdType == "EPOCH"`, Project: epochProjection()},
			Cond:  []string{"h.ClusterId == e.ClusterId", "h.ProcId == e.ProcId"},
			Equi: []db.JoinEqui{
				{Left: "ClusterId", Right: "ClusterId"},
				{Left: "ProcId", Right: "ProcId"},
			},
		}
		for b.Loop() {
			n := 0
			start := time.Now()
			err := cl.Join(ctx, dbrpc.JoinRequest{Spec: spec}, func(row string) bool {
				if _, perr := classad.ParseOld(row); perr == nil {
					n++
				}
				return true
			})
			if err != nil {
				b.Fatalf("join: %v", err)
			}
			b.ReportMetric(float64(n), "rows")
			b.ReportMetric(time.Since(start).Seconds(), "s")
		}
	})
}

// BenchmarkEpochJoinExplain reports the plan, not a time.
func BenchmarkEpochJoinExplain(b *testing.B) {
	f := buildFixture(b)
	cl := dialFixture(b, f)
	ctx := context.Background()
	narrow := []string{"ClusterId", "ProcId", "Owner", "RequestMemory", "MemoryUsage",
		"RemoteWallClockTime", "NumJobStarts", "JobStatus"}
	for _, c := range []struct {
		name       string
		left       []string
		epochWhere string
	}{
		{"C-full-left", Projection(), `EpochAdType == "EPOCH"`},
		{"D-narrow-left", narrow, `EpochAdType == "EPOCH"`},
		{"E-retries-only", narrow, `EpochAdType == "EPOCH" && RunInstanceID > 0`},
	} {
		spec := db.JoinSpec{
			Kind:  db.JoinLeft,
			Left:  db.JoinSide{Table: "history", Alias: "h", Constraint: windowScope, Project: c.left},
			Right: db.JoinSide{Table: "epoch_history", Alias: "e", Constraint: windowScope + " && " + c.epochWhere, Project: epochProjection()},
			Cond:  []string{"h.ClusterId == e.ClusterId", "h.ProcId == e.ProcId"},
			Equi: []db.JoinEqui{
				{Left: "ClusterId", Right: "ClusterId"},
				{Left: "ProcId", Right: "ProcId"},
			},
		}
		ex, err := cl.ExplainJoin(ctx, dbrpc.JoinRequest{Spec: spec})
		if err != nil {
			b.Fatalf("explain %s: %v", c.name, err)
		}
		out, _ := json.MarshalIndent(ex, "", "  ")
		b.Logf("%s plan:\n%s", c.name, out)
	}
	for b.Loop() {
	}
}

// BenchmarkEpochJoinHashLimit checks what a LEFT join does when the side
// it must hash is larger than MaxHashRows. A LEFT join may not exchange
// its sides, so the epoch table is always the hashed one -- and at the
// page's maximum limit (a million jobs) the epoch side is past the
// store's 500,000-row default.
func BenchmarkEpochJoinHashLimit(b *testing.B) {
	f := buildFixture(b)
	cl := dialFixture(b, f)
	ctx := context.Background()
	spec := db.JoinSpec{
		Kind:  db.JoinLeft,
		Left:  db.JoinSide{Table: "history", Alias: "h", Constraint: windowScope, Project: Projection()},
		Right: db.JoinSide{Table: "epoch_history", Alias: "e", Constraint: windowScope + ` && EpochAdType == "EPOCH"`, Project: epochProjection()},
		Cond:  []string{"h.ClusterId == e.ClusterId", "h.ProcId == e.ProcId"},
		Equi:  []db.JoinEqui{{Left: "ClusterId", Right: "ClusterId"}, {Left: "ProcId", Right: "ProcId"}},
	}
	// A tenth of the EPOCH ads this fixture holds.
	rows := 0
	err := cl.Join(ctx, dbrpc.JoinRequest{Spec: spec, Limits: db.JoinLimits{MaxHashRows: 5000}},
		func(string) bool { rows++; return true })
	b.Logf("MaxHashRows=5000 over %d EPOCH ads: %d rows, err = %v", f.jobs*118/50, rows, err)
	for b.Loop() {
	}
}
