package utilization

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// The analysis is asked to handle up to HTTP_API_UTILIZATION_MAX_JOBS
// (default a million) jobs at once. These benchmarks report what that
// costs: the bytes each held Job takes, and Analyze's time and garbage.
//
//	go test ./utilization/ -run '^$' -bench . -benchtime 1x

// synthJobs is n finished jobs across 40 workflows of 7 owners, with the
// strings shared the way a JobReader shares them.
func synthJobs(n int) []Job {
	const workflows = 40
	var owners, batches, cmds [workflows]string
	for w := range workflows {
		owners[w] = fmt.Sprintf("user%d", w%7)
		batches[w] = fmt.Sprintf("batch-%d", w)
		cmds[w] = fmt.Sprintf("/home/user%d/bin/prog%d.sh", w%7, w)
	}
	out := make([]Job, 0, n)
	for i := range n {
		w := i % workflows
		wall := float64(600 + i%7200)
		j := Job{
			Cluster: int64(1000000 + i/100), Proc: int64(i % 100),
			Owner: owners[w], BatchName: batches[w], Cmd: cmds[w],
			Universe: 5, Status: statusCompleted, ExitCode: NumOf(0),
			QDate: int64(1760000000 + i), FirstStart: int64(1760000100 + i),
			Entered: int64(1760003600 + i), Completion: int64(1760003600 + i),
			RequestMemory: NumOf(float64(1024 * (1 + w%8))), RequestCpus: NumOf(float64(1 + w%4)),
			RequestDisk: NumOf(1048576), MemoryUsage: NumOf(float64(300 + i%900)),
			DiskUsage: NumOf(204800), Wall: wall, CPUSeconds: NumOf(wall * 0.8),
			CommittedTime: NumOf(wall), NumJobStarts: 1,
		}
		if w%10 == 0 {
			j.RequestGPUs = NumOf(1)
			j.GPUsAverageUsage = NumOf(float64(i%10) / 10)
		}
		out = append(out, j)
	}
	return out
}

func heapInUse() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// BenchmarkJobFootprint reports the bytes one held Job costs.
func BenchmarkJobFootprint(b *testing.B) {
	const n = 1000000
	for b.Loop() {
		before := heapInUse()
		jobs := synthJobs(n)
		after := heapInUse()
		b.ReportMetric(float64(after-before)/n, "held-B/job")
		runtime.KeepAlive(jobs)
	}
}

// BenchmarkReadJobs reports reading Jobs from ads through a JobReader:
// time per ad, and the bytes each Job holds once the ads are gone.
func BenchmarkReadJobs(b *testing.B) {
	const n = 100000
	texts := make([]string, 20)
	for k := range texts {
		texts[k] = fmt.Sprintf(`ClusterId = %d
ProcId = 0
Owner = "user%d"
JobBatchName = "batch-%d"
Cmd = "/home/user%d/bin/prog.sh"
JobUniverse = 5
JobStatus = 4
ExitCode = 0
QDate = 1760000000
JobStartDate = 1760000100
EnteredHistoryTime = 1760003600
CompletionDate = 1760003600
RequestCpus = 1
RequestMemory = 2048
RequestDisk = 1048576
ResidentSetSize = 512000
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
DiskUsage = 204800
RemoteWallClockTime = 3600.0
CommittedTime = 3600
CumulativeRemoteUserCpu = 3000.0
CumulativeRemoteSysCpu = 10.0
NumJobStarts = 1`, 1000+k, k%7, k%5, k%7)
	}
	for b.Loop() {
		before := heapInUse()
		var r JobReader
		jobs := make([]Job, 0, n)
		for i := range n {
			ad, err := classad.ParseOld(texts[i%len(texts)])
			if err != nil {
				b.Fatal(err)
			}
			jobs = append(jobs, r.FromAd(ad, ""))
		}
		after := heapInUse()
		b.ReportMetric(float64(after-before)/n, "held-B/job")
		runtime.KeepAlive(jobs)
	}
}

// BenchmarkAnalyze reports Analyze over 50,000 and 1,000,000 jobs.
func BenchmarkAnalyze(b *testing.B) {
	for _, n := range []int{50000, 1000000} {
		b.Run(fmt.Sprintf("jobs=%d", n), func(b *testing.B) {
			jobs := synthJobs(n)
			pool := make([]Machine, 100)
			for i := range pool {
				pool[i] = Machine{Cpus: 32, MemoryMiB: 128 * 1024, DiskKiB: 1 << 30, GPUs: float64(i % 2 * 4)}
			}
			b.ReportAllocs()
			for b.Loop() {
				Analyze(jobs, Options{Days: 30, ShowOwner: true, Machines: pool})
			}
		})
	}
}

// synthPool is n jobs spread over about n/91 workflows (the ratio seen on
// a real access point: 10,948 workflows in a million jobs), most of them
// small and a few holding most of the jobs, across 200 owners.
func synthPool(n int) []Job {
	workflows := max(n/91, 1)
	owners := make([]string, 200)
	for i := range owners {
		owners[i] = fmt.Sprintf("user%03d", i)
	}
	progs := make([]string, workflows)
	for i := range progs {
		progs[i] = fmt.Sprintf("/home/u/prog%05d.sh", i)
	}
	out := make([]Job, 0, n)
	seed := uint64(7)
	for i := range n {
		seed = seed*6364136223846793005 + 1442695040888963407
		u := float64(seed>>11) / float64(1<<53)
		w := int(float64(workflows) * u * u * u)
		wall := float64(300 + i%7200)
		j := Job{
			Cluster: int64(1000000 + i/50), Proc: int64(i % 50),
			Owner: owners[w%len(owners)], Cmd: progs[w], Program: base(progs[w]),
			Universe: 5, Status: statusCompleted, ExitCode: NumOf(0),
			QDate: int64(1760000000 + i), FirstStart: int64(1760000300 + i), Completion: int64(1760003600 + i),
			RequestMemory: NumOf(float64(1024 * (1 + w%8))), RequestCpus: NumOf(float64(1 + w%4)),
			RequestDisk: NumOf(1048576), MemoryUsage: NumOf(float64(300 + i%900)),
			DiskUsage: NumOf(204800), Wall: wall, CPUSeconds: NumOf(wall * 0.8), CommittedTime: NumOf(wall), NumJobStarts: 1,
		}
		if w%25 == 0 {
			j.RequestGPUs, j.GPUsAverageUsage = NumOf(1), NumOf(float64(i%10)/10)
		}
		out = append(out, j)
	}
	return out
}

// BenchmarkResponseSize reports the JSON size of the compact answer the
// list endpoint sends, against the full one it replaced.
func BenchmarkResponseSize(b *testing.B) {
	for _, n := range []int{50000, 250000, 1000000} {
		b.Run(fmt.Sprintf("jobs=%d", n), func(b *testing.B) {
			jobs := synthPool(n)
			for b.Loop() {
				resp := Analyze(jobs, Options{Days: 30, ShowOwner: true})
				full, _ := json.Marshal(resp)
				summary, _ := json.Marshal(Summarize(resp))
				b.ReportMetric(float64(len(resp.Workflows)), "workflows")
				b.ReportMetric(float64(len(full))/1e6, "full-MB")
				b.ReportMetric(float64(len(summary))/1e6, "summary-MB")
			}
		})
	}
}

// realisticAd is a history record as the mirror returns it with the full
// projection: a container job with a long quoted argument list and a
// formula memory request.
func realisticAd(i int) string {
	return fmt.Sprintf(`ClusterId = %d
ProcId = %d
Owner = "user%d"
JobBatchName = "ny50.dag+%d"
DAGManJobId = %d
Cmd = ""
Args = "python3 runner.py --circuit ny50_%d --depth 40 --shots 1000 --backend 'aer simulator' --seed %d --out /srv/out/run_%d.json"
JobUniverse = 5
QDate = %d
CompletionDate = %d
EnteredHistoryTime = %d
EnteredCurrentStatus = %d
JobStartDate = %d
JobCurrentStartDate = %d
JobStatus = 4
ExitCode = 0
ExitBySignal = false
RequestMemory = ifthenelse((MemoryUsage isnt undefined), max({ 2048,((3 * MemoryUsage) / 2) }), 2048)
RequestCpus = 1
RequestDisk = 4194304
ResidentSetSize = 2500000
ResidentSetSize_RAW = 2371234
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
DiskUsage = 1000000
DiskUsage_RAW = 966340
RemoteWallClockTime = 3812.0
RemoteUserCpu = 3500.0
RemoteSysCpu = 40.0
CumulativeRemoteUserCpu = 3500.0
CumulativeRemoteSysCpu = 40.0
CommittedTime = 3812
NumJobStarts = 1
NumHoldsByReason = [ JobOutOfResources = 1 ]
LastHoldReasonCode = 34
LastHoldReasonSubCode = 102
VacateReasonCode = 34
VacateReasonSubCode = 102`, 100000+i/100, i%100, i%50, 99000+i/1000, 99000+i/1000, i%9, i, i, 1760000000+i, 1760003800+i, 1760003800+i, 1760003800+i, 1760000100+i, 1760000100+i)
}

func BenchmarkRealisticParse(b *testing.B) {
	text := realisticAd(1)
	for b.Loop() {
		if _, err := classad.ParseOld(text); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRealisticFromAd(b *testing.B) {
	ads := make([]*classad.ClassAd, 1000)
	for i := range ads {
		ads[i], _ = classad.ParseOld(realisticAd(i))
	}
	b.Run("FromAd", func(b *testing.B) {
		var r JobReader
		i := 0
		for b.Loop() {
			_ = r.FromAd(ads[i%len(ads)], "")
			i++
		}
	})
	b.Run("program", func(b *testing.B) {
		for b.Loop() {
			_ = Program("", "python3 runner.py --circuit ny50_1 --depth 40 --shots 1000 --backend 'aer simulator' --seed 7 --out /srv/out/run_7.json")
		}
	})
	b.Run("adaptive", func(b *testing.B) {
		var reader JobReader
		i := 0
		for b.Loop() {
			var j Job
			j.MemoryUsage = NumOf(2316)
			j.readAdaptive(ads[i%len(ads)], &reader)
			i++
		}
	})
}

// BenchmarkDecode is reading records into Jobs: on the goroutine that
// reads them, and through a Decoder on every core.
func BenchmarkDecode(b *testing.B) {
	rows := make([]string, 20000)
	for i := range rows {
		rows[i] = realisticAd(i)
	}
	b.Run("sequential", func(b *testing.B) {
		for b.Loop() {
			var r JobReader
			jobs := make([]Job, 0, len(rows))
			for _, row := range rows {
				ad, err := classad.ParseOld(row)
				if err != nil {
					b.Fatal(err)
				}
				jobs = append(jobs, r.FromAd(ad, ""))
			}
			if len(jobs) != len(rows) {
				b.Fatalf("decoded %d of %d", len(jobs), len(rows))
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(rows)), "ns/record")
	})
	b.Run("decoder", func(b *testing.B) {
		for b.Loop() {
			d := NewDecoder(0)
			for _, row := range rows {
				d.Row(row)
			}
			if chunks, _ := d.Finish(); Count(chunks) != len(rows) {
				b.Fatalf("decoded %d of %d", Count(chunks), len(rows))
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(rows)), "ns/record")
	})
}
