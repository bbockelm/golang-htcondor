package utilization

import (
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
