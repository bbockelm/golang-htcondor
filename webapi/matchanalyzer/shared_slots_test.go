package matchanalyzer

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// The slot cache is shared by every analysis in the process: one user's
// analysis and another's read the same cached slots. These tests pin down
// that an analysis never binds, evaluates or mutates a cached slot ad, so
// a slot's TARGET.* expressions always see the job being analyzed.

// accessPool builds slots whose AllowedForJob depends on the job: slot i
// admits user u when i is a multiple of u+1. Each user therefore matches
// a different number of slots, and a slot evaluated against the wrong job
// changes the count.
func accessPool(t *testing.T, slots, users int) []*classad.ClassAd {
	t.Helper()
	ads := make([]*classad.ClassAd, 0, slots)
	for i := 0; i < slots; i++ {
		var allowed []string
		for u := 0; u < users; u++ {
			if i%(u+1) == 0 {
				allowed = append(allowed, fmt.Sprintf("user%d", u))
			}
		}
		ads = append(ads, makeSlotAd(t, fmt.Sprintf(
			`[ Name = "slot%d@h%d"; Machine = "h%d"; Cpus = 4; AllowedUsers = "%s"; AllowedForJob = stringListMember(TARGET.Owner, AllowedUsers) ]`,
			i, i, i, strings.Join(allowed, ","))))
	}
	return ads
}

func accessJob(t *testing.T, user int) *classad.ClassAd {
	t.Helper()
	return makeSlotAd(t, fmt.Sprintf(
		`[ Owner = "user%d"; Requirements = (TARGET.AllowedForJob == true) && (TARGET.Cpus >= 1) ]`, user))
}

// cachedProvider returns a CollectorSlotProvider whose cache is already
// warm, so every analysis below is served the cached slots.
func cachedProvider(t *testing.T, ads []*classad.ClassAd) (*CollectorSlotProvider, *fakeQuerier) {
	t.Helper()
	q := &fakeQuerier{ads: ads}
	p := NewCollectorSlotProvider(q, WithSlotCacheTTL(time.Hour))
	if _, err := p.Slots(context.Background(), []string{"*"}); err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	return p, q
}

// matchSummary is the part of a Result that depends on which job a slot
// was evaluated against.
type matchSummary struct {
	FullMatches int
	Matched     []int
	Values      []AttributeDistribution
}

func summarize(res *Result) matchSummary {
	s := matchSummary{FullMatches: res.FullMatches}
	for _, p := range res.Predicates {
		s.Matched = append(s.Matched, p.Matched)
		s.Values = append(s.Values, p.AttributeDistributions...)
	}
	return s
}

// Concurrent analyses for different users over the same cached slots must
// each produce exactly what that user's analysis produces alone. Run with
// -race: binding a shared slot to a job is a write that every other
// analysis reads.
func TestConcurrentAnalysesOverCachedSlotsMatchSequential(t *testing.T) {
	const slots, users = 60, 6
	p, q := cachedProvider(t, accessPool(t, slots, users))

	want := make([]matchSummary, users)
	for u := 0; u < users; u++ {
		res, err := New(p).Analyze(context.Background(), accessJob(t, u))
		if err != nil {
			t.Fatalf("baseline user%d: %v", u, err)
		}
		want[u] = summarize(res)
	}
	// The pool is built so users disagree; otherwise a cross-bound slot
	// would go unnoticed.
	if want[0].FullMatches == want[1].FullMatches {
		t.Fatalf("pool does not distinguish users: %d vs %d", want[0].FullMatches, want[1].FullMatches)
	}

	const workers, rounds = 8, 25
	var wg sync.WaitGroup
	errs := make(chan string, workers*rounds)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				u := (w + r) % users
				res, err := New(p).Analyze(context.Background(), accessJob(t, u))
				if err != nil {
					errs <- fmt.Sprintf("user%d: %v", u, err)
					continue
				}
				if got := summarize(res); !reflect.DeepEqual(got, want[u]) {
					errs <- fmt.Sprintf("user%d: concurrent result %+v, alone %+v", u, got, want[u])
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	n := 0
	for e := range errs {
		if n < 5 {
			t.Error(e)
		}
		n++
	}
	if n > 0 {
		t.Errorf("%d of %d concurrent analyses disagreed with the same analysis run alone", n, workers*rounds)
	}
	if got := q.callCount(); got != 1 {
		t.Errorf("collector queried %d times; every analysis should have been served the cache", got)
	}
}

// Deterministic form of the cross-user case. Analysis A binds the slot to
// job A and is held there; analysis B then runs to completion over the
// same cached slot; A resumes and evaluates. A's slot must still see job
// A. With the binding stored on a shared slot ad, B's bind replaced it
// and A evaluated the slot's TARGET.Owner against B's job.
func TestAnalysisSlotBindingSurvivesAnotherAnalysis(t *testing.T) {
	ads := []*classad.ClassAd{makeSlotAd(t,
		`[ Name = "slot1@h1"; Machine = "h1"; Cpus = 4; AllowedUsers = "alice"; AllowedForJob = stringListMember(TARGET.Owner, AllowedUsers) ]`)}
	p, _ := cachedProvider(t, ads)

	alice := makeSlotAd(t, `[ Owner = "alice"; Requirements = (TARGET.AllowedForJob == true) ]`)
	bob := makeSlotAd(t, `[ Owner = "bob"; Requirements = (TARGET.AllowedForJob == true) ]`)

	bound := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	a := New(p)
	a.afterBind = func(_, _ *classad.ClassAd) {
		once.Do(func() {
			close(bound)
			select {
			case <-resume:
			case <-time.After(10 * time.Second):
			}
		})
	}

	type outcome struct {
		res *Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := a.Analyze(context.Background(), alice)
		done <- outcome{res, err}
	}()

	select {
	case <-bound:
	case <-time.After(10 * time.Second):
		t.Fatal("analysis A never bound its slot")
	}
	resB, err := New(p).Analyze(context.Background(), bob)
	close(resume)
	if err != nil {
		t.Fatalf("analysis B: %v", err)
	}
	outA := <-done
	if outA.err != nil {
		t.Fatalf("analysis A: %v", outA.err)
	}

	if resB.FullMatches != 0 {
		t.Errorf("bob: FullMatches = %d, want 0 (slot admits only alice)", resB.FullMatches)
	}
	if outA.res.FullMatches != 1 {
		t.Errorf("alice: FullMatches = %d, want 1; her slot was evaluated against another job", outA.res.FullMatches)
	}
	for _, d := range outA.res.Predicates[0].AttributeDistributions {
		if d.Attribute != "AllowedForJob" {
			continue
		}
		if len(d.Values) != 1 || d.Values[0].Value != "true" {
			t.Errorf("alice: AllowedForJob distribution = %+v, want only true", d.Values)
		}
	}
}

// An analysis must leave no binding behind: not on the cached slots (which
// would keep the last job ad alive for the life of the cache entry and
// hand it to the next reader) and not on the caller's job ad.
func TestAnalyzeLeavesCachedSlotsAndJobUnbound(t *testing.T) {
	p, q := cachedProvider(t, accessPool(t, 8, 2))
	job := accessJob(t, 0)
	a := New(p)
	boundDuring := 0
	a.afterBind = func(_, _ *classad.ClassAd) {
		if job.GetTarget() != nil {
			boundDuring++
		}
	}
	if _, err := a.Analyze(context.Background(), job); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if boundDuring > 0 {
		t.Errorf("caller's job ad was bound to a slot during %d slot evaluations", boundDuring)
	}
	for i, ad := range q.ads {
		if ad.GetTarget() != nil {
			t.Errorf("collector ad %d is still bound to a job after the analysis", i)
		}
	}
	if job.GetTarget() != nil {
		t.Error("caller's job ad is still bound to a slot after the analysis")
	}
	again, err := p.Slots(context.Background(), []string{"*"})
	if err != nil {
		t.Fatalf("Slots: %v", err)
	}
	for i, ad := range again {
		if ad.GetTarget() != nil {
			t.Errorf("cached slot %d is still bound to a job after the analysis", i)
		}
	}
}

// Each call gets ads of its own: a change one caller makes to a slot ad is
// invisible to the next caller and to the cache.
func TestCollectorSlotProviderHandsOutPrivateAds(t *testing.T) {
	p, q := cachedProvider(t, accessPool(t, 3, 2))
	first, err := p.Slots(context.Background(), []string{"Cpus"})
	if err != nil {
		t.Fatalf("Slots: %v", err)
	}
	first[0].InsertAttr("Cpus", 99)
	first[0].InsertAttr("Extra", 1)

	second, err := p.Slots(context.Background(), []string{"Cpus"})
	if err != nil {
		t.Fatalf("Slots: %v", err)
	}
	if q.callCount() != 1 {
		t.Fatalf("collector queried %d times; want the cache", q.callCount())
	}
	if first[0] == second[0] {
		t.Fatal("two calls were handed the same *ClassAd")
	}
	if got, _ := second[0].EvaluateAttrInt("Cpus"); got != 4 {
		t.Errorf("second caller sees Cpus = %d; the first caller's change leaked into the cache", got)
	}
	if _, ok := second[0].Lookup("Extra"); ok {
		t.Error("second caller sees an attribute the first caller added")
	}
	if got, _ := q.ads[0].EvaluateAttrInt("Cpus"); got != 4 {
		t.Errorf("collector's ad sees Cpus = %d; the cache wrote through to it", got)
	}

	var streamed []*classad.ClassAd
	if err := p.StreamSlots(context.Background(), []string{"Cpus"}, func(ad *classad.ClassAd) bool {
		streamed = append(streamed, ad)
		return true
	}); err != nil {
		t.Fatalf("StreamSlots: %v", err)
	}
	if len(streamed) != len(second) || streamed[0] == second[0] {
		t.Error("the streaming fallback handed out a cached ad instead of a copy")
	}
}

// benchSlot is a slot ad as the analyzer's projection brings it back from
// the collector: the attributes a typical Requirements reads, the
// identity attributes, and a few slot-side expressions that read the job.
func benchSlot(i int) string {
	return fmt.Sprintf(`[ Name = "slot1_%d@node%d.example.org"; Machine = "node%d.example.org"; SlotID = 1;
		Arch = "X86_64"; OpSys = "LINUX"; OpSysAndVer = "AlmaLinux9"; Cpus = %d; Memory = %d; Disk = %d;
		GPUs = %d; HasFileTransfer = true; HasSingularity = true; IsGlidein = %t;
		Start = (TARGET.RequestMemory <= Memory) && (TARGET.RequestCpus <= Cpus);
		WithinResourceLimits = (TARGET.RequestDisk <= Disk);
		AllowedForJob = stringListMember(TARGET.Owner, "alice,bob,carol") ]`,
		i, i, i, 1<<(i%5), 1024*(1+i%32), 1048576*(1+i%8), i%7/6, i%3 == 0)
}

func BenchmarkAnalyzeCachedSlots(b *testing.B) {
	for _, n := range []int{10000, 20000} {
		b.Run(fmt.Sprintf("slots=%d", n), func(b *testing.B) {
			ads := make([]*classad.ClassAd, n)
			for i := range ads {
				ad, err := classad.Parse(benchSlot(i))
				if err != nil {
					b.Fatal(err)
				}
				ads[i] = ad
			}
			q := &fakeQuerier{ads: ads}
			p := NewCollectorSlotProvider(q, WithSlotCacheTTL(time.Hour))
			if _, err := p.Slots(context.Background(), []string{"*"}); err != nil {
				b.Fatal(err)
			}
			job, err := classad.Parse(`[ Owner = "alice"; RequestCpus = 4; RequestMemory = 8192; RequestDisk = 2097152;
				Requirements = (TARGET.Arch == "X86_64") && (TARGET.OpSys == "LINUX") && (TARGET.Disk >= RequestDisk) &&
					(TARGET.Memory >= RequestMemory) && (TARGET.Cpus >= RequestCpus) && TARGET.HasFileTransfer &&
					TARGET.Start && TARGET.WithinResourceLimits && TARGET.AllowedForJob ]`)
			if err != nil {
				b.Fatal(err)
			}
			a := New(p)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := a.Analyze(context.Background(), job)
				if err != nil {
					b.Fatal(err)
				}
				if res.TotalSlots != n {
					b.Fatalf("TotalSlots = %d, want %d", res.TotalSlots, n)
				}
			}
		})
	}
}
