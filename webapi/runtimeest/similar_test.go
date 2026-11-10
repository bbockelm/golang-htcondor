package runtimeest

import (
	"fmt"
	"slices"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// historyAd is a finished job's history record.
func historyAd(t *testing.T, owner, cmd, args, batch string, cluster int64, runtime, completed int64) *classad.ClassAd {
	t.Helper()
	text := fmt.Sprintf("Owner = %q\nClusterId = %d\nProcId = 0\nCmd = %q\nArguments = %q\nJobUniverse = 5\nJobStatus = 4\nExitCode = 0\nCommittedTime = %d\nCompletionDate = %d",
		owner, cluster, cmd, args, runtime, completed)
	if batch != "" {
		text += fmt.Sprintf("\nJobBatchName = %q", batch)
	}
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

// The group at each level is decided by the estimator's own keys: the
// template ignores numbers, the batch ignores the run suffix, and every
// level stays with its owner.
func TestInGroup(t *testing.T) {
	job := historyAd(t, "alice", "/home/alice/sim", "--seed 4 --in data.txt", "sweep+101", 101, 0, 0)
	k := DeriveKeys(FeaturesFromAd(job))
	for _, tc := range []struct {
		name  string
		ad    *classad.ClassAd
		level Level
		want  bool
	}{
		{"template ignores numbers", historyAd(t, "alice", "/other/dir/sim", "--seed 9 --in data.txt", "", 7, 60, 1000), LevelTemplate, true},
		{"exact does not", historyAd(t, "alice", "/other/dir/sim", "--seed 9 --in data.txt", "", 7, 60, 1000), LevelExact, false},
		{"exact ignores directories", historyAd(t, "alice", "/x/sim", "--seed 4 --in /tmp/data.txt", "", 7, 60, 1000), LevelExact, true},
		{"template still needs the same words", historyAd(t, "alice", "/x/sim", "--seed 4 --out data.txt", "", 7, 60, 1000), LevelTemplate, false},
		{"batch ignores the run suffix", historyAd(t, "alice", "/x/other", "", "sweep+205", 205, 60, 1000), LevelBatch, true},
		{"cmd, any arguments", historyAd(t, "alice", "/x/sim", "--anything", "", 7, 60, 1000), LevelCmd, true},
		{"cluster siblings", historyAd(t, "alice", "/x/other", "", "", 101, 60, 1000), LevelCluster, true},
		{"another owner never", historyAd(t, "bob", "/home/alice/sim", "--seed 4 --in data.txt", "sweep+101", 101, 60, 1000), LevelTemplate, false},
		{"another owner, owner level", historyAd(t, "bob", "/x/sim", "", "", 7, 60, 1000), LevelOwner, false},
		{"no such level", historyAd(t, "alice", "/home/alice/sim", "--seed 4 --in data.txt", "", 101, 60, 1000), Level(len(Levels())), false},
	} {
		if got := InGroup(tc.ad, k, tc.level); got != tc.want {
			t.Errorf("%s: InGroup at %s = %v, want %v", tc.name, tc.level, got, tc.want)
		}
	}
	noBatch := DeriveKeys(FeaturesFromAd(historyAd(t, "alice", "/x/sim", "", "", 7, 0, 0)))
	if InGroup(historyAd(t, "alice", "/x/sim", "", "", 8, 60, 1000), noBatch, LevelBatch) {
		t.Error("two jobs without a batch name grouped at the batch level")
	}
}

// GroupRuntimes is the estimator's own window for the group, and the
// quantiles are interpolated the way the estimate's median is.
func TestGroupRuntimes(t *testing.T) {
	e := New(Config{})
	b := NewBatch()
	for i := range 10 {
		b.AddAd(historyAd(t, "alice", "/x/sim", fmt.Sprintf("--seed %d", i), "", int64(100+i), int64(100*(i+1)), int64(1000+i)))
	}
	e.Ingest(b)
	k := DeriveKeys(FeaturesFromAd(historyAd(t, "alice", "/x/sim", "--seed 77", "", 999, 0, 0)))
	got := e.GroupRuntimes(k, LevelTemplate)
	if !slices.Equal(got, []float64{100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}) {
		t.Fatalf("runtimes = %v", got)
	}
	// R-7: p50 of 100..1000 is 550, p10 190, p25 325, p75 775, p90 910.
	if s := Summarize(got); *s != (RuntimeSummary{Count: 10, P10: 190, P25: 325, P50: 550, P75: 775, P90: 910}) {
		t.Errorf("summary = %+v", *s)
	}
	res := e.Estimate(Query{Features: FeaturesFromAd(historyAd(t, "alice", "/x/sim", "--seed 77", "", 999, 0, 0))})
	if res.Basis == nil || res.Basis.Level != "template" || res.EstimateSeconds != 550 {
		t.Errorf("estimate = %+v; the median of the listed runtimes should be it", res)
	}
	if e.GroupRuntimes(k, LevelExact) != nil || e.WindowSize() != DefaultWindow {
		t.Error("exact group or window sizes wrong")
	}
	if New(Config{}).GroupRuntimes(k, LevelTemplate) != nil {
		t.Error("an estimator that has read nothing returned runtimes")
	}
}

func TestParseLevel(t *testing.T) {
	for _, l := range Levels() {
		if got, ok := ParseLevel(l.String()); !ok || got != l || l.Description() == "" {
			t.Errorf("%s does not round-trip", l)
		}
	}
	for _, s := range []string{"nonsense", "global"} {
		if _, ok := ParseLevel(s); ok {
			t.Errorf("parsed %q", s)
		}
	}
}
