package runtimeest

import (
	"slices"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func adFrom(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatalf("parse ad: %v", err)
	}
	return ad
}

// stripOwner drops the "owner\x1f" prefix so expectations read plainly.
func stripOwner(key string) string {
	if i := strings.Index(key, keySep); i >= 0 {
		return key[i+1:]
	}
	return key
}

func TestFeaturesFromAdPrefersV2Arguments(t *testing.T) {
	f := FeaturesFromAd(adFrom(t, `Owner = "alice"
ClusterId = 12
Cmd = "/home/alice/run.sh"
Arguments = "--in 'my file.txt' --n 5"
Args = "ignored"
Iwd = "/home/alice/exp3"
JobBatchName = "sweep"`))
	if f.Owner != "alice" || f.ClusterID != 12 || f.Cmd != "/home/alice/run.sh" ||
		f.Iwd != "/home/alice/exp3" || f.BatchName != "sweep" {
		t.Errorf("features = %+v", f)
	}
	if !slices.Equal(f.Args, []string{"--in", "my file.txt", "--n", "5"}) {
		t.Errorf("args = %q", f.Args)
	}

	f = FeaturesFromAd(adFrom(t, `Owner = "alice"
Cmd = "run.sh"
Args = "a b  c"`))
	if !slices.Equal(f.Args, []string{"a", "b", "c"}) {
		t.Errorf("V1 args = %q", f.Args)
	}
}

func TestCommandKeyLooksThroughInterpreters(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		args     []string
		wantKey  string
		wantArgv []string
	}{
		{"plain program", "/usr/bin/blast", []string{"-db", "nt"}, "blast", []string{"-db", "nt"}},
		{"python script", "/usr/bin/python3", []string{"-u", "/home/a/train.py", "--epochs", "10"},
			"python3 train.py", []string{"--epochs", "10"}},
		{"sh -c with a quoted body", "/bin/sh", []string{"-c", "cd /data && ./run.sh 5 > out.txt"},
			"sh -c", []string{"cd", "/data", "./run.sh", "5", "out.txt"}},
		{"bash -lc", "bash", []string{"-lc", "make -j4; ./bench"},
			"bash -c", []string{"make", "-j4", "./bench"}},
		{"python -c", "python", []string{"-c", "print(1)"}, "python -c", []string{"print(1)"}},
		{"env assignments", "/usr/bin/env", []string{"OMP_NUM_THREADS=4", "python3", "x.py"},
			"env python3", []string{"x.py"}},
		{"apptainer exec", "apptainer", []string{"exec", "--nv", "/cvmfs/img.sif", "run.sh", "3"},
			"apptainer img.sif", []string{"run.sh", "3"}},
		{"interpreter with only flags", "python3", []string{"-V"}, "python3", []string{"-V"}},
		{"interpreter with no args", "bash", nil, "bash", nil},
		{"no command", "", []string{"x"}, "", nil},
		{"a lone -l is not -c", "bash", []string{"-l", "script.sh"}, "bash script.sh", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, argv := commandKey(tc.cmd, tc.args)
			if key != tc.wantKey {
				t.Errorf("key = %q, want %q", key, tc.wantKey)
			}
			if len(argv) != len(tc.wantArgv) || (len(argv) > 0 && !slices.Equal(argv, tc.wantArgv)) {
				t.Errorf("argv = %q, want %q", argv, tc.wantArgv)
			}
		})
	}
}

func TestTokenNormalization(t *testing.T) {
	cases := []struct {
		tok, norm, mask string
	}{
		{"https://example.org/data/x.tar.gz", "<url>", "<url>"},
		{"/data/run12/in_003.dat", "in_003.dat", "in_<n>.dat"},
		{"--seed=42", "--seed=42", "--seed=<N>"},
		{"input=/scratch/u/file7.txt", "input=file7.txt", "input=file<n>.txt"},
		{"8f28ab17adda4631", "<HEX>", "<HEX>"},
		{"12345678", "12345678", "<N>"},
		{"-3.5e2", "-3.5e2", "<N>"},
		{"deadbeef", "<HEX>", "<HEX>"},
		{"cafe", "cafe", "cafe"},
		{"v2", "v2", "v<n>"},
		{"=x", "=x", "=x"},
	}
	for _, tc := range cases {
		if got := normToken(tc.tok); got != tc.norm {
			t.Errorf("normToken(%q) = %q, want %q", tc.tok, got, tc.norm)
		}
		if got := maskToken(tc.tok); got != tc.mask {
			t.Errorf("maskToken(%q) = %q, want %q", tc.tok, got, tc.mask)
		}
	}
}

func TestIsNumber(t *testing.T) {
	for _, s := range []string{"0", "42", "-7", "+3", "1.5", "2e10", "1.0E-3"} {
		if !isNumber(s) {
			t.Errorf("isNumber(%q) = false", s)
		}
	}
	for _, s := range []string{"", "-", "1.", ".5", "1e", "NaN", "Inf", "0x10", "1_000", "12a"} {
		if isNumber(s) {
			t.Errorf("isNumber(%q) = true", s)
		}
	}
}

// A DAG node's Cmd is under a spool directory named for its cluster.
// Two runs of the same node are the same program.
func TestSpoolPathsReduceToTheScript(t *testing.T) {
	a := DeriveKeys(Features{Owner: "u", ClusterID: 12094943,
		Cmd: "/var/lib/condor/spool/4943/0/cluster12094943.proc0.subproc0/analyze.sh"})
	b := DeriveKeys(Features{Owner: "u", ClusterID: 12095001,
		Cmd: "/var/lib/condor/spool/5001/0/cluster12095001.proc0.subproc0/analyze.sh"})
	for _, l := range []Level{LevelCmd, LevelExact, LevelTemplate} {
		if a.Key(l) != b.Key(l) {
			t.Errorf("%s: %q != %q", l, a.Key(l), b.Key(l))
		}
	}
	if stripOwner(a.Key(LevelCmd)) != "analyze.sh" {
		t.Errorf("cmd key = %q", a.Key(LevelCmd))
	}
	if a.Key(LevelCluster) == b.Key(LevelCluster) {
		t.Error("different clusters share a cluster key")
	}
}

func TestBatchStem(t *testing.T) {
	cases := map[string]string{
		"htcondor-api-interactive-terminal-8f28ab17adda4631": "htcondor-api-interactive-terminal",
		"ablation.dag+12111467":                              "ablation.dag",
		"sweep_run_3":                                        "sweep_run",
		"run-12-34":                                          "run",
		"sweep":                                              "sweep",
		"decade":                                             "decade",
		"12345":                                              "",
		"":                                                   "",
	}
	for in, want := range cases {
		if got := BatchStem(in); got != want {
			t.Errorf("BatchStem(%q) = %q, want %q", in, got, want)
		}
	}
	if got := BatchStem("\tspaced \n"); got != "spaced" {
		t.Errorf("surrounding whitespace kept: %q", got)
	}
}

func TestDeriveKeys(t *testing.T) {
	k := DeriveKeys(Features{
		Owner: "alice", ClusterID: 7, Cmd: "/home/alice/sim",
		Args: []string{"--steps", "1000", "/data/run4/cfg.yaml"},
		Iwd:  "/home/alice/exp12", BatchName: "sweep+77",
	})
	want := map[Level]string{
		LevelCluster:  "7",
		LevelExact:    "sim --steps 1000 cfg.yaml",
		LevelTemplate: "sim --steps <N> cfg.yaml",
		LevelBatch:    "sweep",
		LevelIwd:      "/home/alice/exp<n>",
		LevelCmd:      "sim",
	}
	for l, w := range want {
		if got := stripOwner(k.Key(l)); got != w {
			t.Errorf("%s = %q, want %q", l, got, w)
		}
	}
	if k.Key(LevelOwner) != "alice" || k.Owner() != "alice" {
		t.Errorf("owner key = %q", k.Key(LevelOwner))
	}
	for l := LevelCluster; l < LevelOwner; l++ {
		if !strings.HasPrefix(k.Key(l), "alice"+keySep) {
			t.Errorf("%s key %q is not confined to the owner", l, k.Key(l))
		}
	}
}

// A job with no batch name or working directory must not share a key
// with every other such job: the level is skipped instead.
func TestDeriveKeysSkipsEmptyComponents(t *testing.T) {
	k := DeriveKeys(Features{Owner: "alice", Cmd: "x"})
	for _, l := range []Level{LevelBatch, LevelIwd, LevelCluster} {
		if k.Key(l) != "" {
			t.Errorf("%s = %q, want skipped", l, k.Key(l))
		}
	}
	k = DeriveKeys(Features{Owner: "alice", BatchName: "123"})
	if k.Key(LevelBatch) != "" {
		t.Errorf("a batch name that is all run number gave key %q", k.Key(LevelBatch))
	}
	if k.Key(LevelCmd) != "" || k.Key(LevelExact) != "" {
		t.Error("a job with no Cmd got command keys")
	}
	k = DeriveKeys(Features{Cmd: "x", BatchName: "b", Iwd: "/d"})
	for l := LevelCluster; l < LevelGlobal; l++ {
		if k.Key(l) != "" {
			t.Errorf("owner-less job got %s key %q", l, k.Key(l))
		}
	}
}

// Two owners running the identical command never share a group.
func TestKeysAreOwnerConfined(t *testing.T) {
	a := DeriveKeys(Features{Owner: "alice", Cmd: "x", Iwd: "/d", BatchName: "b", ClusterID: 1})
	b := DeriveKeys(Features{Owner: "bob", Cmd: "x", Iwd: "/d", BatchName: "b", ClusterID: 1})
	for l := LevelCluster; l < LevelGlobal; l++ {
		if a.Key(l) == b.Key(l) {
			t.Errorf("%s: alice and bob share key %q", l, a.Key(l))
		}
	}
}
