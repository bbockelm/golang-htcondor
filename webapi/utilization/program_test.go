package utilization

import (
	"slices"
	"strconv"
	"testing"
)

func TestProgram(t *testing.T) {
	for _, tc := range []struct{ cmd, args, want string }{
		{"/home/alice/sim", "", "sim"},
		{"/home/alice/sim", "--in data.txt", "sim"},
		// Container universe: no Cmd, the command in the arguments.
		{"", "python3 runner.py --circuit qft --n 20", "runner.py"},
		{"", `"python3 'runner.py' --circuit 'a b'"`, "runner.py"},
		{"", `python3 -u -W ignore /srv/app/train.py --epochs 3`, "train.py"},
		{"", "python -m torch.distributed.run --nproc 4 train.py", "torch.distributed.run"},
		{"", "python3 -c 'print(1)'", "python3"},
		{"", "", ""},
		// Interpreters as Cmd run the script that follows.
		{"/bin/bash", "script.sh arg1", "script.sh"},
		{"/bin/bash", "-x ./run_all.sh", "run_all.sh"},
		{"/bin/sh", `-c "cd /tmp && ./analyze --fast"`, "analyze"},
		{"/bin/bash", `-c "export X=1; source env.sh; module load gcc && python3 fit.py"`, "fit.py"},
		{"/bin/bash", `-c "cd /tmp"`, "bash"},
		{"/bin/bash", `-c "./analyze --fast"`, "analyze"},
		{"/bin/bash", "", "bash"},
		{"/usr/bin/env", "FOO=1 -i python3 fit.py", "fit.py"},
		{"/usr/bin/time", "-v ./crunch input", "crunch"},
		{"/usr/bin/timeout", "-s KILL 3600 ./crunch", "crunch"},
		{"/usr/bin/Rscript", "--vanilla analysis.R 3", "analysis.R"},
		{"/usr/bin/R", "CMD BATCH --no-save model.R out.log", "model.R"},
		{"/usr/bin/R", "--file=model.R", "model.R"},
		{"/usr/bin/perl", "-I lib count.pl", "count.pl"},
		{"/usr/bin/julia", "--project=. sim.jl", "sim.jl"},
		{"/usr/bin/java", "-Xmx4g -jar /opt/tool/Tool.jar --x", "Tool.jar"},
		{"/usr/bin/java", "-cp lib/* org.example.Main 3", "org.example.Main"},
		{"/usr/bin/apptainer", "exec --nv -B /data:/data image.sif python3 /opt/infer.py", "infer.py"},
		{"/usr/bin/singularity", "run --cleanenv /cvmfs/img/tool.sif --x 1", "tool.sif"},
		{"apptainer", "exec image.sif", "image.sif"},
		{"/usr/bin/python3.11", "pipeline.py", "pipeline.py"},
	} {
		if got := Program(tc.cmd, tc.args); got != tc.want {
			t.Errorf("Program(%q, %q) = %q, want %q", tc.cmd, tc.args, got, tc.want)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"a b  c", []string{"a", "b", "c"}},
		{`"a 'b c' 'it''s'"`, []string{"a", "b c", "it's"}},
		{`a \"b c\"`, []string{"a", `"b`, `c"`}},
		{`x "y z"`, []string{"x", "y z"}},
		{"", nil},
	} {
		if got := splitArgs(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("splitArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Workflows are named by the program: container jobs with no Cmd split by
// the script in their arguments, and `/bin/bash x.sh` jobs by the script,
// rather than lumping into "(unknown)" and "bash".
func TestWorkflowsSplitByProgram(t *testing.T) {
	ad := func(cluster int, cmd, args string) Job {
		text := "JobStatus = 4\nExitCode = 0\nOwner = \"alice\"\nJobUniverse = 5\nClusterId = " + strconv.Itoa(cluster) +
			"\nRemoteWallClockTime = 600.0"
		if cmd != "" {
			text += "\nCmd = " + strconv.Quote(cmd)
		}
		if args != "" {
			text += "\nArguments = " + strconv.Quote(args)
		}
		return FromAd(parseAd(t, text), "")
	}
	jobs := []Job{
		ad(1, "", "python3 runner.py --circuit a"),
		ad(2, "", "python3 runner.py --circuit b"),
		ad(3, "", "python3 other.py"),
		ad(4, "/bin/bash", "align.sh sample1"),
		ad(5, "/bin/bash", "call.sh sample1"),
	}
	var got []string
	for _, w := range Analyze(jobs, Options{}).Workflows {
		got = append(got, w.Executable+":"+strconv.Itoa(w.Jobs))
	}
	slices.Sort(got)
	if want := []string{"align.sh:1", "call.sh:1", "other.py:1", "runner.py:2"}; !slices.Equal(got, want) {
		t.Errorf("workflows = %v, want %v", got, want)
	}
}
