package htcondor

import (
	"path/filepath"
	"strings"
	"testing"
)

// Every expected value in this file was measured against HTCondor's own
// SubmitHash through the differential oracle in fuzz/submit, not read off the
// Go implementation. The measurements, for a submit directory D:
//
//	executable = sleep                 -> Cmd     = D/sleep
//	log = j.log                        -> UserLog = D/j.log
//	log = j.log, initialdir = sub      -> UserLog = D/sub/j.log, Cmd = D/sleep
//	executable = ./sleep               -> Cmd     = D/./sleep
//	executable = a//b                  -> Cmd     = D/a/b
//	executable = /bin/sleep            -> Cmd     = /bin/sleep
//	transfer_executable = FALSE        -> Cmd     = sleep
//	transfer_executable = 0 or no      -> Cmd     = D/sleep
//	universe = vm / grid ec2           -> Cmd     = <as written>
//	output/error/input = o.out ...     -> Out/Err/In = <as written>

// submitInDir parses src with the process's working directory set to a real
// directory the test owns, and returns that directory's path together with the
// first proc ad. The directory is resolved through EvalSymlinks first, so the
// expected values do not come from the same os.Getwd call the code under test
// uses, and so the two cannot differ over a symlink: on macOS t.TempDir hands
// back a /var path whose real name is /private/var, and os.Getwd prefers $PWD
// (which t.Chdir sets) whenever it names the same directory.
func submitInDir(t *testing.T, src string) (dir string, ad map[string]string) {
	t.Helper()

	tmp := t.TempDir()
	realDir, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", tmp, err)
	}
	t.Chdir(realDir)

	sf, err := ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseSubmitFile(%q): %v", src, err)
	}
	sub, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit(%q): %v", src, err)
	}
	if len(sub.ProcAds) != 1 {
		t.Fatalf("got %d proc ads, want 1", len(sub.ProcAds))
	}

	attrs := make(map[string]string)
	for _, name := range sub.ProcAds[0].GetAttributes() {
		v, ok := sub.ProcAds[0].EvaluateAttrString(name)
		if !ok {
			continue
		}
		attrs[name] = v
	}
	return realDir, attrs
}

func wantAttr(t *testing.T, ad map[string]string, name, want string) {
	t.Helper()
	got, ok := ad[name]
	if !ok {
		t.Fatalf("%s is missing; want %q", name, want)
	}
	if got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}

func TestSubmitResolvesRelativeExecutableAndLog(t *testing.T) {
	dir, ad := submitInDir(t, "executable = sleep\nlog = j.log\nqueue\n")
	wantAttr(t, ad, "Cmd", dir+"/sleep")
	wantAttr(t, ad, "UserLog", dir+"/j.log")
	wantAttr(t, ad, "Iwd", dir)
}

// initialdir moves the job's working directory and its log, and deliberately
// does NOT move the executable: SetExecutable calls full_path with use_iwd
// false, so the executable is still looked for where condor_submit ran.
func TestSubmitResolvesLogAgainstInitialdirButExecutableAgainstCwd(t *testing.T) {
	dir, ad := submitInDir(t, "executable = sleep\nlog = j.log\ninitialdir = sub\nqueue\n")
	wantAttr(t, ad, "Iwd", dir+"/sub")
	wantAttr(t, ad, "UserLog", dir+"/sub/j.log")
	wantAttr(t, ad, "Cmd", dir+"/sleep")
}

func TestSubmitKeepsAbsolutePathsAsWritten(t *testing.T) {
	_, ad := submitInDir(t, "executable = /bin/sleep\nlog = /var/tmp/j.log\ninitialdir = /tmp\nqueue\n")
	wantAttr(t, ad, "Cmd", "/bin/sleep")
	wantAttr(t, ad, "UserLog", "/var/tmp/j.log")
	wantAttr(t, ad, "Iwd", "/tmp")
}

// compress_path collapses repeated separators and nothing else, so a dot
// component survives into the ad exactly as the user wrote it.
func TestSubmitResolvedPathsKeepDotComponents(t *testing.T) {
	dir, ad := submitInDir(t, "executable = ./sleep\nlog = ./d/../j.log\nqueue\n")
	wantAttr(t, ad, "Cmd", dir+"/./sleep")
	wantAttr(t, ad, "UserLog", dir+"/./d/../j.log")
}

func TestSubmitResolvedPathsCollapseRepeatedSlashes(t *testing.T) {
	dir, ad := submitInDir(t, "executable = a//b\nlog = x//y.log\nqueue\n")
	wantAttr(t, ad, "Cmd", dir+"/a/b")
	wantAttr(t, ad, "UserLog", dir+"/x/y.log")
}

// An executable that is not transferred names a path on the EXECUTE machine,
// so resolving it against a submit-side directory would name a file that is
// not there.
func TestSubmitLeavesUntransferredExecutableAsWritten(t *testing.T) {
	_, ad := submitInDir(t, "executable = sleep\ntransfer_executable = FALSE\nqueue\n")
	wantAttr(t, ad, "Cmd", "sleep")
}

// SetExecutable turns transfer off only for a value starting with 'f' or 'F',
// which is not the same test as parsing the value as a boolean: both of these
// are transferred, and so both are resolved.
func TestSubmitTransferExecutableIsNotParsedAsABoolean(t *testing.T) {
	for _, value := range []string{"0", "no"} {
		t.Run(value, func(t *testing.T) {
			dir, ad := submitInDir(t, "executable = sleep\ntransfer_executable = "+value+"\nqueue\n")
			wantAttr(t, ad, "Cmd", dir+"/sleep")
		})
	}
}

// vm universe and the ec2/gce/azure grid types do not have an executable at
// all -- the value is only the job's name -- and SetExecutable leaves it alone.
func TestSubmitLeavesNonFileExecutableAsWritten(t *testing.T) {
	cases := map[string]string{
		"vm":  "universe = vm\nvm_type = kvm\nvm_memory = 128\nvm_disk = /tmp/d.img:hda:w\nexecutable = myvmjob\nqueue\n",
		"ec2": "universe = grid\ngrid_resource = ec2 https://example.com\nexecutable = myjob\nec2_ami_id = ami-1\nqueue\n",
		// The grid type is matched case-insensitively.
		"EC2": "universe = grid\ngrid_resource = EC2 https://example.com\nexecutable = myjob\nec2_ami_id = ami-1\nqueue\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			_, ad := submitInDir(t, src)
			if got := ad["Cmd"]; got != "myvmjob" && got != "myjob" {
				t.Errorf("Cmd = %q, want the name as written", got)
			}
		})
	}
}

// A batch grid type DOES have a real executable, so it is resolved; only the
// cloud types are exempt.
func TestSubmitResolvesExecutableForBatchGridType(t *testing.T) {
	dir, ad := submitInDir(t, "universe = grid\ngrid_resource = batch slurm\nexecutable = sleep\nqueue\n")
	wantAttr(t, ad, "Cmd", dir+"/sleep")
}

// The three standard streams are NOT resolved: SetStdin/SetStdout/SetStderr
// keep the name as written and the starter resolves it in the sandbox.
func TestSubmitLeavesStandardStreamsUnresolved(t *testing.T) {
	_, ad := submitInDir(t, "executable = /bin/sleep\noutput = o.out\nerror = e.err\ninput = i.in\nqueue\n")
	wantAttr(t, ad, "Out", "o.out")
	wantAttr(t, ad, "Err", "e.err")
	wantAttr(t, ad, "In", "i.in")
}

// An empty log names no file: C++ records no UserLog at all rather than an
// empty one, and an empty UserLog would otherwise be resolved into the Iwd
// itself.
func TestSubmitEmptyLogRecordsNoUserLog(t *testing.T) {
	_, ad := submitInDir(t, "executable = /bin/sleep\nlog =\nqueue\n")
	if got, ok := ad["UserLog"]; ok {
		t.Errorf("UserLog = %q, want it unset", got)
	}
}

func TestCompressPath(t *testing.T) {
	cases := map[string]string{
		"/a//b":      "/a/b",
		"//a":        "/a",
		"/a/./b":     "/a/./b",
		"/a/../b":    "/a/../b",
		"/a///b////": "/a/b/",
		"a":          "a",
		"":           "",
		`/a\\b`:      `/a\b`,
	}
	for in, want := range cases {
		if got := compressPath(in); got != want {
			t.Errorf("compressPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFullPath(t *testing.T) {
	cases := []struct{ name, base, want string }{
		{"sleep", "/d", "/d/sleep"},
		{"/bin/sleep", "/d", "/bin/sleep"},
		{"./sleep", "/d", "/d/./sleep"},
		{"a//b", "/d", "/d/a/b"},
		// full_path has no notion of a URL: HTCondor joins it like any
		// other relative name, and the ad carries the join.
		{"http://example.com/a.sh", "/d", "/d/http:/example.com/a.sh"},
	}
	for _, c := range cases {
		if got := fullPath(c.name, c.base); got != c.want {
			t.Errorf("fullPath(%q, %q) = %q, want %q", c.name, c.base, got, c.want)
		}
	}
}

func TestJobIwdFallsBackToWorkingDirectory(t *testing.T) {
	tmp := t.TempDir()
	realDir, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(realDir)

	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\nqueue\n"))
	if err != nil {
		t.Fatal(err)
	}
	iwd, err := sf.jobIwd()
	if err != nil {
		t.Fatal(err)
	}
	if iwd != realDir {
		t.Errorf("jobIwd() = %q, want %q", iwd, realDir)
	}
}
