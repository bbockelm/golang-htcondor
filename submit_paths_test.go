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

// The grid credential and data files below are the second place HTCondor
// resolves a path: SetGridParams calls full_path on each one, against Iwd
// rather than against the submitting directory the executable uses. Every
// expected value here was measured against SubmitHash through the oracle in
// fuzz/submit, for a submit directory D:
//
//	ec2_access_key_id = akey           -> EC2AccessKeyId     = D/akey
//	ec2_secret_access_key = skey       -> EC2SecretAccessKey = D/skey
//	ec2_keypair_file = kpfile          -> EC2KeyPairFile     = D/kpfile
//	ec2_key_pair_file = kpfile         -> EC2KeyPairFile     = D/kpfile
//	ec2_keypair = k + ec2_keypair_file -> EC2KeyPairFile unset
//	ec2_user_data_file = udfile        -> EC2UserDataFile    = D/udfile
//	ec2_user_data_file = http://h/x    -> EC2UserDataFile    = D/http:/h/x
//	ec2_access_key_id = from instance  -> both credentials   = FROM INSTANCE
//	gce_auth_file = ./auth.json        -> GceAuthFile        = D/./auth.json
//	gce_json_file = sub//j.json        -> GceJsonFile        = D/sub/j.json
//	azure_auth_file = ./a//b/auth.json -> AzureAuthFile      = D/./a/b/auth.json
//	initialdir = sub                   -> all of them under D/sub

const ec2Job = "universe = grid\ngrid_resource = ec2 https://example.com\n" +
	"executable = myjob\nec2_ami_id = ami-1\n"

func TestSubmitResolvesEC2CredentialAndDataFiles(t *testing.T) {
	dir, ad := submitInDir(t, ec2Job+
		"ec2_access_key_id = akey\nec2_secret_access_key = skey\n"+
		"ec2_keypair_file = kpfile\nec2_user_data_file = udfile\nqueue\n")
	wantAttr(t, ad, "EC2AccessKeyId", dir+"/akey")
	wantAttr(t, ad, "EC2SecretAccessKey", dir+"/skey")
	wantAttr(t, ad, "EC2KeyPairFile", dir+"/kpfile")
	wantAttr(t, ad, "EC2UserDataFile", dir+"/udfile")
}

func TestSubmitResolvesGceAndAzureAuthFiles(t *testing.T) {
	gce := "universe = grid\ngrid_resource = gce https://example.com proj zone\n" +
		"executable = myjob\ngce_image = img\ngce_machine_type = mt\n"
	dir, ad := submitInDir(t, gce+"gce_auth_file = ./auth.json\ngce_json_file = sub//j.json\nqueue\n")
	wantAttr(t, ad, "GceAuthFile", dir+"/./auth.json")
	wantAttr(t, ad, "GceJsonFile", dir+"/sub/j.json")

	azure := "universe = grid\ngrid_resource = azure sub-id\nexecutable = myjob\n" +
		"azure_image = img\nazure_size = sz\nazure_location = loc\n"
	dir, ad = submitInDir(t, azure+"azure_auth_file = ./a//b/auth.json\nqueue\n")
	wantAttr(t, ad, "AzureAuthFile", dir+"/./a/b/auth.json")
}

// Resolution is against Iwd, so initialdir moves these files -- unlike the
// executable, which stays with the submitting directory.
func TestSubmitResolvesGridFilesAgainstInitialdir(t *testing.T) {
	dir, ad := submitInDir(t, ec2Job+
		"initialdir = sub\nec2_access_key_id = akey\nec2_user_data_file = udfile\nqueue\n")
	wantAttr(t, ad, "Iwd", dir+"/sub")
	wantAttr(t, ad, "EC2AccessKeyId", dir+"/sub/akey")
	wantAttr(t, ad, "EC2UserDataFile", dir+"/sub/udfile")
}

// full_path has no URL case here either: a transfer-plugin scheme is joined
// like any other relative name and the repeated separator collapses.
func TestSubmitResolvesGridFileThatLooksLikeAURL(t *testing.T) {
	dir, ad := submitInDir(t, ec2Job+"ec2_user_data_file = http://host/x\nqueue\n")
	wantAttr(t, ad, "EC2UserDataFile", dir+"/http:/host/x")
}

func TestSubmitKeepsAbsoluteGridFilesAsWritten(t *testing.T) {
	_, ad := submitInDir(t, ec2Job+"ec2_access_key_id = /abs//akey\nqueue\n")
	wantAttr(t, ad, "EC2AccessKeyId", "/abs/akey")
}

// ec2_key_pair_file is the second spelling SetGridParams accepts.
func TestSubmitAcceptsBothKeyPairFileSpellings(t *testing.T) {
	dir, ad := submitInDir(t, ec2Job+"ec2_key_pair_file = kpfile\nqueue\n")
	wantAttr(t, ad, "EC2KeyPairFile", dir+"/kpfile")
}

// A named keypair makes the file meaningless, and C++ drops the file rather
// than recording a path the gridmanager would then write to.
func TestSubmitDropsKeyPairFileWhenAKeyPairIsNamed(t *testing.T) {
	_, ad := submitInDir(t, ec2Job+"ec2_keypair = mykp\nec2_keypair_file = kpfile\nqueue\n")
	wantAttr(t, ad, "EC2KeyPair", "mykp")
	if got, ok := ad["EC2KeyPairFile"]; ok {
		t.Errorf("EC2KeyPairFile = %q, want it unset", got)
	}
}

// The one EC2 credential value that is not a filename: it names the
// instance's own IAM role, is matched without regard to case, and setting
// either half of the credential to it sets both.
func TestSubmitEC2InstanceRoleCredentialIsNotAPath(t *testing.T) {
	for _, src := range []string{
		"ec2_access_key_id = from instance\n",
		"ec2_secret_access_key = FROM INSTANCE\n",
	} {
		t.Run(src, func(t *testing.T) {
			_, ad := submitInDir(t, ec2Job+src+"queue\n")
			wantAttr(t, ad, "EC2AccessKeyId", "FROM INSTANCE")
			wantAttr(t, ad, "EC2SecretAccessKey", "FROM INSTANCE")
		})
	}
}
