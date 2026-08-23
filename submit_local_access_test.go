package htcondor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseSubmitFileNoIncludeCommand is the sharp one: `include
// command` runs a shell command while the submit file is being parsed.
// A daemon that parses a submit file it received over an API would run
// it as the daemon's user on a remote caller's behalf.
func TestParseSubmitFileNoIncludeCommand(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")

	raw := "include command : touch " + marker + "\nexecutable = /bin/true\nqueue\n"
	if _, err := ParseSubmitFile(strings.NewReader(raw)); err == nil {
		t.Error("expected `include command` to be refused")
	} else if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("unexpected error: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("`include command` executed a shell command during parsing")
	}

	// With local access the directive works, which is what a
	// condor_submit-style client on the user's own machine expects.
	if _, err := ParseSubmitFileWithOptions(strings.NewReader(raw), SubmitParseOptions{AllowLocalAccess: true}); err != nil {
		t.Fatalf("AllowLocalAccess should permit `include command`: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("AllowLocalAccess should have run the command: %v", err)
	}
}

// TestParseSubmitFileNoInclude covers the file-read counterpart: an
// include pulls a file readable by the parsing process into the macros
// the submit file is built from.
func TestParseSubmitFileNoInclude(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.conf")
	if err := os.WriteFile(secret, []byte("STOLEN = topsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	raw := "include : \"" + secret + "\"\nexecutable = /bin/true\nqueue\n"
	if _, err := ParseSubmitFile(strings.NewReader(raw)); err == nil {
		t.Error("expected `include` to be refused")
	}

	sf, err := ParseSubmitFileWithOptions(strings.NewReader(raw), SubmitParseOptions{AllowLocalAccess: true})
	if err != nil {
		t.Fatalf("AllowLocalAccess should permit `include`: %v", err)
	}
	// Proves the include is a real read primitive, so the refusal above
	// is closing something rather than nothing.
	if got, _ := sf.cfg.Get("STOLEN"); got != "topsecret" {
		t.Errorf("expected the included file's value to be readable, got %q", got)
	}
}

// TestParseSubmitFileNoEnv covers $ENV(): the environment belongs to
// the parsing process, which may hold credentials the submitter has no
// business reading.
func TestParseSubmitFileNoEnv(t *testing.T) {
	t.Setenv("SUBMIT_LOCAL_ACCESS_PROBE", "daemon-secret")
	raw := "executable = /bin/true\narguments = \"$ENV(SUBMIT_LOCAL_ACCESS_PROBE)\"\nqueue\n"

	if sf, err := ParseSubmitFile(strings.NewReader(raw)); err == nil {
		// The refusal may surface at expansion time rather than parse
		// time; either way the value must not reach the job ad.
		if ad, adErr := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil); adErr == nil {
			if args, _ := ad.EvaluateAttrString("Arguments"); strings.Contains(args, "daemon-secret") {
				t.Errorf("$ENV() leaked the parsing process's environment: Arguments=%q", args)
			}
		}
	}

	sf, err := ParseSubmitFileWithOptions(strings.NewReader(raw), SubmitParseOptions{AllowLocalAccess: true})
	if err != nil {
		t.Fatalf("AllowLocalAccess should permit $ENV(): %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	if args, _ := ad.EvaluateAttrString("Arguments"); !strings.Contains(args, "daemon-secret") {
		t.Errorf("expected $ENV() to expand with AllowLocalAccess, got Arguments=%q", args)
	}
}

// TestParseSubmitFileNoItemdataFile covers the itemdata forms: `queue
// ... from <file>` turns any file the parsing process can read into job
// attributes the submitter can read back, and `matching` does the same
// for directory contents.
func TestParseSubmitFileNoItemdataFile(t *testing.T) {
	dir := t.TempDir()
	items := filepath.Join(dir, "items.txt")
	if err := os.WriteFile(items, []byte("alpha\nbeta\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fromFile := "executable = /bin/true\nqueue x from \"" + items + "\"\n"
	if _, err := ParseSubmitFile(strings.NewReader(fromFile)); err == nil {
		t.Error("expected `queue ... from <file>` to be refused")
	}
	sf, err := ParseSubmitFileWithOptions(strings.NewReader(fromFile), SubmitParseOptions{AllowLocalAccess: true})
	if err != nil {
		t.Fatalf("AllowLocalAccess should permit an itemdata file: %v", err)
	}
	if got := sf.queueCount; got != 2 {
		t.Errorf("expected 2 items from the itemdata file, got %d", got)
	}

	matching := "executable = /bin/true\nqueue matching \"" + filepath.Join(dir, "*.txt") + "\"\n"
	if _, err := ParseSubmitFile(strings.NewReader(matching)); err == nil {
		t.Error("expected `queue ... matching <glob>` to be refused")
	}
	if _, err := ParseSubmitFileWithOptions(strings.NewReader(matching), SubmitParseOptions{AllowLocalAccess: true}); err != nil {
		t.Fatalf("AllowLocalAccess should permit a matching glob: %v", err)
	}
}

// TestParseSubmitFileInlineItemdataStillWorks checks the refusal does
// not catch the inline `queue vars from ((rows))` form, whose temp file
// ParseSubmitFile writes itself. That form is how the web API submits
// table-shaped job sets, and it never names a caller-chosen path.
func TestParseSubmitFileInlineItemdataStillWorks(t *testing.T) {
	raw := `executable = /bin/true
arguments = $(sample) $(events)
queue sample, events from ((
  alpha, 100
  beta, 200
))
`
	sf, err := ParseSubmitFile(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("inline itemdata must still parse without local access: %v", err)
	}
	if got := sf.queueCount; got != 2 {
		t.Errorf("expected 2 jobs from the inline rows, got %d", got)
	}
}

// TestParseSubmitFileOrdinaryFilesUnaffected checks the everyday submit
// file — file names as plain values, no directives — is untouched by
// the restriction.
func TestParseSubmitFileOrdinaryFilesUnaffected(t *testing.T) {
	raw := `executable = run.sh
transfer_input_files = in.dat, /home/alice/big.root
output = out.txt
queue 3
`
	sf, err := ParseSubmitFile(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ordinary submit file must parse: %v", err)
	}
	if got := sf.queueCount; got != 3 {
		t.Errorf("expected 3 jobs, got %d", got)
	}
}
