package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRootConfig writes a root configuration file and points
// CONDOR_CONFIG at it.
func writeRootConfig(t *testing.T, body string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "condor_config")
	if err := os.WriteFile(root, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONDOR_CONFIG", root)
}

// TestRootConfigInclude is the reported case: a root file that is a thin
// wrapper around an include used to come up with nothing from the
// included file and no error.
func TestRootConfigInclude(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub.conf")
	if err := os.WriteFile(sub, []byte("FOO = bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRootConfig(t, "include : "+sub+"\nBAZ = qux\n")

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("FOO"); got != "bar" {
		t.Errorf("Get(FOO) = %q, want bar (the include must be processed)", got)
	}
	// The assignment beside it must still be read.
	if got, _ := cfg.Get("BAZ"); got != "qux" {
		t.Errorf("Get(BAZ) = %q, want qux", got)
	}
}

// TestRootConfigIncludeIsRelativeToNothing checks a missing include is
// an error rather than a silent skip — the whole point of the report was
// that a dropped include produced no diagnostic.
func TestRootConfigMissingIncludeErrors(t *testing.T) {
	writeRootConfig(t, "include : /nonexistent/definitely-not-here.conf\n")

	if _, err := New(); err == nil {
		t.Error("expected a missing include to be reported")
	}
}

// TestRootConfigIncludeIfExist is the tolerated form: absent file, no
// error.
func TestRootConfigIncludeIfExist(t *testing.T) {
	writeRootConfig(t, "include ifexist : /nonexistent/definitely-not-here.conf\nFOO = bar\n")

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("FOO"); got != "bar" {
		t.Errorf("Get(FOO) = %q, want bar", got)
	}
}

// TestRootConfigIncludeCommand covers the command form in the root file.
func TestRootConfigIncludeCommand(t *testing.T) {
	writeRootConfig(t, "include command : echo FROM_COMMAND = yes\n")

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("FROM_COMMAND"); got != "yes" {
		t.Errorf("Get(FROM_COMMAND) = %q, want yes", got)
	}
}

// TestRootConfigConditional covers if/else/endif in the root file, both
// branches, so a test cannot pass by the conditional being ignored
// wholesale.
func TestRootConfigConditional(t *testing.T) {
	writeRootConfig(t, `TAKEN = no
NOT_TAKEN = no
if true
  TAKEN = yes
else
  NOT_TAKEN = yes
endif
`)
	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("TAKEN"); got != "yes" {
		t.Errorf("Get(TAKEN) = %q, want yes (the if branch must run)", got)
	}
	if got, _ := cfg.Get("NOT_TAKEN"); got != "no" {
		t.Errorf("Get(NOT_TAKEN) = %q, want no (the else branch must not run)", got)
	}
}

// TestRootConfigHeredoc covers a heredoc value in the root file. The old
// KEY = VALUE scanner split "SCRIPT @=END" on the "=" inside the tag and
// stored garbage.
func TestRootConfigHeredoc(t *testing.T) {
	writeRootConfig(t, `SCRIPT @=END
line one
line two
@END
AFTER = read
`)
	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, _ := cfg.Get("SCRIPT")
	if !strings.Contains(got, "line one") || !strings.Contains(got, "line two") {
		t.Errorf("Get(SCRIPT) = %q, want the heredoc body", got)
	}
	// Parsing must resume after the terminator.
	if got, _ := cfg.Get("AFTER"); got != "read" {
		t.Errorf("Get(AFTER) = %q, want read", got)
	}
}

// TestRootConfigContinuationAndComments guards what the old scanner did
// handle, since it was replaced: continuations join and comments are
// dropped.
func TestRootConfigContinuationAndComments(t *testing.T) {
	writeRootConfig(t, `# a comment
JOINED = one \
  two
# COMMENTED = should-not-appear
LAST = end
`)
	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, _ := cfg.Get("JOINED")
	if !strings.Contains(got, "one") || !strings.Contains(got, "two") {
		t.Errorf("Get(JOINED) = %q, want the continued value", got)
	}
	if _, ok := cfg.Get("COMMENTED"); ok {
		t.Error("a commented-out assignment must not be read")
	}
	if got, _ := cfg.Get("LAST"); got != "end" {
		t.Errorf("Get(LAST) = %q, want end", got)
	}
}

// TestRootConfigLocalChainStillRuns checks the local chain the root file
// points at is still processed after the root file itself — the change
// touches how the root file is read, not the order of the chain.
func TestRootConfigLocalChainStillRuns(t *testing.T) {
	dir := t.TempDir()
	confd := filepath.Join(dir, "config.d")
	if err := os.MkdirAll(confd, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confd, "50-late.config"),
		[]byte("FROM_CONFD = yes\nOVERRIDDEN = late\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(root,
		[]byte("OVERRIDDEN = early\nLOCAL_CONFIG_DIR = "+confd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONDOR_CONFIG", root)

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("FROM_CONFD"); got != "yes" {
		t.Errorf("Get(FROM_CONFD) = %q, want yes", got)
	}
	if got, _ := cfg.Get("OVERRIDDEN"); got != "late" {
		t.Errorf("Get(OVERRIDDEN) = %q, want late (config.d wins over the root file)", got)
	}
}
