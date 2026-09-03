package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

// TestBuildReportsSomethingUseful: the whole point is that a daemon can
// say what it is without anyone remembering to pass ldflags. A test
// binary is itself a module build, so build info is present here.
func TestBuildReportsSomethingUseful(t *testing.T) {
	b := GetBuild()

	if b.Module == "" {
		t.Error("no main module path; build info was not read")
	}
	if b.Stack.Go == "" {
		t.Error("no Go toolchain version")
	}
	// Describe is what lands in the startup banner, so it must never be
	// empty — a banner saying nothing is worse than no banner.
	if d := b.Describe(); d == "" || d == "()" {
		t.Errorf("Describe() = %q, which tells an operator nothing", d)
	}
}

// TestStackStringOmitsWhatItDoesNotKnow: a daemon built without one of
// these components should not advertise an empty version for it, which
// reads as "0" or "missing" rather than "not applicable".
func TestStackStringOmitsWhatItDoesNotKnow(t *testing.T) {
	s := Stack{ClassAd: "v0.29.7", Go: "go1.25.7"}
	got := s.String()

	if strings.Contains(got, "cedar") || strings.Contains(got, "golang-htcondor") {
		t.Errorf("stack names a component it has no version for: %q", got)
	}
	for _, want := range []string{"classad v0.29.7", "go1.25.7"} {
		if !strings.Contains(got, want) {
			t.Errorf("stack omits %q: %q", want, got)
		}
	}
}

// TestDownstreamDaemonReportsItsOwnBuild is the reported bug.
//
// htcondordb builds on this library and injects -X main.version, its
// own variable, never this module's. So CondorVersion() read the
// library defaults and every ad it published said
//
//	$CondorVersion: dev BuildID: golang-htcondor-unknown $
//
// which identifies neither the daemon nor the code in it. The build
// info the toolchain embeds already answers both, and needs no
// cooperation from a downstream Makefile.
//
// Built against a synthetic BuildInfo because a test binary's own says
// "(devel)" with no VCS stamp, and so cannot exercise this.
func TestDownstreamDaemonReportsItsOwnBuild(t *testing.T) {
	savedVersion, savedCommit := Version, Commit
	defer func() { Version, Commit = savedVersion, savedCommit }()
	Version, Commit = "dev", "unknown" // as a downstream build leaves them

	b := buildFrom(&debug.BuildInfo{
		Main: debug.Module{Path: "github.com/bbockelm/htcondordb", Version: "v0.18.6"},
		Deps: []*debug.Module{
			{Path: "github.com/PelicanPlatform/classad", Version: "v0.29.7"},
			{Path: "github.com/bbockelm/cedar", Version: "v0.6.11"},
			{Path: "github.com/bbockelm/golang-htcondor", Version: "v0.12.10"},
			{Path: "github.com/some/unrelated", Version: "v1.0.0"},
		},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "3954b36e31f7c1c2a017d9ff32171bb0666bf683"},
			{Key: "vcs.modified", Value: "false"},
		},
	}, true)

	if b.Version != "v0.18.6" {
		t.Errorf("Version = %q, want the daemon's own module version", b.Version)
	}
	if b.Module != "github.com/bbockelm/htcondordb" {
		t.Errorf("Module = %q", b.Module)
	}
	if b.ShortRevision() != "3954b36e31f7" {
		t.Errorf("ShortRevision() = %q", b.ShortRevision())
	}
	if b.Dirty {
		t.Error("Dirty set from vcs.modified=false")
	}

	// The tech stack, which is the question a combined daemon version
	// cannot answer on its own.
	if b.Stack.ClassAd != "v0.29.7" || b.Stack.Cedar != "v0.6.11" || b.Stack.GolangHTCondor != "v0.12.10" {
		t.Errorf("stack = %+v, want the three component versions", b.Stack)
	}
	if strings.Contains(b.Stack.String(), "unrelated") {
		t.Errorf("stack reports a module nobody asked about: %q", b.Stack.String())
	}
}

// TestLdflagsWinOverBuildInfo: this repo's own binaries inject a release
// version, and the module version must not overwrite it.
func TestLdflagsWinOverBuildInfo(t *testing.T) {
	saved := Version
	defer func() { Version = saved }()

	Version = "v1.2.3-release"
	b := buildFrom(&debug.BuildInfo{
		Main: debug.Module{Path: "github.com/bbockelm/golang-htcondor", Version: "v0.9.9"},
	}, true)
	if b.Version != "v1.2.3-release" {
		t.Errorf("Version = %q, want the injected value to win", b.Version)
	}
}

// TestDevelIsNotAVersion: a local build records "(devel)" for the main
// module. Reporting that as a version puts the literal string "(devel)"
// in a ClassAd attribute and a log banner, which reads like a real
// value and is not one.
func TestDevelIsNotAVersion(t *testing.T) {
	saved := Version
	defer func() { Version = saved }()
	Version = "dev"

	b := buildFrom(&debug.BuildInfo{
		Main: debug.Module{Path: "github.com/bbockelm/golang-htcondor", Version: "(devel)"},
	}, true)
	if strings.Contains(b.Stack.String(), "devel") {
		t.Errorf("stack advertises a placeholder as a version: %q", b.Stack.String())
	}
	if b.Version == "(devel)" {
		t.Error("Version reported as the placeholder")
	}
}

// TestNoBuildInfoStillDescribes: a binary built outside module mode has
// none of this. It must degrade to the ldflags values rather than
// producing an empty banner.
func TestNoBuildInfoStillDescribes(t *testing.T) {
	savedVersion, savedCommit := Version, Commit
	defer func() { Version, Commit = savedVersion, savedCommit }()
	Version, Commit = "v2.0.0", "abcdef123456"

	b := buildFrom(nil, false)
	if b.Version != "v2.0.0" || b.ShortRevision() != "abcdef123456" {
		t.Errorf("build = %+v, want the ldflags values", b)
	}
	if !strings.Contains(b.Describe(), "v2.0.0") {
		t.Errorf("Describe() = %q", b.Describe())
	}
}

// TestShortRevisionIsReadable: a full 40-character SHA in a log banner
// is noise; the short form is what people paste into a bug report.
func TestShortRevisionIsReadable(t *testing.T) {
	b := Build{Revision: "3954b36e31f7c1c2a017d9ff32171bb0666bf683"}
	if got := b.ShortRevision(); len(got) != 12 {
		t.Errorf("ShortRevision() = %q (%d chars), want 12", got, len(got))
	}
	// A short or absent revision must survive unchanged rather than
	// panic on the slice.
	if got := (Build{Revision: "abc"}).ShortRevision(); got != "abc" {
		t.Errorf("short revision mangled: %q", got)
	}
	if got := (Build{}).ShortRevision(); got != "" {
		t.Errorf("absent revision became %q", got)
	}
}

// TestUnstampedBuildSaysSo is the case a unit test can cover for the
// VCS-detection problem, and the reason a unit test cannot cover the
// rest of it.
//
// VCS stamping needs a .git directory at build time. A container build
// often has none -- this repository's own .dockerignore excludes .git --
// and the toolchain then omits the stamps SILENTLY rather than failing,
// leaving Main.Version as "(devel)" and no vcs.revision. With no ldflags
// either, the binary cannot say what it is.
//
// A test binary cannot verify that real builds get stamped: `go test`
// records no VCS settings at all, so asserting "revision is non-empty"
// would fail on every ordinary run. What is testable, and what matters
// to whoever reads the log, is that this state announces itself instead
// of printing a bare "dev" that reads like a release name.
func TestUnstampedBuildSaysSo(t *testing.T) {
	savedVersion, savedCommit := Version, Commit
	defer func() { Version, Commit = savedVersion, savedCommit }()
	Version, Commit = "dev", "unknown" // the package defaults

	b := buildFrom(&debug.BuildInfo{
		Main: debug.Module{Path: "github.com/bbockelm/golang-htcondor", Version: "(devel)"},
		// No vcs.* settings: exactly what a build without .git produces.
	}, true)

	if b.Stamped() {
		t.Error("a build with no linked version and no VCS metadata claims to be stamped")
	}
	got := b.Describe()
	if !strings.Contains(got, "unstamped") {
		t.Errorf("Describe() = %q; an unidentifiable build must say so, not read like a release named dev", got)
	}
}

// TestStampedBuildsDoNotApologize: the notice above must appear only
// when there is genuinely nothing to report. A build carrying either a
// linked version or a revision is identified, and saying "unstamped"
// there would be noise in every log line of every release.
func TestStampedBuildsDoNotApologize(t *testing.T) {
	savedVersion, savedCommit := Version, Commit
	defer func() { Version, Commit = savedVersion, savedCommit }()

	cases := map[string]Build{
		"linked version only": {Version: "v1.2.3"},
		"revision only":       {Version: "dev", Revision: "3954b36e31f7c1c2a017d9ff32171bb0666bf683"},
		"both":                {Version: "v1.2.3", Revision: "3954b36e31f7c1c2a017d9ff32171bb0666bf683"},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if !b.Stamped() {
				t.Error("an identified build reports itself unstamped")
			}
			if strings.Contains(b.Describe(), "unstamped") {
				t.Errorf("Describe() = %q, which apologizes for a build that is identified", b.Describe())
			}
		})
	}
}
