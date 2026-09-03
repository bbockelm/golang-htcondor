package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// Where version information comes from, and why it is not just ldflags.
//
// Version and Commit are injected with -ldflags when this repository
// builds its own binaries. That does not carry across repositories: a
// daemon built elsewhere on top of this library -- htcondordb, the
// collector -- would have to know to inject THIS module's variables
// into ITS build, which nothing tells it to do. htcondordb's Makefile
// sets -X main.version, its own, so every ad it published read
//
//	$CondorVersion: dev BuildID: golang-htcondor-unknown $
//
// which says nothing about what is actually running.
//
// The Go toolchain already embeds the answer. A module build records
// the main module's version, the VCS revision and whether the tree was
// dirty, and the resolved version of every dependency. So ldflags stay
// authoritative when present, and build info fills in what they do not
// cover -- which for a downstream daemon is everything.

// Stack names the versions of the Go components a daemon is built from.
// These are the ones an operator triaging a pool actually asks about:
// the HTCondor protocol implementation, the ClassAd engine, and the
// CEDAR wire library.
type Stack struct {
	// GolangHTCondor is this library's version as linked into the
	// running binary. Empty when this module IS the main module.
	GolangHTCondor string `json:"golang_htcondor,omitempty"`
	ClassAd        string `json:"classad,omitempty"`
	Cedar          string `json:"cedar,omitempty"`
	// Go is the toolchain that compiled the binary.
	Go string `json:"go"`
}

// String renders the stack for a log line or an ad attribute.
func (s Stack) String() string {
	parts := make([]string, 0, 4)
	if s.GolangHTCondor != "" {
		parts = append(parts, "golang-htcondor "+s.GolangHTCondor)
	}
	if s.ClassAd != "" {
		parts = append(parts, "classad "+s.ClassAd)
	}
	if s.Cedar != "" {
		parts = append(parts, "cedar "+s.Cedar)
	}
	if s.Go != "" {
		parts = append(parts, s.Go)
	}
	return strings.Join(parts, ", ")
}

// Build is everything known about how the running binary was produced.
type Build struct {
	// Module is the main module's path, e.g. github.com/bbockelm/htcondordb.
	// Empty for a binary built outside module mode.
	Module string `json:"module,omitempty"`
	// Version is the release this binary claims: the ldflags value when
	// set, else the main module's version.
	Version string `json:"version"`
	// Revision is the VCS commit, and Dirty reports uncommitted changes
	// at build time. Both come from the toolchain's VCS stamping.
	Revision string `json:"revision,omitempty"`
	Dirty    bool   `json:"dirty,omitempty"`
	Stack    Stack  `json:"stack"`
}

// Stamped reports whether this binary carries any identity at all: a
// version somebody chose, or a revision the toolchain recorded.
//
// It can be false, and that is worth saying out loud rather than
// printing a bare "dev". VCS stamping needs a .git directory at build
// time, which a container build does not necessarily have -- this
// repository's own .dockerignore excludes it -- and Go omits the stamps
// silently in that case rather than failing. Without ldflags to fall
// back on, the result is a binary that cannot say what it is. An
// operator reading "dev" cannot tell that apart from a release actually
// named dev; reading "unstamped build" they can.
func (b Build) Stamped() bool {
	return b.Revision != "" || (b.Version != "" && b.Version != "dev")
}

// module paths whose versions are worth reporting.
const (
	pathGolangHTCondor = "github.com/bbockelm/golang-htcondor"
	pathClassAd        = "github.com/PelicanPlatform/classad"
	pathCedar          = "github.com/bbockelm/cedar"
)

var (
	buildOnce sync.Once
	buildInfo Build
)

// GetBuild returns the running binary's build information, reading the
// embedded build info once.
func GetBuild() Build {
	buildOnce.Do(func() { buildInfo = readBuild() })
	return buildInfo
}

func readBuild() Build {
	bi, ok := debug.ReadBuildInfo()
	return buildFrom(bi, ok)
}

// devel is what the toolchain records as the main module's version for
// a build that is not from a tagged module -- a local `go build`, or a
// test binary. It is a placeholder, not a version, so it is never
// reported as one.
const devel = "(devel)"

// buildFrom assembles the Build from embedded info. Split out so the
// resolution rules can be tested against a realistic build -- a test
// binary's own build info always says "(devel)" with no VCS stamp, so
// it cannot exercise the case this exists for.
func buildFrom(bi *debug.BuildInfo, ok bool) Build {
	b := Build{
		Version: Version,
		Stack:   Stack{Go: runtime.Version()},
	}
	if Commit != "" && Commit != "unknown" {
		b.Revision = Commit
	}

	if !ok || bi == nil {
		return b
	}
	b.Module = bi.Main.Path

	// An ldflags version wins; "dev" is this package's placeholder for
	// "nobody said", so it does not.
	if b.Version == "" || b.Version == "dev" {
		if v := bi.Main.Version; v != "" && v != devel {
			b.Version = v
		}
	}

	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if b.Revision == "" {
				b.Revision = s.Value
			}
		case "vcs.modified":
			b.Dirty = s.Value == "true"
		}
	}

	// This module's own version is absent from Deps when it IS the main
	// module -- there is no dependency on yourself -- so take it from
	// the main module in that case.
	if bi.Main.Path == pathGolangHTCondor && bi.Main.Version != devel {
		b.Stack.GolangHTCondor = bi.Main.Version
	}
	for _, d := range bi.Deps {
		switch d.Path {
		case pathGolangHTCondor:
			b.Stack.GolangHTCondor = d.Version
		case pathClassAd:
			b.Stack.ClassAd = d.Version
		case pathCedar:
			b.Stack.Cedar = d.Version
		}
	}
	return b
}

// ShortRevision is the revision abbreviated for human-facing output.
func (b Build) ShortRevision() string {
	if len(b.Revision) > 12 {
		return b.Revision[:12]
	}
	return b.Revision
}

// Describe renders the build for a log banner: the version, the commit
// it came from, and whether the tree was dirty when it was built.
func (b Build) Describe() string {
	out := b.Version
	if out == "" {
		out = "unknown"
	}
	if r := b.ShortRevision(); r != "" {
		out += " (" + r
		if b.Dirty {
			out += ", dirty"
		}
		out += ")"
		return out
	}
	if !b.Stamped() {
		// Name the reason, because the fix is in the build rather than
		// anywhere an operator can reach at runtime.
		out += " (unstamped build: no version linked in and no VCS metadata)"
	}
	return out
}
