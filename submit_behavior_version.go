package htcondor

import (
	"strconv"
	"strings"
)

// SubmitBehaviorFor returns the behavior of the HTCondor release named by
// version: the job ad that release's condor_submit would build.
//
// This is the way to set a SubmitBehavior. The individual fields say what
// each choice IS, which is what makes them reviewable, but picking a correct
// combination by hand means knowing which upstream change went into which
// release -- so the fields are the vocabulary and this is the sentence.
//
//	opts.Behavior = htcondor.SubmitBehaviorFor(scheddVersion)
//
// version may be a plain "26.2.0" or "26.2", or the whole
// "$CondorVersion: 26.2.0 Nov 7 2026 $" banner a daemon publishes in its
// CondorVersion attribute, so the value read from a schedd ad can be passed
// through unchanged. A version this library cannot parse returns the zero
// value, the behavior of the oldest releases, because a job ad carrying an
// attribute the access point ignores is harmless where one missing an
// attribute it reads is not.
//
// A release NEWER than anything named here gets every behavior, on the
// assumption that upstream does not undo these.
func SubmitBehaviorFor(version string) SubmitBehavior {
	v, ok := parseCondorVersion(version)
	if !ok {
		return SubmitBehavior{}
	}
	var b SubmitBehavior
	for _, r := range submitBehaviorReleases {
		if releaseCarries(r.since, v) {
			r.apply(&b)
		}
	}
	return b
}

// submitBehaviorReleases maps each upstream change to the first release on
// every series that carries it, and to the fields it sets.
//
// `since` holds one version per series, because HTCondor backports: a change
// can reach a 25.x release, a 26.0.x release and a 26.x release with no
// single version number that separates the ones that have it from the ones
// that do not. Each entry is the version the branch carrying the change was
// at, which is the release it first appears in.
//
// These are the releases upstream has not cut yet. When one ships, check the
// number here against the tag it actually went out in.
var submitBehaviorReleases = []struct {
	ticket string
	since  []string
	apply  func(*SubmitBehavior)
}{
	{
		ticket: "HTCONDOR-4020",
		since:  []string{"26.2.0"},
		apply:  func(b *SubmitBehavior) { b.OmitExitStatus = true },
	},
	{
		ticket: "HTCONDOR-3998",
		since:  []string{"26.2.0"},
		apply: func(b *SubmitBehavior) {
			b.OmitZeroedRunTimeCounters = true
			b.OmitLeaveJobInQueueDefault = true
		},
	},
	{
		ticket: "HTCONDOR-3998-remoteio",
		since:  []string{"26.2.0"},
		apply:  func(b *SubmitBehavior) { b.OmitRemoteIOKeywords = true },
	},
	{
		ticket: "HTCONDOR-3932-container",
		since:  []string{"25.15.16", "26.0.2", "26.2.0"},
		apply:  func(b *SubmitBehavior) { b.OmitContainerIsCommonAttr = true },
	},
	{
		ticket: "HTCONDOR-3932",
		since:  []string{"25.15.16", "26.0.2", "26.2.0"},
		apply: func(b *SubmitBehavior) {
			b.OmitVanillaDiskClause = true
			b.OmitTransferVersionCheck = true
		},
	},
	{
		ticket: "HTCONDOR-3926",
		since:  []string{"25.15.16", "26.0.2", "26.2.0"},
		apply: func(b *SubmitBehavior) {
			b.OmitLocalAndSchedulerMachineChecks = true
			b.OmitLocalAndSchedulerResourceDefaults = true
		},
	},
}

// condorVersion is a parsed HTCondor release number.
type condorVersion struct{ major, minor, patch int }

// series tells HTCondor's two kinds of release line apart. X.0.y is the
// long-term-support line of major X and takes only fixes; X.m.y with m above
// zero is the feature line. A change reaches them separately, so a version
// on one line says nothing about the other.
func (v condorVersion) isLTS() bool { return v.minor == 0 }

// compare orders two versions.
func (v condorVersion) compare(o condorVersion) int {
	for _, p := range [][2]int{{v.major, o.major}, {v.minor, o.minor}, {v.patch, o.patch}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// releaseCarries reports whether version v has a change that first appeared
// in the releases named by since.
//
// A threshold speaks only for its own series: 26.2.0 says nothing about the
// 26.0.x line, which is why a change on main alone is correctly absent from
// an LTS release with a higher patch number. When no threshold shares v's
// series, v has the change only if its major is past every one named -- a
// release line opened after the change went in starts with it.
func releaseCarries(since []string, v condorVersion) bool {
	maxMajor := -1
	for _, s := range since {
		t, ok := parseCondorVersion(s)
		if !ok {
			continue
		}
		if t.major > maxMajor {
			maxMajor = t.major
		}
		if t.major == v.major && t.isLTS() == v.isLTS() {
			return v.compare(t) >= 0
		}
	}
	return v.major > maxMajor
}

// parseCondorVersion reads "X.Y.Z", "X.Y", or the "$CondorVersion: X.Y.Z ..."
// banner a daemon publishes.
func parseCondorVersion(s string) (condorVersion, bool) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "$CondorVersion:"); i >= 0 {
		s = strings.TrimSpace(s[i+len("$CondorVersion:"):])
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, "$")
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return condorVersion{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return condorVersion{}, false
		}
		out[i] = n
	}
	return condorVersion{major: out[0], minor: out[1], patch: out[2]}, true
}
