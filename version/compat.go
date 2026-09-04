package version

import "strings"

// HTCondorCompat is the C++ HTCondor release whose wire protocol this
// library claims compatibility with.
//
// This is deliberately NOT this module's own version, and the two must
// not be conflated. A C++ peer parses the CondorVersion string we
// publish with CondorVersionInfo::string_to_VersionData
// (condor_ver_info.cpp), which does:
//
//	sscanf(ptr, "%d.%d.%d ", &Major, &Minor, &SubMinor)
//	if (cfld != 3 || Major < 6 || Minor > 99 || SubMinor > 99) return false;
//
// So a Go-module version -- "v0.18.7", or "dev" in an unstamped build --
// does not parse at all: the leading 'v' defeats the sscanf, and even
// bare "0.18.7" fails the Major < 6 sanity check. A peer that cannot
// parse our version is left with MajorVer == 0, i.e. it concludes we
// predate every feature it might negotiate, and every
// built_since_version() gate it checks against us answers false.
//
// Peers use that answer to pick protocol behavior, so this value is a
// capability floor, not decoration. Raising it asserts that we
// implement what the C++ side gates on between the old and new values.
// Most such gates are paired with an explicit capability attribute
// (HasCommonFilesTransfer, LvmBackingStore) that we do not advertise,
// but some are version-only -- for example the shadow enables delayed
// attribute updates for any peer built since 25.3.0. Audit the
// built_since_version() calls in the range before raising this.
//
// 25.4.0 is the value the file-transfer and peek paths in this library
// already put on the wire against real C++ daemons, so it is the level
// this implementation is actually exercised at.
const HTCondorCompat = "25.4.0"

// CondorVersionString renders the "$CondorVersion: ... $" string that a
// C++ peer can parse, carrying our own identity in the BuildID segment
// where it is informational rather than protocol-bearing.
//
// The trailing " $" is required, not stylistic: the C++ parser ends with
//
//	ver.Rest.erase(ver.Rest.find(" $"));
//
// and std::string::erase throws std::out_of_range when find returns npos,
// so a string without it does worse than fail to parse.
func CondorVersionString(buildID string) string {
	buildID = strings.TrimSpace(buildID)
	if buildID == "" {
		buildID = "unknown"
	}
	return "$CondorVersion: " + HTCondorCompat + " BuildID: golang-htcondor-" + buildID + " $"
}

// BuildID describes the running binary for the BuildID segment: our own
// version and revision, which is what an operator needs to map a daemon
// in a pool back to a commit.
func (b Build) BuildID() string {
	parts := make([]string, 0, 2)
	// "dev" and "(devel)" are placeholders for "nobody stamped this",
	// not versions; see Build.Stamped. Emitting them as an identity
	// would make an unstamped build indistinguishable from a release.
	if v := b.Version; v != "" && v != devel && v != "dev" {
		parts = append(parts, v)
	}
	if r := b.ShortRevision(); r != "" {
		parts = append(parts, r)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	id := strings.Join(parts, "-")
	if b.Dirty {
		id += "-dirty"
	}
	return id
}
