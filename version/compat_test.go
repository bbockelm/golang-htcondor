package version

import (
	"fmt"
	"strings"
	"testing"
)

// parseLikeCondor reimplements CondorVersionInfo::string_to_VersionData
// (condor_ver_info.cpp) closely enough to catch strings a C++ peer would
// reject. It returns the parsed version, or an error describing how the
// C++ side would fail.
//
// The C++ code, in order:
//
//	if (strncmp(verstring, "$CondorVersion: ", 16) != 0) return false;
//	ptr = strchr(verstring, ' ') + 1;
//	cfld = sscanf(ptr, "%d.%d.%d ", &Major, &Minor, &SubMinor);
//	if (cfld != 3 || Major < 6 || Minor > 99 || SubMinor > 99) return false;
//	ptr = strchr(ptr, ' ') + 1;               // must exist
//	ver.Rest = ptr;
//	ver.Rest.erase(ver.Rest.find(" $"));      // throws if " $" absent
func parseLikeCondor(s string) (major, minor, sub int, err error) {
	const prefix = "$CondorVersion: "
	if !strings.HasPrefix(s, prefix) {
		return 0, 0, 0, fmt.Errorf("missing %q prefix", prefix)
	}
	rest := s[len(prefix):]

	// sscanf("%d.%d.%d") stops at the first character that cannot
	// continue an integer, so a leading "v" yields zero conversions.
	n, _ := fmt.Sscanf(rest, "%d.%d.%d", &major, &minor, &sub)
	if n != 3 {
		return 0, 0, 0, fmt.Errorf("version field %q is not three integers (sscanf converted %d)", firstField(rest), n)
	}
	if major < 6 {
		return 0, 0, 0, fmt.Errorf("major version %d fails the C++ sanity check (< 6)", major)
	}
	if minor > 99 || sub > 99 {
		return 0, 0, 0, fmt.Errorf("minor/subminor %d.%d out of range (> 99)", minor, sub)
	}
	// The parser then requires a space after the version numbers.
	if !strings.Contains(rest, " ") {
		return 0, 0, 0, fmt.Errorf("no space after the version numbers")
	}
	// ver.Rest.erase(find(" $")) throws std::out_of_range when absent.
	if !strings.HasSuffix(s, " $") {
		return 0, 0, 0, fmt.Errorf(`missing trailing " $": erase(npos) throws std::out_of_range in the peer`)
	}
	return major, minor, sub, nil
}

func firstField(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// TestParseLikeCondorRejectsWhatCppRejects checks the test's own model of
// the C++ parser against the cases that motivated this code, so a green
// run below means something.
func TestParseLikeCondorRejectsWhatCppRejects(t *testing.T) {
	bad := map[string]string{
		"go module version": "$CondorVersion: v0.18.7 BuildID: golang-htcondor-dd1334bc $",
		"unstamped build":   "$CondorVersion: dev BuildID: golang-htcondor-unknown $",
		"semver without v":  "$CondorVersion: 0.18.7 BuildID: golang-htcondor-dd1334bc $",
		// The container workflow stamps untagged main builds as
		// 0.0.0-<branch>-<timestamp>, which is what the deployed API daemon
		// reported. It is the subtlest shape here: sscanf converts three
		// integers from it, so it clears the cfld != 3 check and only the
		// Major < 6 sanity check rejects it.
		"untagged main build": "$CondorVersion: 0.0.0-main-20260904002529 BuildID: golang-htcondor-abc1234 $",
		"two-part version":    "$CondorVersion: 25.4 BuildID: x $",
		"no trailing dollar":  "$CondorVersion: 25.4.0 BuildID: x",
		"wrong prefix":        "$CondorVer: 25.4.0 BuildID: x $",
	}
	for name, s := range bad {
		if _, _, _, err := parseLikeCondor(s); err == nil {
			t.Errorf("%s: %q parsed, but a C++ peer would reject it", name, s)
		}
	}

	good := "$CondorVersion: 25.4.0 BuildID: golang-htcondor-v0.18.7-dd1334bc $"
	if maj, minor, sub, err := parseLikeCondor(good); err != nil {
		t.Errorf("%q: %v", good, err)
	} else if maj != 25 || minor != 4 || sub != 0 {
		t.Errorf("parsed %d.%d.%d, want 25.4.0", maj, minor, sub)
	}
}

// TestCondorVersionStringIsParseable is the regression guard: every
// CondorVersion this library emits must survive the C++ parser,
// whatever the local build stamping looks like.
func TestCondorVersionStringIsParseable(t *testing.T) {
	buildIDs := []string{
		"",                     // no identity at all
		"unknown",              // unstamped build
		"v0.18.7-dd1334bc",     // released build
		"v0.18.7-dd1334-dirty", // dirty working tree
		"   ",                  // whitespace only
	}
	for _, id := range buildIDs {
		s := CondorVersionString(id)
		maj, minor, sub, err := parseLikeCondor(s)
		if err != nil {
			t.Errorf("BuildID %q produced %q, which a C++ peer rejects: %v", id, s, err)
			continue
		}
		if got := fmt.Sprintf("%d.%d.%d", maj, minor, sub); got != HTCondorCompat {
			t.Errorf("BuildID %q: peer reads version %s, want HTCondorCompat %s", id, got, HTCondorCompat)
		}
		if !strings.Contains(s, "golang-htcondor") {
			t.Errorf("BuildID %q: %q loses the golang-htcondor marker", id, s)
		}
	}
}

// TestHTCondorCompatIsAValidHTCondorVersion pins the constant itself.
// It is a protocol capability floor, so it must both parse and stay a
// version a real HTCondor ever shipped.
func TestHTCondorCompatIsAValidHTCondorVersion(t *testing.T) {
	var maj, minor, sub int
	if n, _ := fmt.Sscanf(HTCondorCompat, "%d.%d.%d", &maj, &minor, &sub); n != 3 {
		t.Fatalf("HTCondorCompat = %q is not a three-part version", HTCondorCompat)
	}
	if maj < 6 {
		t.Errorf("HTCondorCompat major %d fails the C++ sanity check (< 6)", maj)
	}
	if minor > 99 || sub > 99 {
		t.Errorf("HTCondorCompat = %q has a component > 99", HTCondorCompat)
	}
	if strings.HasPrefix(HTCondorCompat, "v") {
		t.Errorf("HTCondorCompat = %q must not carry a Go-style leading v", HTCondorCompat)
	}
}
