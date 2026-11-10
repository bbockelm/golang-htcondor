package htcondor

import "testing"

// TestSubmitBehaviorForKnownReleases pins the releases either side of every
// boundary. The 25.14 row is the one the differential fuzzer pins against, so
// it is also the assertion that this table agrees with what that oracle does.
func TestSubmitBehaviorForKnownReleases(t *testing.T) {
	newest := SubmitBehavior{
		OmitExitStatus: true, OmitZeroedRunTimeCounters: true,
		OmitLeaveJobInQueueDefault: true, OmitVanillaDiskClause: true,
		OmitTransferVersionCheck: true, OmitLocalAndSchedulerMachineChecks: true,
		OmitLocalAndSchedulerResourceDefaults: true,
		OmitRemoteIOKeywords:                  true, OmitContainerIsCommonAttr: true,
		CommonContainerVanillaOnly: true,
	}
	// The backported changes: HTCONDOR-3932, which covers both the
	// Requirements clauses and container_is_common's attribute,
	// HTCONDOR-3926, and HTCONDOR-4003. They reached the 25.x feature
	// line and the 26.0 LTS line. HTCONDOR-4020 and the two halves of
	// HTCONDOR-3998 went to the 26.x feature line alone, which is what
	// separates this from newest.
	backportedOnly := SubmitBehavior{
		OmitVanillaDiskClause: true, OmitTransferVersionCheck: true,
		OmitLocalAndSchedulerMachineChecks: true, OmitLocalAndSchedulerResourceDefaults: true,
		OmitContainerIsCommonAttr: true, CommonContainerVanillaOnly: true,
	}

	cases := map[string]SubmitBehavior{
		"25.14.1":                             {},             // what the pinned fuzz oracle is
		"25.14.99":                            {},             // still before the 25.x boundary
		"25.15.16":                            backportedOnly, // the 25.x feature release that got them
		"25.16.0":                             backportedOnly, // later on that line
		"25.0.16":                             {},             // the 25 LTS line never got them
		"25.0.99":                             {},             // ...however far it goes
		"26.0.1":                              {},             // 26 LTS, before its boundary
		"26.0.2":                              backportedOnly, // 26 LTS release that got the backports
		"26.0.99":                             backportedOnly, // LTS stays without the main-only ones
		"26.1.0":                              {},             // 26 feature line, before 26.2
		"26.2.0":                              newest,         // everything lands here
		"26.3.0":                              newest,         // later on that line
		"27.0.0":                              newest,         // a line opened after the changes
		"28.4.1":                              newest,         //
		"$CondorVersion: 26.2.0 Nov 7 2026 $": newest,         // a daemon's own banner
		"26.2":                                newest,         // two components is enough
		"":                                    {},             // unparseable falls back to the oldest
		"garbage":                             {},             //
		"v26.2.0":                             {},             // not HTCondor's spelling
	}
	for version, want := range cases {
		if got := SubmitBehaviorFor(version); got != want {
			t.Errorf("SubmitBehaviorFor(%q) =\n  %+v\nwant\n  %+v", version, got, want)
		}
	}
}

// TestSubmitBehaviorForIsMonotonicWithinASeries checks the shape the fields
// are documented to have: upstream does not put these back, so walking up one
// release line never takes a behavior away.
func TestSubmitBehaviorForIsMonotonicWithinASeries(t *testing.T) {
	count := func(b SubmitBehavior) int {
		n := 0
		for _, set := range []bool{
			b.OmitExitStatus, b.OmitZeroedRunTimeCounters, b.OmitLeaveJobInQueueDefault,
			b.OmitVanillaDiskClause, b.OmitTransferVersionCheck,
			b.OmitLocalAndSchedulerMachineChecks, b.OmitLocalAndSchedulerResourceDefaults,
			b.OmitRemoteIOKeywords, b.OmitContainerIsCommonAttr,
			b.CommonContainerVanillaOnly,
		} {
			if set {
				n++
			}
		}
		return n
	}
	for _, line := range [][]string{
		{"25.0.1", "25.0.16", "25.0.99"},
		{"25.1.0", "25.14.1", "25.15.16", "25.16.0"},
		{"26.0.0", "26.0.2", "26.0.99"},
		{"26.1.0", "26.2.0", "26.9.9"},
	} {
		prev := -1
		for _, v := range line {
			n := count(SubmitBehaviorFor(v))
			if n < prev {
				t.Errorf("%s has fewer behaviors than the release before it on its line", v)
			}
			prev = n
		}
	}
}

// TestReleaseCarriesIgnoresTheOtherSeries is the rule a plain version
// comparison gets wrong. 26.0.99 is numerically above 26.2.0 in patch terms
// and below it overall, but what decides is that the LTS line never received
// the change at all.
func TestReleaseCarriesIgnoresTheOtherSeries(t *testing.T) {
	mainOnly := []string{"26.2.0"}
	cases := map[string]bool{
		"26.0.0":  false, // LTS: no threshold on its line, major not past 26
		"26.0.99": false,
		"26.1.9":  false, // feature line, before the boundary
		"26.2.0":  true,
		"27.0.0":  true, // a line that opened after the change
	}
	for s, want := range cases {
		v, ok := parseCondorVersion(s)
		if !ok {
			t.Fatalf("parse %q", s)
		}
		if got := releaseCarries(mainOnly, v); got != want {
			t.Errorf("releaseCarries(%v, %s) = %v, want %v", mainOnly, s, got, want)
		}
	}
}
