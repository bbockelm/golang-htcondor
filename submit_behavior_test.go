package htcondor

import (
	"strings"
	"testing"
)

// behaviorAd parses the simplest submit file under one behavior and returns
// the attribute names it produced, lower-cased.
func behaviorAd(t *testing.T, b SubmitBehavior) map[string]bool {
	t.Helper()
	sf, err := ParseSubmitFileWithOptions(
		strings.NewReader("executable = /bin/true\nqueue\n"),
		SubmitParseOptions{Behavior: b})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	names := map[string]bool{}
	for _, n := range ad.GetAttributes() {
		names[strings.ToLower(n)] = true
	}
	return names
}

// TestSubmitBehaviorOmitsWhatItSays pins both shapes of every gate. One side
// alone is not enough: a gate that is never off produces the new ad for
// everyone, and a gate that is never on is dead code that reads as support
// for a release it does not actually produce.
func TestSubmitBehaviorOmitsWhatItSays(t *testing.T) {
	cases := []struct {
		name     string
		behavior SubmitBehavior
		gated    []string
	}{
		{
			name:     "OmitExitStatus",
			behavior: SubmitBehavior{OmitExitStatus: true},
			gated:    []string{"exitstatus"},
		},
		{
			name:     "OmitZeroedRunTimeCounters",
			behavior: SubmitBehavior{OmitZeroedRunTimeCounters: true},
			gated:    []string{"remoteusercpu", "remotesyscpu", "lastsuspensiontime", "exitbysignal"},
		},
		{
			name:     "OmitLeaveJobInQueueDefault",
			behavior: SubmitBehavior{OmitLeaveJobInQueueDefault: true},
			gated:    []string{"leavejobinqueue"},
		},
	}

	def := behaviorAd(t, SubmitBehavior{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			on := behaviorAd(t, tc.behavior)
			for _, attr := range tc.gated {
				if !def[attr] {
					t.Errorf("%s is absent by default, so the gate guards nothing", attr)
				}
				if on[attr] {
					t.Errorf("%s is still written with %s set", attr, tc.name)
				}
			}
		})
	}
}

// TestSubmitBehaviorTouchesNothingElse is the other half: a gate must remove
// what it names and leave the rest of the ad alone. The attributes HTCondor
// KEPT are the ones at risk -- RemoteWallClockTime and the Cumulative*
// counters are read exactly like the counters that went away.
func TestSubmitBehaviorTouchesNothingElse(t *testing.T) {
	all := SubmitBehavior{
		OmitExitStatus:             true,
		OmitZeroedRunTimeCounters:  true,
		OmitLeaveJobInQueueDefault: true,
	}
	def := behaviorAd(t, SubmitBehavior{})
	on := behaviorAd(t, all)

	gated := map[string]bool{
		"exitstatus": true, "remoteusercpu": true, "remotesyscpu": true,
		"lastsuspensiontime": true, "exitbysignal": true, "leavejobinqueue": true,
	}
	for attr := range def {
		if !on[attr] && !gated[attr] {
			t.Errorf("%s went missing, and no behavior here says it should", attr)
		}
	}
	for attr := range on {
		if !def[attr] {
			t.Errorf("%s appeared, and these behaviors only remove attributes", attr)
		}
	}
	for _, kept := range []string{"remotewallclocktime", "cumulativeremoteusercpu", "cumulativeremotesyscpu"} {
		if !on[kept] {
			t.Errorf("%s is not one of the attributes HTCondor dropped and must stay", kept)
		}
	}
}
