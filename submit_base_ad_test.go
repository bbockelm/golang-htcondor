package htcondor

import (
	"strings"
	"testing"
)

// TestSubmitTimeDefaults pins the bookkeeping condor_submit writes into every
// job ad, and the ClassAd TYPE of each one.
//
// The types are the point as much as the values. The CPU and wall-clock
// counters are reals, because that is what the shadow writes into them later
// and a consumer reading one with an integer lookup gets nothing from a real;
// the rest are integers. An absent attribute is worse than either: it reads
// as UNDEFINED, so `condor_q -constraint 'RemoteUserCpu > 60'` does not match
// a job that has used no CPU, and a policy expression doing arithmetic on one
// is neither true nor false.
func TestSubmitTimeDefaults(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/true\nqueue\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}

	for attr, want := range map[string]string{"MyType": "Job", "TargetType": "Machine"} {
		got, ok := ad.EvaluateAttrString(attr)
		if !ok || got != want {
			t.Errorf("%s = %q (found=%v), want %q", attr, got, ok, want)
		}
	}

	for _, attr := range []string{
		"RemoteWallClockTime", "RemoteUserCpu", "RemoteSysCpu",
		"CumulativeRemoteUserCpu", "CumulativeRemoteSysCpu",
	} {
		v := ad.EvaluateAttr(attr)
		if !v.IsReal() {
			t.Errorf("%s is %v, want the real 0.0 condor_submit writes", attr, v)
			continue
		}
		if r, _ := v.RealValue(); r != 0 {
			t.Errorf("%s = %v, want 0", attr, r)
		}
	}

	for _, attr := range []string{
		"ExitStatus", "NumCkpts", "NumJobStarts", "NumJobCompletions", "NumRestarts",
		"NumSystemHolds", "CommittedTime", "CommittedSlotTime", "CumulativeSlotTime",
		"TotalSuspensions", "LastSuspensionTime", "CumulativeSuspensionTime",
		"CommittedSuspensionTime", "CurrentHosts", "JobPrio",
	} {
		v := ad.EvaluateAttr(attr)
		if !v.IsInteger() {
			t.Errorf("%s is %v, want the integer 0", attr, v)
			continue
		}
		if n, _ := v.IntValue(); n != 0 {
			t.Errorf("%s = %v, want 0", attr, n)
		}
	}

	if v := ad.EvaluateAttr("ExitBySignal"); !v.IsBool() {
		t.Errorf("ExitBySignal is %v, want the boolean false", v)
	} else if b, _ := v.BoolValue(); b {
		t.Error("ExitBySignal = true, want false")
	}

	// JobRunCount is the schedd's, from the job's shadow exceptions.
	// condor_submit does not write it, and a 0 here claimed the job had run
	// no times when the attribute's absence is what says that.
	if _, ok := ad.Lookup("JobRunCount"); ok {
		t.Error("JobRunCount is in the ad; condor_submit does not write it")
	}
}

// TestSubmitTimeDefaultsYieldToTheSubmitFile makes sure the defaults are
// written BEFORE the submit file is read, so a keyword still wins.
func TestSubmitTimeDefaultsYieldToTheSubmitFile(t *testing.T) {
	ad := adFor(t, "executable = /bin/true\npriority = 5\n+ExitStatus = 7\nqueue\n")
	if got := ad["JobPrio"]; got != "5" {
		t.Errorf("JobPrio = %q, want 5 from the priority keyword", got)
	}
	if got := ad["ExitStatus"]; got != "7" {
		t.Errorf("ExitStatus = %q, want 7 from the +Attr pass", got)
	}
}

// TestJobNotification covers the keyword that decides when the schedd mails
// the submitter: the five words condor_submit accepts, the attribute's own
// name as the alternate spelling, the default when nothing is said, and the
// two ways it refuses a value.
func TestJobNotification(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want string
	}{
		{"executable = /bin/true\nqueue\n", "0"},
		{"executable = /bin/true\nnotification = never\nqueue\n", "0"},
		{"executable = /bin/true\nnotification = Always\nqueue\n", "1"},
		{"executable = /bin/true\nnotification = COMPLETE\nqueue\n", "2"},
		{"executable = /bin/true\nnotification = Error\nqueue\n", "3"},
		{"executable = /bin/true\nnotification = Start\nqueue\n", "4"},
		{"executable = /bin/true\nJobNotification = Start\nqueue\n", "4"},
	} {
		ad := adFor(t, tc.src)
		if got := ad["JobNotification"]; got != tc.want {
			t.Errorf("%q: JobNotification = %q, want %s", strings.TrimSpace(tc.src), got, tc.want)
		}
	}
	// condor_submit compares the WORDS and nothing else, so a number is not
	// a notification setting and an unknown word is not ignored.
	mustReject(t, "executable = /bin/true\nnotification = 2\nqueue\n")
	mustReject(t, "executable = /bin/true\nnotification = sometimes\nqueue\n")
}

// TestLeaveJobInQueueDefault covers the default condor_submit writes for a
// local submission, and that a submitter's own expression is left alone.
func TestLeaveJobInQueueDefault(t *testing.T) {
	ad := adFor(t, "executable = /bin/true\nqueue\n")
	if got := ad["LeaveJobInQueue"]; got != "false" {
		t.Errorf("LeaveJobInQueue = %q, want false", got)
	}
	ad = adFor(t, "executable = /bin/true\nleave_in_queue = JobStatus == 4\nqueue\n")
	if got := ad["LeaveJobInQueue"]; !strings.Contains(got, "JobStatus") {
		t.Errorf("LeaveJobInQueue = %q, want the submitter's expression", got)
	}
}

// TestDefaultJobLease covers JOB_DEFAULT_LEASE_DURATION: a job that can
// reconnect gets a lease it did not ask for, and one that cannot does not.
//
// The lease is what lets a job survive a disconnect, so a job ad with none
// turns a network blip into a lost execution.
func TestDefaultJobLease(t *testing.T) {
	ad := adFor(t, "executable = /bin/true\nqueue\n")
	if got := ad["JobLeaseDuration"]; got != "2400" {
		t.Errorf("JobLeaseDuration = %q, want 2400 from JOB_DEFAULT_LEASE_DURATION", got)
	}
	// scheduler universe cannot reconnect, so there is nothing to lease.
	ad = adFor(t, "universe = scheduler\nexecutable = /bin/true\nqueue\n")
	if got, ok := ad["JobLeaseDuration"]; ok {
		t.Errorf("JobLeaseDuration = %q on a scheduler-universe job, want it absent", got)
	}
	// An explicit lease is not overwritten by the default.
	ad = adFor(t, "executable = /bin/true\njob_lease_duration = 300\nqueue\n")
	if got := ad["JobLeaseDuration"]; got != "300" {
		t.Errorf("JobLeaseDuration = %q, want the submitted 300", got)
	}
}
