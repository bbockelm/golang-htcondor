package htcondor

import (
	"strings"
	"testing"
)

// TestOnEvictChecks covers the submit-side transforms a job carries for the
// schedd to run when it is evicted.
//
// `on_evict_checks` names TAGS, not expressions: each tag's body is written
// under `transform_body_<tag>`, and the pair reaches the ad as
// TransformOnEvict (the tags that had a body) and TransformBody_<tag> (the
// body, lines joined with 0x1e, because a newline cannot live in a ClassAd
// string in the job queue).
//
// Go wrote none of it, so a job asking to be transformed on eviction was
// submitted without the transform and the schedd had nothing to run.
func TestOnEvictChecks(t *testing.T) {
	t.Run("a tag and its body", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\non_evict_checks = memck\ntransform_body_memck = SET RequestMemory 2048\nqueue\n")
		if got := ad["TransformOnEvict"]; got != `"memck"` {
			t.Errorf("TransformOnEvict = %s, want \"memck\"", got)
		}
		if got := ad["TransformBody_memck"]; got != `"SET RequestMemory 2048"` {
			t.Errorf("TransformBody_memck = %s", got)
		}
	})

	t.Run("a tag with no body is dropped", func(t *testing.T) {
		// The list attribute is still written, empty: that is what
		// condor_submit does, and a body nothing names is never run.
		ad := adFor(t, "executable = /bin/true\non_evict_checks = nosuch\nqueue\n")
		if got := ad["TransformOnEvict"]; got != `""` {
			t.Errorf("TransformOnEvict = %s, want the empty string", got)
		}
	})

	t.Run("several tags", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\non_evict_checks = a, b\ntransform_body_a = SET X 1\ntransform_body_b = SET Y 2\nqueue\n")
		if got := ad["TransformOnEvict"]; got != `"a b"` {
			t.Errorf("TransformOnEvict = %s, want \"a b\"", got)
		}
	})

	t.Run("a multi-line body", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\non_evict_checks = memck\ntransform_body_memck @=end\nSET A 1\n# a comment\n\nSET B 2\n@end\nqueue\n")
		// The ad renders the separator in octal, as ClassAd string escapes do.
		if got := ad["TransformBody_memck"]; got != `"SET A 1\036SET B 2"` {
			t.Errorf("TransformBody_memck = %s, want the two lines joined with 0x1e and the comment dropped", got)
		}
	})

	t.Run("the body is macro-expanded", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nMY = 7\non_evict_checks = memck\ntransform_body_memck = SET A $(MY)\nqueue\n")
		if got := ad["TransformBody_memck"]; got != `"SET A 7"` {
			t.Errorf("TransformBody_memck = %s, want the macro expanded", got)
		}
	})

	t.Run("under the attribute names", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nTransformOnEvict = memck\nTransformBody_memck = SET A 1\nqueue\n")
		if got := ad["TransformOnEvict"]; got != `"memck"` {
			t.Errorf("TransformOnEvict = %s", got)
		}
	})

	// The built-in memory transform appends ITS tag to the same list, so
	// the two have to be written in the right order: the explicit tags
	// first, the built-in one after. The other way round the built-in
	// tag is written and then thrown away, leaving a
	// TransformBody_RequestMemory that nothing names.
	t.Run("alongside the built-in memory transform", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nretry_request_memory = 2048\nmax_retries = 2\n"+
			"on_evict_checks = memck\ntransform_body_memck = SET A 1\nqueue\n")
		if got := ad["TransformOnEvict"]; got != `"memck RequestMemory"` {
			t.Errorf("TransformOnEvict = %s, want \"memck RequestMemory\"", got)
		}
		if got, ok := ad["TransformBody_RequestMemory"]; !ok || !strings.Contains(got, "SET RequestMemory 2048") {
			t.Errorf("TransformBody_RequestMemory = %s", got)
		}
	})
}

// TestRetryRequestMemoryIsReadOncePerCluster pins where the
// retry_request_memory family is read when the submit file names no
// request_memory of its own.
//
// condor_submit chains every proc ad after the first to proc 0's, so
// SetRequestMem finds RequestMemory already there and takes the branch
// that reads neither JOB_DEFAULT_REQUESTMEMORY nor the retry commands.
// The built-in transform therefore names itself in TransformOnEvict on
// proc 0 only -- which is visible because on_evict_checks overwrites that
// attribute outright on every proc, just before the resource requests are
// set, so a later proc is left with whatever on_evict_checks wrote.
//
// Building every proc ad from scratch instead put RequestMemory in
// TransformOnEvict on all of them, and the schedd would have run the
// grow-the-request transform for procs condor_submit does not.
func TestRetryRequestMemoryIsReadOncePerCluster(t *testing.T) {
	const src = "executable = /bin/true\n" +
		"on_evict_checks = nosuch\n" +
		"retry_request_memory_max = 2048\n" +
		"queue 3\n"

	sf, err := ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sub, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if len(sub.ProcAds) != 3 {
		t.Fatalf("got %d proc ads, want 3", len(sub.ProcAds))
	}

	// Without on_evict_checks every proc would read "RequestMemory"
	// through the chain, so this file names a tag with no body: that
	// assigns the attribute on every proc, and a later proc keeps the
	// empty string it wrote.
	want := []string{"RequestMemory", "", ""}
	for proc, w := range want {
		got, _ := sub.ProcAds[proc].EvaluateAttrString("TransformOnEvict")
		if got != w {
			t.Errorf("proc %d: TransformOnEvict = %q, want %q", proc, got, w)
		}
		// A later proc reads the body through the chain in
		// condor_submit, so Go writes it on every proc. Only the
		// append to TransformOnEvict is held back.
		if _, ok := sub.ProcAds[proc].Lookup("TransformBody_RequestMemory"); !ok {
			t.Errorf("proc %d: TransformBody_RequestMemory is missing", proc)
		}
	}

	// With no on_evict_checks nothing assigns the attribute on a later
	// proc, so every proc reads the name the cluster pass appended.
	sfPlain, err := ParseSubmitFile(strings.NewReader(
		"executable = /bin/true\nretry_request_memory_max = 2048\nqueue 3\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	subPlain, err := sfPlain.Submit(1)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	for proc := range subPlain.ProcAds {
		got, _ := subPlain.ProcAds[proc].EvaluateAttrString("TransformOnEvict")
		if got != "RequestMemory" {
			t.Errorf("proc %d with no on_evict_checks: TransformOnEvict = %q, want RequestMemory", proc, got)
		}
	}

	// With request_memory in the file, submit_param answers on every
	// proc, so the family is read on every proc.
	sf2, err := ParseSubmitFile(strings.NewReader("executable = /bin/true\nrequest_memory = 128\n" +
		"on_evict_checks = nosuch\nretry_request_memory_max = 2048\nqueue 3\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sub2, err := sf2.Submit(1)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	for proc := range sub2.ProcAds {
		got, _ := sub2.ProcAds[proc].EvaluateAttrString("TransformOnEvict")
		if got != "RequestMemory" {
			t.Errorf("proc %d with request_memory: TransformOnEvict = %q, want RequestMemory", proc, got)
		}
	}
}

// TestRetryRequestDisk covers the disk half of the built-in on-evict
// transforms. Disk has one retry command rather than three -- there is no
// retry_request_disk_max or _increase -- and its transform is limited to
// the vacate sub-code that means the job went over its DISK request, 104,
// where memory's is 102.
//
// None of it was implemented, so a job asking to be retried with more disk
// was submitted with no transform at all.
func TestRetryRequestDisk(t *testing.T) {
	t.Run("a single retry value", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nrequest_disk = 512\nretry_request_disk = 1024\nqueue\n")
		if got := ad["TransformOnEvict"]; got != `"RequestDisk"` {
			t.Errorf("TransformOnEvict = %s, want \"RequestDisk\"", got)
		}
		want := `"REQUIREMENTS (VacateReasonCode==21 || VacateReasonCode == 34) && VacateReasonSubCode == 104\036SET RequestDisk 1024"`
		if got := ad["TransformBody_RequestDisk"]; got != want {
			t.Errorf("TransformBody_RequestDisk = %s,\nwant %s", got, want)
		}
	})

	t.Run("a sequence", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nrequest_disk = 512\nretry_request_disk = 1024, 2048\nqueue\n")
		// adFor renders with String, which spaces a list differently
		// from the sink form the ad is stored and compared in.
		if got := ad["RetryRequestDisk"]; got != "{1024, 2048}" {
			t.Errorf("RetryRequestDisk = %s, want the two sizes as a list", got)
		}
		if !strings.Contains(ad["TransformBody_RequestDisk"], "RetryRequestDiskIndex") {
			t.Errorf("TransformBody_RequestDisk = %s, want it to walk the sequence", ad["TransformBody_RequestDisk"])
		}
	})

	t.Run("the short spelling supersedes it", func(t *testing.T) {
		// `request_disk = a, b` is read instead of retry_request_disk,
		// which condor_submit never looks at in that case.
		ad := adFor(t, "executable = /bin/true\nrequest_disk = 512, 4096\nretry_request_disk = 1024\nqueue\n")
		if got := ad["RequestDisk"]; got != "512" {
			t.Errorf("RequestDisk = %s, want 512", got)
		}
		if !strings.Contains(ad["TransformBody_RequestDisk"], "SET RequestDisk 4096") {
			t.Errorf("TransformBody_RequestDisk = %s, want the second value of request_disk", ad["TransformBody_RequestDisk"])
		}
	})

	t.Run("an expression request takes it out of play", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nrequest_disk = MY.Foo\nretry_request_disk = 1024\nqueue\n")
		if _, ok := ad["TransformBody_RequestDisk"]; ok {
			t.Errorf("TransformBody_RequestDisk = %s, want it absent", ad["TransformBody_RequestDisk"])
		}
	})

	t.Run("disk is named before memory", func(t *testing.T) {
		// SetRequestResources walks the submit macro set, which is kept
		// sorted, so request_disk is reached before request_memory
		// whatever order the file writes them in.
		ad := adFor(t, "executable = /bin/true\nrequest_memory = 100\nretry_request_memory = 2048\n"+
			"request_disk = 512\nretry_request_disk = 1024\nqueue\n")
		if got := ad["TransformOnEvict"]; got != `"RequestDisk RequestMemory"` {
			t.Errorf("TransformOnEvict = %s, want \"RequestDisk RequestMemory\"", got)
		}
	})
}
