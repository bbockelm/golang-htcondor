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
