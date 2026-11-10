package htcondor

import (
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// transformBodySeparator is what joins the lines of a transform body in the
// job ad: 0x1e, the record separator. A newline cannot be used, because the
// body lives in a ClassAd string in the job queue.
const transformBodySeparator = "\x1e"

// setOnEvictChecks stores the submit-side transforms a job carries for the
// schedd to apply when it is evicted, mirroring
// SubmitHash::SetOnEvictExpressions.
//
// `on_evict_checks` names TAGS, not expressions. Each tag's body is a submit
// transform written under `transform_body_<tag>`, usually as a multi-line
// block, and the pair reaches the job ad as TransformOnEvict (the list of
// tags that had a body) and TransformBody_<tag> (the body, its lines joined
// with 0x1e).
//
// A tag with no body is dropped from the list rather than carried: the
// schedd would have nothing to run for it. The list attribute is still
// written when every tag is dropped, as an empty string, because that is
// what condor_submit writes -- `on_evict_checks = nosuch` produces
// `TransformOnEvict = ""`.
//
// Comment and blank lines are dropped from the body, so a block can be
// written the way a configuration file is.
func (sf *SubmitFile) setOnEvictChecks(ad *classad.ClassAd) {
	tags, ok := sf.simpleKeywordParam("on_evict_checks", "TransformOnEvict")
	if !ok {
		return
	}

	var kept []string
	for _, tag := range splitSubmitListItems(tags) {
		body, ok := sf.submitCommandAlt("transform_body_"+tag, "TransformBody_"+tag)
		if !ok || body == "" {
			continue
		}
		var lines []string
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimRight(line, "\r")
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			lines = append(lines, line)
		}
		_ = ad.Set("TransformBody_"+tag, strings.Join(lines, transformBodySeparator))
		kept = append(kept, tag)
	}

	_ = ad.Set("TransformOnEvict", strings.Join(kept, " "))
}

// splitSubmitListItems cuts a submit-file list on HTCondor's separators --
// commas and whitespace -- and drops the empty pieces. canonicalizeSubmitList
// does the same split and rejoins with commas; this hands back the items.
func splitSubmitListItems(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', ' ', '\t', '\r', '\n':
			return true
		}
		return false
	})
}
