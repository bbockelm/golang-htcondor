package mcpserver

import "fmt"

// maxToolResults is the most rows any listing tool hands back in one
// call, regardless of what the caller asked for.
//
// These tools answer into a model's context window, which is the real
// budget — not the schedd's willingness to send. A thousand job ads is
// a useless answer twice over: it crowds out the reasoning the caller
// was going to do with it, and the model cannot read a thousand rows
// any more usefully than it can read fifty. Past a few hundred, the
// honest response is a smaller question, not a bigger answer.
//
// So "raise the limit" is advice with a ceiling, and past that ceiling
// the guidance has to change to narrowing the query or asking for a
// count instead. 500 is comfortably above any listing a person reads
// and well below what hurts.
const maxToolResults = 500

// MaxToolResults is maxToolResults, exported so tests and callers in
// other packages can name the ceiling rather than duplicating it.
const MaxToolResults = maxToolResults

// clampToolLimit bounds a caller-requested limit. capped reports that
// the ceiling, not the caller, decided the size — which changes what
// the caller should be told to do about a truncated answer.
//
// A non-positive request means "no limit" to the query layer. There is
// no such thing here: unlimited is exactly the answer that does not
// fit, so it becomes the ceiling.
func clampToolLimit(requested int) (effective int, capped bool) {
	if requested <= 0 || requested > maxToolResults {
		return maxToolResults, true
	}
	return requested, false
}

// truncationNote explains an answer that stopped short, and what to do
// about it. The two cases need different advice: a caller who set a
// small limit can raise it, and a caller who hit the ceiling cannot.
func truncationNote(returned, effective int, capped bool) string {
	if capped {
		return fmt.Sprintf("\n\nStopped at %d results, the most this tool returns in one call — more match. "+
			"Raising the limit will not return more. Narrow the query instead (Owner, JobStatus, a ClusterId "+
			"range, a time bound), or use aggregate_jobs to count or summarize without listing every row.",
			effective)
	}
	return fmt.Sprintf("\n\nStopped at the requested limit of %d; more match. Raise limit (up to %d), "+
		"narrow the query, or use aggregate_jobs to count without listing every row.",
		effective, maxToolResults)
}
