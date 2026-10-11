package mcpserver

import (
	"fmt"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// runtimeEstimateSchema is the runtime_estimate get_job files when the
// server runs the estimator: a runtimeest.Result. Only available is
// required -- an unavailable estimate is just a reason.
var runtimeEstimateSchema = obj(map[string]interface{}{
	"available":        boolSchema,
	"reason":           strSchema,
	"estimate_seconds": numberSchema,
	"p10_seconds":      numberSchema,
	"p90_seconds":      numberSchema,
	"basis": obj(map[string]interface{}{
		"level":        strSchema,
		"sample_count": intSchema,
	}, "level", "sample_count"),
	"elapsed_seconds":   numberSchema,
	"remaining_seconds": numberSchema,
	"exceeded_history":  boolSchema,
	"model": obj(map[string]interface{}{
		"trained_through": strSchema,
		"jobs_ingested":   intSchema,
	}),
}, "available")

// runtimeLevelText says what each level compared the job with, in the
// words an agent can repeat to the person it is helping.
var runtimeLevelText = map[string]string{
	"cluster":  "finished jobs in the same cluster",
	"exact":    "of your finished jobs with the same command and arguments",
	"template": "of your finished jobs with the same command and argument pattern",
	"batch":    "of your finished jobs in the same batch",
	"iwd":      "of your finished jobs from the same submit directory",
	"cmd":      "of your finished jobs running the same program",
	"owner":    "of your recently finished jobs",
	"global":   "recently finished jobs on this access point",
}

// renderRuntimeEstimate is the text form of get_job's runtime_estimate.
func renderRuntimeEstimate(r runtimeest.Result) string {
	if !r.Available {
		switch r.Reason {
		case runtimeest.ReasonWarmingUp:
			return "\n\nRuntime estimate: not available yet (the job history is still being read)."
		case runtimeest.ReasonInsufficientHistory:
			return "\n\nRuntime estimate: not available (too few comparable finished jobs)."
		}
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\nRuntime estimate: about %s (likely between %s and %s)",
		secondsText(r.EstimateSeconds), secondsText(r.P10Seconds), secondsText(r.P90Seconds))
	if r.Basis != nil {
		what := runtimeLevelText[r.Basis.Level]
		if what == "" {
			what = r.Basis.Level
		}
		fmt.Fprintf(&b, ", based on %d %s", r.Basis.SampleCount, what)
	}
	b.WriteString(".")
	switch {
	case r.ExceededHistory && r.ElapsedSeconds != nil:
		fmt.Fprintf(&b, " It has been running %s, longer than nearly every comparable job, so there is no estimate of the time remaining.",
			secondsText(*r.ElapsedSeconds))
	case r.RemainingSeconds != nil && r.ElapsedSeconds != nil:
		fmt.Fprintf(&b, " Running %s so far; about %s remaining.",
			secondsText(*r.ElapsedSeconds), secondsText(*r.RemainingSeconds))
	}
	return b.String()
}

func secondsText(s float64) string {
	return shortDuration(time.Duration(s) * time.Second)
}
