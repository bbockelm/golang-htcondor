package mcpserver

import (
	"fmt"
	"strings"
)

// formatSubmitWarnings renders the non-fatal diagnostics for the
// submit_job response. It leads the response text rather than trailing
// it: the job is already submitted by the time these are known, so the
// caller has to decide whether to remove and resubmit it.
func formatSubmitWarnings(warnings []string) string {
	if len(warnings) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("WARNINGS about this submit file:\n")
	for _, w := range warnings {
		fmt.Fprintf(&b, "- %s\n", w)
	}
	b.WriteString("The job was submitted anyway; remove it with remove_job and resubmit if a warning " +
		"describes a mistake.\n\n")
	return b.String()
}
