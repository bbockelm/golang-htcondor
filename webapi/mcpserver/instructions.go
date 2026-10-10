package mcpserver

import (
	"fmt"
	"strings"

	"github.com/bbockelm/golang-htcondor/webapi/condordocs"
)

// instructionsBudget caps the built-in instructions, the access point's
// name included. Clients do not always pass the whole initialize text to
// the model -- Claude Code keeps about the first 2 KB -- and the operator's
// notes and the site skills come after this text, so every byte here
// pushes them further toward the cut. Anything longer belongs in the
// agent guide (guide.go), which the instructions name topic by topic.
const instructionsBudget = 2000

// defaultInstructions builds generic HTCondor MCP instructions that are
// always included, regardless of per-deployment configuration. The
// scheddName (access point hostname) is inserted when available.
func defaultInstructions(scheddName string) string {
	return identityInstructions(scheddName) + genericInstructions(condordocs.IsEmbedded())
}

// identityInstructions names the access point.
func identityInstructions(scheddName string) string {
	if scheddName != "" {
		return fmt.Sprintf("This is the HTCondor access point %q. Jobs submitted here run on remote machines.\n\n", scheddName)
	}
	return "This is an HTCondor access point. Jobs submitted here run on remote machines.\n\n"
}

// genericInstructions is the guidance every deployment serves: the
// mistakes agents make most often when submitting and monitoring jobs, and
// where the rest lives. Mistakes submit_job already rejects or warns about
// in its response are left out; this text is for the ones nothing catches.
//
// docsEmbedded says whether the HTCondor manual lookups are offered, so
// the text never names a tool this build does not have.
func genericInstructions(docsEmbedded bool) string {
	var b strings.Builder
	b.WriteString("## Submitting\n")
	b.WriteString("- submit_job takes a submit file. Files on your machine are not on the access point: " +
		"upload the executable and small inputs (<100 KB) with upload_job_input, and until you do " +
		"the job stays held. Larger inputs: create_input_upload_url, or URLs in transfer_input_files.\n")
	b.WriteString("- $(...) is HTCondor macro expansion, not shell: $(hostname) becomes empty. " +
		"Put shell logic in a script.\n")
	b.WriteString("- Steps that depend on each other are a DAG: use submit_dag rather than sequencing jobs yourself.\n\n")

	b.WriteString("## Monitoring\n")
	b.WriteString("- JobStatus: 1 Idle, 2 Running, 3 Removed, 4 Completed, 5 Held, 6 Transferring Output, 7 Suspended.\n")
	b.WriteString("- To wait, call watch_jobs once, then check_watches (it can block). Never poll query_jobs in a loop.\n")
	b.WriteString("- While a job runs: tail_job_output for stdout/stderr, exec_in_job for a command. " +
		"After it finishes: get_job_stdout, get_job_stderr, get_job_output. Each pair is wrong at the other time.\n")
	b.WriteString("- Held: read HoldReason, fix the cause, then release_job or resubmit. " +
		"Idle too long: analyze_job_match. Many failures at once: analyze_issues.\n\n")

	b.WriteString("## More\n")
	fmt.Fprintf(&b, "doc_guide(topic) has the details and every tool: %s.", strings.Join(guideTopicNames(), ", "))
	if docsEmbedded {
		b.WriteString(" doc_search and doc_submit_syntax look up the HTCondor manual.")
	}
	b.WriteString("\n")
	return b.String()
}

// buildInstructions assembles the initialize text: which access point this
// is, then what is specific to this site (the operator's MCP_INSTRUCTIONS and
// the site skills catalogue), then the generic HTCondor guidance.
//
// The site-specific parts go first because clients do not always pass the
// whole text to the model (see instructionsBudget). When this text was 13 KB
// and they came last, an agent on an access point that holds jobs without a
// credential never saw the note telling it to store one. Of the three, the
// generic guidance is the part an agent can best do without: doc_guide and
// the tool descriptions carry it too.
func buildInstructions(scheddName, customInstructions, skillsSection string) string {
	var b strings.Builder
	b.WriteString(identityInstructions(scheddName))
	if custom := strings.TrimSpace(customInstructions); custom != "" {
		b.WriteString("## Deployment-specific notes\n\n")
		b.WriteString(custom)
		b.WriteString("\n\n")
	}
	if skillsSection != "" {
		b.WriteString(skillsSection)
		b.WriteString("\n")
	}
	b.WriteString(genericInstructions(condordocs.IsEmbedded()))
	return b.String()
}

// buildMultiAPInstructions is buildInstructions for multi-AP mode: the AP
// set instead of one access point, and no generic submitting guidance --
// none of those tools is offered.
func buildMultiAPInstructions(constraint, customInstructions, skillsSection string) string {
	var b strings.Builder
	b.WriteString(multiAPInstructions(constraint))
	if custom := strings.TrimSpace(customInstructions); custom != "" {
		b.WriteString("## Deployment-specific notes\n\n")
		b.WriteString(custom)
		b.WriteString("\n\n")
	}
	if skillsSection != "" {
		b.WriteString(skillsSection)
		b.WriteString("\n")
	}
	b.WriteString("JobStatus: 1 Idle, 2 Running, 3 Removed, 4 Completed, 5 Held, 6 Transferring Output, 7 Suspended.\n")
	return b.String()
}

// SetInstructions installs the deployment-specific instructions, combining them
// with the generic HTCondor guidance the same way construction does. It is the
// dynamic half of MCP_INSTRUCTIONS: a reconfigure calls this so an operator can
// correct the guidance agents receive without restarting the daemon and
// dropping every live session.
//
// Only sessions that initialize after this call see the new text. MCP delivers
// instructions once, in the initialize response, so an agent already connected
// keeps the text it was given -- there is no way to push a revision to it.
func (s *Server) SetInstructions(custom string) {
	s.customInstructions.Store(&custom)
	s.rebuildInstructions()
}

// rebuildInstructions regenerates the initialize text from the operator's
// instructions and the skills currently loaded.
//
// Both inputs can change independently at runtime -- MCP_INSTRUCTIONS on a
// reconfigure, the library when a checkout is reloaded -- and the text has
// to reflect whichever changed without discarding the other.
func (s *Server) rebuildInstructions() {
	custom := ""
	if p := s.customInstructions.Load(); p != nil {
		custom = *p
	}
	var built string
	if s.multi != nil {
		built = buildMultiAPInstructions(s.multiConstraint, custom, skillsInstructions(s.skillsLibrary()))
	} else {
		name := ""
		if sc := s.getSchedd(); sc != nil {
			name = sc.Name()
		}
		built = buildInstructions(name, custom, skillsInstructions(s.skillsLibrary()))
	}
	s.instructions.Store(&built)
	// The SDK transport bakes this text, and the catalogue it is built
	// from, into servers it caches per scope set. Bumping the generation
	// is what makes those caches notice; without it a reconfigure would
	// change the text every other surface serves and not this one.
	s.catalogGen.Add(1)
}

// InvalidateCatalog tells the cached per-scope SDK servers that what a
// caller would be served has changed.
//
// The tool catalogue is built per call but cached per scope set, keyed on
// this generation, so a change that adds or removes tools is invisible
// until the generation moves. Credd discovery is exactly that change:
// the credential tools are offered only when a credd is present, so an
// access point that finds its credd after startup would otherwise keep
// serving the catalogue it built without one.
func (s *Server) InvalidateCatalog() {
	s.catalogGen.Add(1)
}
