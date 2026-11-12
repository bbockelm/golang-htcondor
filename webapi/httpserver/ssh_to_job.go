package httpserver

import "net/http"

// Turning off everything built on condor_ssh_to_job.
//
// A site can forbid condor_ssh_to_job outright -- CHTC does -- and at
// such a site every feature here that reaches into a running job is
// dead on arrival: it submits the job, waits for it, and fails at the
// connect with a permission error that reads like a bug in this server
// rather than like a decision somebody made. There were knobs for the
// pieces (HTTP_API_INTERACTIVE_TERMINAL, HTTP_API_SSH_GATEWAY_ADDRESS,
// HTTP_API_MCP_DISABLED_TOOLS), so saying it took four settings that
// have to be kept in step, and the list grew whenever a feature was
// added.
//
// HTTP_API_SSH_TO_JOB = false says it once. It withdraws:
//
//   - the SSH gateway: no listener, and no session for a caller who
//     reaches one another way;
//   - /api/v1/jobs/{id}/ssh, the console's terminal on a running job,
//     and the consent flow and certificate endpoints that serve it;
//   - /api/v1/jobs/{id}/proxy/..., which rides the same transport --
//     and with it the VS Code app, which is reached through it;
//   - the Terminal interactive application;
//   - exec_in_job and the interactive-session tools over MCP.
//
// JupyterLab is deliberately NOT withdrawn. Its traffic goes through a
// tunnel the job dials back to this server, which is a connection out
// of the sandbox rather than into it, so it works at a site that
// forbids ssh-to-job entirely.
//
// Everything that only READS a finished or running job is untouched:
// the queue, the history, output files, tail. Those go through the
// schedd and the spool, not into the sandbox.

// requireSSHToJob refuses a request that would reach into a running job
// where the site does not allow it, and reports whether the caller may
// continue.
//
// 503 with the parameter named, as requireInteractiveApp and
// requireReservations do: a statement about the installation rather
// than about the caller.
func (h *Handler) requireSSHToJob(w http.ResponseWriter) bool {
	if h.sshToJobEnabled() {
		return true
	}
	h.writeError(w, http.StatusServiceUnavailable,
		"This access point does not allow connecting into a running job (HTTP_API_SSH_TO_JOB). "+
			"Job output and files are still available.")
	return false
}

// sshToJobEnabled reports whether anything may reach into a running
// job.
//
// Stored negatively, so the zero value of a Handler -- which is how
// most of this package's tests build one, and what every installation
// had before the setting existed -- allows it.
func (h *Handler) sshToJobEnabled() bool { return !h.sshToJobOff.Load() }
