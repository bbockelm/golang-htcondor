package main

import (
	"log"
	"os"
	"strconv"
	"syscall"
)

// Ending the session, as opposed to ending the helper.
//
// The helper is not the job. The launch script starts it with --daemonize,
// which setsids into its own session, and then execs JupyterLab -- so
// JupyterLab is the job's main process and the helper is a detached daemon
// beside it. Exiting therefore frees nothing: the tunnel goes, the slot
// stays, and JupyterLab keeps running with no way left to reach it.
//
// That is a gap in what is already documented: the idle timeout is described
// as ending the job, and it never did. Whatever decides a session is over --
// the idle timer, or a rejection that can never be retried past -- has to say
// so to the process that IS the job.
//
// It signals the process group the helper was started in, captured before
// the setsid and passed through jobPGIDEnv. That group is the job's, because
// stage 1 runs as a child of the launch script; the daemon is no longer in
// it, so this cannot kill the messenger.

// jobPGIDEnv carries the pre-setsid process group from stage 1 to stage 2.
const jobPGIDEnv = "HTCONDOR_JUPYTER_JOB_PGID"

// jobPGID reports the process group to signal, and whether one is known.
//
// Unknown is normal for a helper started by hand, and for one launched by a
// script older than this. It is not an error: the caller falls back to
// exiting, which is what it did before.
func jobPGID() (int, bool) {
	v := os.Getenv(jobPGIDEnv)
	if v == "" {
		return 0, false
	}
	pgid, err := strconv.Atoi(v)
	if err != nil || pgid <= 1 {
		// pgid 1 would be init, or a parsing accident. Refusing is the
		// only safe reading: signalling the wrong group is worse than
		// leaving one slot held.
		return 0, false
	}
	return pgid, true
}

// currentPGID is the group this process is in, so the caller can avoid
// signalling itself when the setsid did not happen.
func currentPGID() int {
	pgid, err := syscall.Getpgid(os.Getpid())
	if err != nil {
		return 0
	}
	return pgid
}

// endSession terminates the job the helper belongs to.
//
// SIGTERM, not SIGKILL: JupyterLab flushes and shuts its kernels down on
// term, and a notebook losing unsaved state because the tunnel could not
// reconnect would be a worse bug than the one this fixes. HTCondor escalates
// on its own if the job ignores it.
func endSession(reason string) {
	pgid, ok := jobPGID()
	if !ok {
		log.Printf("helper: %s; no job process group recorded, so only the helper exits and the slot stays held", reason)
		return
	}
	if pgid == currentPGID() {
		// Not daemonized -- signalling this group would kill the helper
		// mid-log and leave the reason unwritten.
		log.Printf("helper: %s; refusing to signal our own process group", reason)
		return
	}
	log.Printf("helper: %s; ending the session (SIGTERM to process group %d)", reason, pgid)
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
		log.Printf("helper: could not signal the job: %v", err)
	}
}
