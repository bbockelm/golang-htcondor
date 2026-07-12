// Package userlog implements a byte-compatible writer for the classic (non
// XML/JSON) HTCondor user-log format -- the file a submit description
// points at with `log = ...`.
//
// The format is defined only by the C++ source; this writer mirrors
// src/condor_utils/condor_event.cpp (the per-event formatBody methods
// and ULogEvent::formatHeader) and src/condor_utils/write_user_log.cpp
// (the doWriteEvent framing). In particular:
//
//   - Every event is framed as:
//
//     NNN (cluster.proc.subproc) <date> <time> <first-body-line>\n
//     <more body lines...>\n
//     ...\n
//
//     where the "...\n" line (SynchDelimiter) terminates the event.
//
//   - The header carries the 3-digit ULogEventNumber and a zero-padded
//     job id, then a timestamp. Stock HTCondor's default format
//     (USERLOG_FORMAT_DEFAULT == formatOpt::ISO_DATE, and
//     ENABLE_USERLOG_LOCKING defaulting off) is local-time ISO date
//     "YYYY-MM-DD HH:MM:SS" with no sub-second field and no UTC 'Z'. We
//     target exactly that so stock condor_wait / condor_userlog in this
//     build accept the file, and so the sibling Parse() round-trips it.
//
//   - The first line of the body is appended directly after the header's
//     trailing space (the C++ formatHeader ends with a space, then
//     formatBody prints "Job submitted from host: ...\n"). So the header
//     "description" the parser sees is really the first body line.
//
// Files are opened O_APPEND and each event is written with a single
// write() call under an advisory flock, matching the C++ writer's
// reopen-append-per-event behavior and remaining safe for concurrent
// writers (the schedd core and the queue-action path) as well as
// concurrent C++ readers (read_user_log does not lock by default).
package userlog

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ULogEventNumber values this writer emits. Mirrors the enum in
// src/condor_utils/condor_event.h. Only the numbers the pure-Go SchedD
// needs are given names here; the parser (eventKinds) knows the rest.
const (
	NumSubmit             = 0
	NumExecute            = 1
	NumJobEvicted         = 4
	NumJobTerminated      = 5
	NumJobAborted         = 9
	NumJobHeld            = 12
	NumJobReleased        = 13
	NumJobDisconnected    = 22
	NumJobReconnected     = 23
	NumJobReconnectFailed = 24
)

// SynchDelimiter terminates every classic-format event. Matches the C++
// const in read_user_log.cpp: "...\n".
const synchDelimiter = "...\n"

// EventRecord is one user-log event to be written. Callers build the
// concrete event via the constructor helpers (SubmitEvent, ExecuteEvent,
// ...) rather than populating this by hand; the helpers set Number and
// the body-formatting closure.
type EventRecord struct {
	// Number is the ULogEventNumber (see the Num* constants).
	Number int

	// When is the event timestamp. Zero means time.Now() at write.
	When time.Time

	// body returns the event body -- the text the C++ formatBody method
	// would emit, starting with the "description" line (which lands on the
	// header line) and ending with a trailing newline. It must NOT include
	// the "...\n" terminator.
	body string
}

// Writer appends events for a single job proc to its user-log file. It
// is safe for concurrent use; each WriteEvent opens, appends under an
// advisory lock, and closes, so multiple Writers (or processes) sharing
// a path interleave cleanly.
type Writer struct {
	path                   string
	cluster, proc, subproc int

	mu sync.Mutex
}

// NewWriter returns a Writer that appends events for job
// cluster.proc.subproc to the file at path. The file is created on the
// first WriteEvent if it does not exist. path must already be absolute
// (the caller resolves UserLog against Iwd).
func NewWriter(path string, cluster, proc, subproc int) *Writer {
	return &Writer{path: path, cluster: cluster, proc: proc, subproc: subproc}
}

// Path returns the log file path the Writer appends to.
func (w *Writer) Path() string { return w.path }

// WriteEvent renders rec into the classic format and appends it to the
// log file atomically (single write() under an advisory exclusive lock).
func (w *Writer) WriteEvent(rec EventRecord) error {
	when := rec.When
	if when.IsZero() {
		when = time.Now()
	}
	out := w.formatHeader(rec.Number, when) + rec.body + synchDelimiter

	w.mu.Lock()
	defer w.mu.Unlock()

	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664) //nolint:gosec // matches C++ WriteUserLog default mode 0664; the user job log is meant to be readable
	if err != nil {
		return fmt.Errorf("userlog: open %s: %w", w.path, err)
	}
	defer func() { _ = f.Close() }()

	// Advisory exclusive lock around the append. O_APPEND already makes a
	// single write() atomic on local filesystems; the lock additionally
	// serializes against any other flock-aware writer. Best-effort: if the
	// platform/filesystem refuses the lock we still append (matching the C++
	// default of ENABLE_USERLOG_LOCKING=false).
	unlock := lockFile(f)
	defer unlock()

	if _, err := f.WriteString(out); err != nil {
		return fmt.Errorf("userlog: append %s: %w", w.path, err)
	}
	return nil
}

// formatHeader renders "NNN (ccc.ppp.sss) YYYY-MM-DD HH:MM:SS " -- the
// C++ formatHeader output for the default (ISO_DATE, local-time) format,
// including the single trailing space the first body line is appended
// after.
func (w *Writer) formatHeader(number int, when time.Time) string {
	return fmt.Sprintf("%03d (%03d.%03d.%03d) %s ",
		number, w.cluster, w.proc, w.subproc,
		when.Format("2006-01-02 15:04:05"))
}

// --- event body builders ----------------------------------------------------
//
// Each returns an EventRecord with the body a C++ formatBody method would
// emit. Bodies for the "usage" events (Terminated, Evicted) zero-fill the
// rusage / byte fields the pure-Go SchedD does not track, exactly as the
// C++ shadow does when those values are unknown.

// zeroRusageLine is the formatRusage output for an all-zero rusage:
// "\tUsr 0 00:00:00, Sys 0 00:00:00". The caller appends the "  -  ...
// Usage\n" suffix.
const zeroRusageLine = "\tUsr 0 00:00:00, Sys 0 00:00:00"

// SubmitEvent (000) records a job entering the queue. submitHost is the
// schedd's sinful string (C++ sets it to daemonCore->privateNetworkIpAddr).
func SubmitEvent(when time.Time, submitHost string) EventRecord {
	return EventRecord{
		Number: NumSubmit,
		When:   when,
		body:   fmt.Sprintf("Job submitted from host: %s\n", submitHost),
	}
}

// ExecuteEvent (001) records a job beginning execution. executeHost is the
// remote startd's address/name. slotName, when non-empty, adds the
// "\tSlotName: ..." line the C++ ExecuteEvent emits.
func ExecuteEvent(when time.Time, executeHost, slotName string) EventRecord {
	var b strings.Builder
	fmt.Fprintf(&b, "Job executing on host: %s\n", executeHost)
	if slotName != "" {
		fmt.Fprintf(&b, "\tSlotName: %s\n", slotName)
	}
	return EventRecord{Number: NumExecute, When: when, body: b.String()}
}

// TerminatedEvent (005) records a job's completion. On a normal exit pass
// bySignal=false and code=exit status; on a signal exit pass bySignal=true
// and code=signal number. Usage and byte counters are zero-filled.
func TerminatedEvent(when time.Time, bySignal bool, code int) EventRecord {
	var b strings.Builder
	b.WriteString("Job terminated.\n")
	if !bySignal {
		fmt.Fprintf(&b, "\t(1) Normal termination (return value %d)\n\t", code)
	} else {
		fmt.Fprintf(&b, "\t(0) Abnormal termination (signal %d)\n", code)
		b.WriteString("\t(0) No core file\n\t")
	}
	b.WriteString(zeroRusageLine + "  -  Run Remote Usage\n\t")
	b.WriteString(zeroRusageLine + "  -  Run Local Usage\n\t")
	b.WriteString(zeroRusageLine + "  -  Total Remote Usage\n\t")
	b.WriteString(zeroRusageLine + "  -  Total Local Usage\n")
	b.WriteString("\t0  -  Run Bytes Sent By Job\n")
	b.WriteString("\t0  -  Run Bytes Received By Job\n")
	b.WriteString("\t0  -  Total Bytes Sent By Job\n")
	b.WriteString("\t0  -  Total Bytes Received By Job\n")
	return EventRecord{Number: NumJobTerminated, When: when, body: b.String()}
}

// EvictedEvent (004) records a job being evicted and requeued (starter
// death, lease loss, panic requeue). Mirrors the C++ shadow's
// logRequeueEvent: terminate_and_requeued with a Reason line. reason may be
// empty.
func EvictedEvent(when time.Time, reason string) EventRecord {
	var b strings.Builder
	b.WriteString("Job was evicted.\n\t")
	b.WriteString("(0) Job terminated and was requeued\n\t")
	b.WriteString(zeroRusageLine + "  -  Run Remote Usage\n\t")
	b.WriteString(zeroRusageLine + "  -  Run Local Usage\n")
	b.WriteString("\t0  -  Run Bytes Sent By Job\n")
	b.WriteString("\t0  -  Run Bytes Received By Job\n")
	// terminate_and_requeued with no known exit status: C++ writes the
	// normal-termination line with the recorded return value; we do not
	// track it here, so emit an abnormal (signal 0) line -- valid and
	// parseable, marking the run as not-normally-terminated.
	b.WriteString("\t(0) Abnormal termination (signal 0)\n")
	b.WriteString("\t(0) No core file\n")
	if reason != "" {
		fmt.Fprintf(&b, "\t%s\n", reason)
	}
	return EventRecord{Number: NumJobEvicted, When: when, body: b.String()}
}

// AbortedEvent (009) records a job removed from the queue (condor_rm).
// reason may be empty.
func AbortedEvent(when time.Time, reason string) EventRecord {
	var b strings.Builder
	b.WriteString("Job was aborted.\n")
	if reason != "" {
		fmt.Fprintf(&b, "\t%s\n", reason)
	}
	return EventRecord{Number: NumJobAborted, When: when, body: b.String()}
}

// HeldEvent (012) records a job being held. reason is free text; code and
// subcode are the HoldReasonCode / HoldReasonSubCode.
func HeldEvent(when time.Time, reason string, code, subcode int) EventRecord {
	var b strings.Builder
	b.WriteString("Job was held.\n")
	if reason != "" {
		fmt.Fprintf(&b, "\t%s\n", reason)
	} else {
		b.WriteString("\tReason unspecified\n")
	}
	fmt.Fprintf(&b, "\tCode %d Subcode %d\n", code, subcode)
	return EventRecord{Number: NumJobHeld, When: when, body: b.String()}
}

// ReleasedEvent (013) records a held job being released. reason may be
// empty.
func ReleasedEvent(when time.Time, reason string) EventRecord {
	var b strings.Builder
	b.WriteString("Job was released.\n")
	if reason != "" {
		fmt.Fprintf(&b, "\t%s\n", reason)
	}
	return EventRecord{Number: NumJobReleased, When: when, body: b.String()}
}

// DisconnectedEvent (022) records the shadow losing its connection to the
// starter and beginning a reconnect attempt. All three fields are required
// by the C++ formatBody (it refuses to write with any empty).
func DisconnectedEvent(when time.Time, reason, startdName, startdAddr string) EventRecord {
	var b strings.Builder
	b.WriteString("Job disconnected, attempting to reconnect\n")
	fmt.Fprintf(&b, "    %s\n", reason)
	fmt.Fprintf(&b, "    Trying to reconnect to %s %s\n", startdName, startdAddr)
	return EventRecord{Number: NumJobDisconnected, When: when, body: b.String()}
}

// ReconnectedEvent (023) records a successful reconnect to a running job.
func ReconnectedEvent(when time.Time, startdName, startdAddr, starterAddr string) EventRecord {
	var b strings.Builder
	fmt.Fprintf(&b, "Job reconnected to %s\n", startdName)
	fmt.Fprintf(&b, "    startd address: %s\n", startdAddr)
	fmt.Fprintf(&b, "    starter address: %s\n", starterAddr)
	return EventRecord{Number: NumJobReconnected, When: when, body: b.String()}
}

// ReconnectFailedEvent (024) records a failed reconnect (the job is
// rescheduled).
func ReconnectFailedEvent(when time.Time, reason, startdName string) EventRecord {
	var b strings.Builder
	b.WriteString("Job reconnection failed\n")
	fmt.Fprintf(&b, "    %s\n", reason)
	fmt.Fprintf(&b, "    Can not reconnect to %s, rescheduling job\n", startdName)
	return EventRecord{Number: NumJobReconnectFailed, When: when, body: b.String()}
}
