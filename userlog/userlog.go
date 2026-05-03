// Package userlog parses HTCondor user-log files (the file pointed at
// by `log = ...` in a submit description).
//
// The wire format isn't formally specified anywhere outside the C++
// source — see reference/htcondor/src/condor_utils/condor_event.cpp,
// in particular ULogEvent::readHeader and the per-event formatBody /
// readEvent methods. This parser handles the bits that show up in
// real-world logs:
//
//   - Header line:
//
//       NNN (cluster.proc.subproc) <date> <time> <description>\n
//
//     where:
//       * NNN is a 3-digit event-type number (ULogEventNumber, see
//         the C++ enum). We recognize the well-known ones by name
//         and pass through any number we don't know.
//       * <date> is either MM/DD (legacy; year inferred from the
//         file's mtime — or "now" if we don't have one) or
//         YYYY-MM-DD (HTCondor 8.9+).
//       * <time> is HH:MM:SS, optionally with .uuuuuu microseconds
//         and an optional ±hh:mm offset.
//
//   - Body lines until a line containing only "..." (the canonical
//     event terminator). Body lines are kept verbatim in Body. We
//     also do a best-effort sweep for "key = value" / "key: value"
//     style pairs and stash them in Attributes so simple events
//     (Submit, Execute, Held, ...) can be rendered without the UI
//     having to reparse the prose.
//
// Specific events with structured per-event fields (terminated jobs'
// return code, held jobs' hold reason and code) get those fields
// promoted into top-level struct fields by extractWellKnown. The
// generic Attributes map and verbatim Body remain on every event so
// callers can fall back to raw display for anything we missed.

package userlog

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EventKind is a stable string label for an event type. The numeric
// ULogEventNumber lives in EventNumber on the parsed Event so callers
// that don't recognize the kind can still display the number.
//
// New event types should be added here AND in eventKinds (for the
// number → kind mapping). Unknown numbers parse as KindUnknown with
// EventNumber populated.
type EventKind string

const (
	KindSubmit             EventKind = "Submit"
	KindExecute            EventKind = "Execute"
	KindExecutableError    EventKind = "ExecutableError"
	KindCheckpointed       EventKind = "Checkpointed"
	KindJobEvicted         EventKind = "JobEvicted"
	KindJobTerminated      EventKind = "JobTerminated"
	KindImageSize          EventKind = "ImageSizeUpdate"
	KindShadowException    EventKind = "ShadowException"
	KindGeneric            EventKind = "Generic"
	KindJobAborted         EventKind = "JobAborted"
	KindJobSuspended       EventKind = "JobSuspended"
	KindJobUnsuspended     EventKind = "JobUnsuspended"
	KindJobHeld            EventKind = "JobHeld"
	KindJobReleased        EventKind = "JobReleased"
	KindNodeExecute        EventKind = "NodeExecute"
	KindNodeTerminated     EventKind = "NodeTerminated"
	KindPostScriptTerm     EventKind = "PostScriptTerminated"
	KindRemoteError        EventKind = "RemoteError"
	KindJobDisconnected    EventKind = "JobDisconnected"
	KindJobReconnected     EventKind = "JobReconnected"
	KindJobReconnectFailed EventKind = "JobReconnectFailed"
	KindJobAdInformation   EventKind = "JobAdInformation"
	KindJobStatusUnknown   EventKind = "JobStatusUnknown"
	KindJobStatusKnown     EventKind = "JobStatusKnown"
	KindJobStageIn         EventKind = "JobStageIn"
	KindJobStageOut        EventKind = "JobStageOut"
	KindAttributeUpdate    EventKind = "AttributeUpdate"
	KindPreSkip            EventKind = "PreSkip"
	KindClusterSubmit      EventKind = "ClusterSubmit"
	KindClusterRemove      EventKind = "ClusterRemove"
	KindFactoryPaused      EventKind = "FactoryPaused"
	KindFactoryResumed     EventKind = "FactoryResumed"
	KindFileTransfer       EventKind = "FileTransfer"
	KindReserveSpace       EventKind = "ReserveSpace"
	KindReleaseSpace       EventKind = "ReleaseSpace"
	KindFileComplete       EventKind = "FileComplete"
	KindFileUsed           EventKind = "FileUsed"
	KindFileRemoved        EventKind = "FileRemoved"
	KindDataflowJobSkipped EventKind = "DataflowJobSkipped"
	KindCommonFiles        EventKind = "CommonFiles"
	KindUnknown            EventKind = "Unknown"
)

// eventKinds maps ULogEventNumber → EventKind. Mirrors the enum in
// reference/htcondor/src/condor_utils/condor_event.h.
var eventKinds = map[int]EventKind{
	0:  KindSubmit,
	1:  KindExecute,
	2:  KindExecutableError,
	3:  KindCheckpointed,
	4:  KindJobEvicted,
	5:  KindJobTerminated,
	6:  KindImageSize,
	7:  KindShadowException,
	8:  KindGeneric,
	9:  KindJobAborted,
	10: KindJobSuspended,
	11: KindJobUnsuspended,
	12: KindJobHeld,
	13: KindJobReleased,
	14: KindNodeExecute,
	15: KindNodeTerminated,
	16: KindPostScriptTerm,
	21: KindRemoteError,
	22: KindJobDisconnected,
	23: KindJobReconnected,
	24: KindJobReconnectFailed,
	28: KindJobAdInformation,
	29: KindJobStatusUnknown,
	30: KindJobStatusKnown,
	31: KindJobStageIn,
	32: KindJobStageOut,
	33: KindAttributeUpdate,
	34: KindPreSkip,
	35: KindClusterSubmit,
	36: KindClusterRemove,
	37: KindFactoryPaused,
	38: KindFactoryResumed,
	40: KindFileTransfer,
	41: KindReserveSpace,
	42: KindReleaseSpace,
	43: KindFileComplete,
	44: KindFileUsed,
	45: KindFileRemoved,
	46: KindDataflowJobSkipped,
	47: KindCommonFiles,
}

// Event is one parsed log entry, shaped to round-trip through JSON.
// Mirrors what the Python bindings' ClassAd representation provides:
// stable fields up top, an Attributes map for everything else.
type Event struct {
	// Kind is the symbolic event type. Always set; KindUnknown when
	// the EventNumber isn't one we recognize.
	Kind EventKind `json:"kind"`

	// EventNumber is the raw 3-digit ULogEventNumber. Useful for
	// rendering "Unknown event 49" without losing the number.
	EventNumber int `json:"event_number"`

	// EventTime is the parsed timestamp from the header. UTC for
	// ISO 8601 logs that include a trailing Z; local-time for the
	// legacy MM/DD format.
	EventTime time.Time `json:"event_time"`

	// ClusterID, ProcID, SubProcID identify the job the event
	// pertains to. SubProcID is 0 for non-DAG, non-parallel jobs.
	ClusterID int `json:"cluster_id"`
	ProcID    int `json:"proc_id"`
	SubProcID int `json:"sub_proc_id"`

	// Description is the free-form text that follows the timestamp
	// on the header line — e.g. "Job submitted from host: <...>" or
	// "Job terminated.".
	Description string `json:"description"`

	// Body is the verbatim text of the body lines (everything
	// between the header and the `...` terminator), with leading
	// tabs preserved so callers can render it exactly. Empty when
	// the event has no body.
	Body string `json:"body,omitempty"`

	// Attributes are best-effort key/value pairs extracted from the
	// body. We accept "Key = value", "Key: value", and tab/spaced
	// "  key = value" forms — in roughly that order of preference.
	// String values are unwrapped if they're double-quoted; numeric
	// strings stay strings (the SPA decides whether to display a
	// number or a label).
	Attributes map[string]string `json:"attributes,omitempty"`

	// --- Promoted, well-known fields. Populated only when the
	// matching event kind sets them. ---

	// SubmitHost is the value after "Job submitted from host: " on
	// SubmitEvent. Includes the angle-bracketed sinful string.
	SubmitHost string `json:"submit_host,omitempty"`

	// ExecuteHost is the value after "Job executing on host: " on
	// ExecuteEvent.
	ExecuteHost string `json:"execute_host,omitempty"`

	// TerminatedNormally is true when JobTerminated reports a
	// normal exit (header text "(0) Normal termination"). False on
	// abnormal/signal exits.
	TerminatedNormally bool `json:"terminated_normally,omitempty"`

	// ReturnValue is the exit code on normal termination. nil when
	// the event isn't a JobTerminated, or when the job exited via
	// signal.
	ReturnValue *int `json:"return_value,omitempty"`

	// TerminatedBySignal is the signal number on signal-exit
	// terminations.
	TerminatedBySignal *int `json:"terminated_by_signal,omitempty"`

	// HoldReason / HoldReasonCode / HoldReasonSubCode populate on
	// JobHeld (12). HoldReason is the free-text reason from the
	// body; the codes come from "Code N Subcode M".
	HoldReason        string `json:"hold_reason,omitempty"`
	HoldReasonCode    *int   `json:"hold_reason_code,omitempty"`
	HoldReasonSubCode *int   `json:"hold_reason_sub_code,omitempty"`

	// AbortReason populates on JobAborted (9).
	AbortReason string `json:"abort_reason,omitempty"`
}

// Parse reads `r` to EOF and returns every event it can recognize.
// A trailing partial event (header but no `...` terminator yet — i.e.
// a job whose log is still being written) is dropped silently rather
// than reported as an error: live tailing the same file later will
// see the same event in full once it's flushed.
//
// Truly malformed events (bad header line) abort the parse and return
// every event up to that point along with the error so callers can
// still show what they got. Use ParseStrict if you'd rather refuse
// any input that isn't 100% clean.
func Parse(r io.Reader) ([]Event, error) {
	return parseAny(r, false)
}

// ParseStrict is Parse but with a partial-trailing-event check: if
// the file ends mid-event, we return the trailing partial along with
// io.ErrUnexpectedEOF.
func ParseStrict(r io.Reader) ([]Event, error) {
	return parseAny(r, true)
}

func parseAny(r io.Reader, strict bool) ([]Event, error) {
	scanner := bufio.NewScanner(r)
	// HTCondor doesn't put a hard cap on body line length but in
	// practice they're short. 1 MiB per line is enough that the
	// "Partitionable Resources" tables in JobTerminated never trip
	// the default 64 KiB ceiling.
	scanner.Buffer(make([]byte, 1<<16), 1<<20)

	var events []Event
	var current *Event
	var bodyLines []string
	lineNo := 0

	flush := func() {
		if current == nil {
			return
		}
		if len(bodyLines) > 0 {
			current.Body = strings.Join(bodyLines, "\n")
			current.Attributes = extractAttributes(bodyLines)
		}
		extractWellKnown(current, bodyLines)
		events = append(events, *current)
		current = nil
		bodyLines = nil
	}

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		// "..." on its own line ends the current event.
		if strings.TrimSpace(line) == "..." {
			if current == nil {
				// "..." with no event in progress — skip, not fatal.
				continue
			}
			flush()
			continue
		}

		// If we don't have an in-flight event, this line should be
		// a header. If it isn't, that's a malformed log; abort.
		if current == nil {
			ev, err := parseHeader(line)
			if err != nil {
				return events, fmt.Errorf("line %d: %w", lineNo, err)
			}
			current = ev
			continue
		}

		// In-flight event — accumulate body.
		bodyLines = append(bodyLines, line)
	}
	if err := scanner.Err(); err != nil {
		return events, err
	}

	// File ended mid-event. In strict mode, report; otherwise drop.
	if current != nil {
		if strict {
			return events, io.ErrUnexpectedEOF
		}
		// Fall through silently.
	}
	return events, nil
}

// headerRE matches the canonical user-log header line:
//
//	NNN (cluster.proc.subproc) <date>[ T]<time>(.usec)?(±hh:mm|Z)? description
//
// We keep a single pattern with two date alternatives so the body
// regex stays simple. The description is the rest of the line.
//
// Matching groups:
//
//	1: event-number string                  e.g. "005"
//	2: cluster.proc.subproc                 e.g. "12345.000.001"
//	3: full date+time prefix consumed       (used only as an anchor)
//	4: description                          remainder of line
var headerRE = regexp.MustCompile(
	`^(\d{3}) \((\d+)\.(\d+)\.(\d+)\) ` +
		// Date+time. Two flavors:
		//   1) MM/DD HH:MM:SS                       (legacy)
		//   2) YYYY-MM-DD HH:MM:SS(.uuuuuu)?(Z|±hh:mm)?  (ISO 8601)
		`(\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?` +
		`|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)` +
		` (.*)$`)

func parseHeader(line string) (*Event, error) {
	m := headerRE.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("malformed header: %q", line)
	}
	num, err := strconv.Atoi(m[1])
	if err != nil {
		return nil, fmt.Errorf("bad event number %q: %w", m[1], err)
	}
	cluster, _ := strconv.Atoi(m[2])
	proc, _ := strconv.Atoi(m[3])
	subproc, _ := strconv.Atoi(m[4])
	dateTimePart := m[5]
	desc := m[6]

	t, err := parseHeaderTime(dateTimePart)
	if err != nil {
		return nil, fmt.Errorf("bad timestamp %q: %w", dateTimePart, err)
	}

	kind, ok := eventKinds[num]
	if !ok {
		kind = KindUnknown
	}
	return &Event{
		Kind:        kind,
		EventNumber: num,
		EventTime:   t,
		ClusterID:   cluster,
		ProcID:      proc,
		SubProcID:   subproc,
		Description: strings.TrimRight(desc, " \t\r"),
	}, nil
}

// parseHeaderTime tolerates both the legacy MM/DD format (year
// inferred from the local clock) and the ISO 8601 form. We try the
// most-specific layouts first so a real timezone offset doesn't get
// silently dropped.
func parseHeaderTime(s string) (time.Time, error) {
	// ISO 8601 family. time.Parse insists on a literal 'T'; condor
	// uses a space, so we splice one in.
	if len(s) >= 10 && s[4] == '-' {
		spaced := strings.Replace(s, " ", "T", 1)
		layouts := []string{
			"2006-01-02T15:04:05Z",
			"2006-01-02T15:04:05.999999Z",
			"2006-01-02T15:04:05-07:00",
			"2006-01-02T15:04:05.999999-07:00",
			"2006-01-02T15:04:05",
			"2006-01-02T15:04:05.999999",
		}
		for _, l := range layouts {
			if t, err := time.Parse(l, spaced); err == nil {
				return t, nil
			}
		}
	}
	// Legacy MM/DD form. Year unstamped on the wire — fall back to
	// the current local year. This will be wrong across a year
	// boundary on old logs, matching condor_event.cpp's own
	// pre-8.8.2 behavior (gittrac #6936).
	if len(s) >= 5 && s[2] == '/' {
		layouts := []string{
			"01/02 15:04:05",
			"01/02 15:04:05.999999",
		}
		for _, l := range layouts {
			if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
				now := time.Now().Local()
				return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(),
					t.Minute(), t.Second(), t.Nanosecond(), time.Local), nil
			}
		}
	}
	return time.Time{}, errors.New("no recognized layout matched")
}

// kvRE matches a "key = value" or "key: value" pair, stripping the
// usual leading-tab indentation HTCondor emits in event bodies.
var kvRE = regexp.MustCompile(`^[\s\t]*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(.*?)\s*$`)

// extractAttributes scans body lines for "key = value" style pairs.
// Multi-line values are not supported — the C++ writer never produces
// any.  A repeated key wins last-write.
func extractAttributes(lines []string) map[string]string {
	out := map[string]string{}
	for _, ln := range lines {
		m := kvRE.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		k, v := m[1], m[2]
		// Strip surrounding double quotes (string-literal style).
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// extractWellKnown promotes per-event-type structured fields out of
// the verbatim body text. The bodies for these cases are written by
// the C++ formatBody methods in condor_event.cpp; we hand-parse the
// shapes that matter for the SPA's "pretty rendering" use case.
func extractWellKnown(ev *Event, body []string) {
	switch ev.Kind {
	case KindSubmit:
		// "Job submitted from host: <127.0.0.1:9618?...>"
		if h := strings.TrimPrefix(ev.Description, "Job submitted from host: "); h != ev.Description {
			ev.SubmitHost = h
		}

	case KindExecute:
		// "Job executing on host: <10.0.0.1:9618?...>"
		if h := strings.TrimPrefix(ev.Description, "Job executing on host: "); h != ev.Description {
			ev.ExecuteHost = h
		}

	case KindJobTerminated:
		// First body line is one of:
		//   "\t(1) Normal termination (return value 0)"
		//   "\t(0) Abnormal termination (signal 9)"
		// Description is just "Job terminated." — substance lives in
		// the body.
		for _, ln := range body {
			s := strings.TrimSpace(ln)
			if strings.HasPrefix(s, "(0) Abnormal termination") {
				ev.TerminatedNormally = false
				if sig, ok := extractParens(s, "signal "); ok {
					ev.TerminatedBySignal = &sig
				}
				break
			}
			if strings.HasPrefix(s, "(1) Normal termination") {
				ev.TerminatedNormally = true
				if rv, ok := extractParens(s, "return value "); ok {
					ev.ReturnValue = &rv
				}
				break
			}
		}

	case KindJobHeld:
		// First non-empty body line is the reason. Then a line
		// "\tCode N Subcode M".
		for _, ln := range body {
			s := strings.TrimSpace(ln)
			if s == "" {
				continue
			}
			if ev.HoldReason == "" && !strings.HasPrefix(s, "Code ") {
				ev.HoldReason = s
				continue
			}
			if strings.HasPrefix(s, "Code ") {
				if c, ok := extractInt(s, "Code "); ok {
					ev.HoldReasonCode = &c
				}
				if sc, ok := extractInt(s, "Subcode "); ok {
					ev.HoldReasonSubCode = &sc
				}
			}
		}

	case KindJobAborted:
		// Body's first non-empty line is the abort reason.
		for _, ln := range body {
			s := strings.TrimSpace(ln)
			if s != "" {
				ev.AbortReason = s
				break
			}
		}
	}
}

// extractParens reads the integer that follows `prefix` up to the
// next ')' character. Used to pull the return-value / signal number
// out of "...(return value 0)" style bodies. Returns false when the
// prefix isn't found or the trailing token isn't a clean int.
func extractParens(s, prefix string) (int, bool) {
	i := strings.Index(s, prefix)
	if i < 0 {
		return 0, false
	}
	rest := s[i+len(prefix):]
	end := strings.Index(rest, ")")
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(strings.TrimSpace(rest[:end]))
	if err != nil {
		return 0, false
	}
	return n, true
}

// extractInt reads the integer that follows `prefix`, terminated by
// whitespace, ')' or end of string. Used by the JobHeld path to pull
// "Code 16" / "Subcode 0" out of mixed prose.
func extractInt(s, prefix string) (int, bool) {
	i := strings.Index(s, prefix)
	if i < 0 {
		return 0, false
	}
	rest := s[i+len(prefix):]
	// Walk while we see digits / leading sign.
	end := 0
	for end < len(rest) {
		c := rest[end]
		if c == '-' && end == 0 {
			end++
			continue
		}
		if c < '0' || c > '9' {
			break
		}
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}
