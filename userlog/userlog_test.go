package userlog

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// Realistic log captured from a vanilla-universe job that submitted
// (with a SPOOL hold), ran briefly, then terminated normally. Layout
// matches what HTCondor 25.x emits to a `log = job.log`.
const sampleLog = `000 (12345.000.000) 2024-09-15 10:23:45 Job submitted from host: <127.0.0.1:9618?addrs=127.0.0.1-9618&noUDP&sock=schedd_1234>
...
012 (12345.000.000) 2024-09-15 10:23:45 Job was held.
	Spooling input data files
	Code 16 Subcode 0
...
013 (12345.000.000) 2024-09-15 10:23:48 Job was released.
	Data files spooled
...
001 (12345.000.000) 2024-09-15 10:23:50 Job executing on host: <10.0.0.1:9618?addrs=10.0.0.1-9618&noUDP&sock=startd_5678>
	SlotName: slot1@worker.example.org
	CondorScratchDir = "/scratch/condor/dir_12345"
...
006 (12345.000.000) 2024-09-15 10:23:55 Image size of job updated: 4096
	1024  -  MemoryUsage of job (MB)
	1048576  -  ResidentSetSize of job (KB)
...
005 (12345.000.000) 2024-09-15 10:24:02 Job terminated.
	(1) Normal termination (return value 0)
		Usr 0 00:00:01, Sys 0 00:00:00  -  Run Remote Usage
		Usr 0 00:00:00, Sys 0 00:00:00  -  Run Local Usage
		Usr 0 00:00:01, Sys 0 00:00:00  -  Total Remote Usage
		Usr 0 00:00:00, Sys 0 00:00:00  -  Total Local Usage
	0  -  Run Bytes Sent By Job
	18  -  Run Bytes Received By Job
	0  -  Total Bytes Sent By Job
	18  -  Total Bytes Received By Job
	Partitionable Resources :    Usage  Request Allocated
	   Cpus                 :     0.00        1         1
	   Disk (KB)            :       45     1024     50000
	   Memory (MB)          :        0      128       128
...
`

func TestParse_HappyPath(t *testing.T) {
	events, err := Parse(strings.NewReader(sampleLog))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := len(events), 6; got != want {
		t.Fatalf("got %d events, want %d", got, want)
	}

	// Spot-check identity and ordering.
	wantKinds := []EventKind{
		KindSubmit,
		KindJobHeld,
		KindJobReleased,
		KindExecute,
		KindImageSize,
		KindJobTerminated,
	}
	for i, ev := range events {
		if ev.Kind != wantKinds[i] {
			t.Errorf("event[%d] kind = %q, want %q", i, ev.Kind, wantKinds[i])
		}
		if ev.ClusterID != 12345 || ev.ProcID != 0 || ev.SubProcID != 0 {
			t.Errorf("event[%d] job id = %d.%d.%d, want 12345.0.0",
				i, ev.ClusterID, ev.ProcID, ev.SubProcID)
		}
	}

	// SubmitHost extracted from header description.
	submit := events[0]
	if submit.SubmitHost == "" {
		t.Error("Submit event: expected SubmitHost to be populated")
	}
	if !strings.HasPrefix(submit.SubmitHost, "<127.0.0.1:9618") {
		t.Errorf("Submit event: SubmitHost = %q", submit.SubmitHost)
	}

	// Held event: hold reason + code + subcode promoted.
	held := events[1]
	if held.HoldReason != "Spooling input data files" {
		t.Errorf("JobHeld: HoldReason = %q", held.HoldReason)
	}
	if held.HoldReasonCode == nil || *held.HoldReasonCode != 16 {
		t.Errorf("JobHeld: HoldReasonCode = %v, want 16", held.HoldReasonCode)
	}
	if held.HoldReasonSubCode == nil || *held.HoldReasonSubCode != 0 {
		t.Errorf("JobHeld: HoldReasonSubCode = %v, want 0", held.HoldReasonSubCode)
	}

	// Execute event: executing host + arbitrary tabbed key=value pairs
	// stashed into Attributes for the SPA to render.
	exec := events[3]
	if !strings.Contains(exec.ExecuteHost, "10.0.0.1:9618") {
		t.Errorf("Execute: ExecuteHost = %q", exec.ExecuteHost)
	}
	if got := exec.Attributes["SlotName"]; got != "slot1@worker.example.org" {
		t.Errorf("Execute: Attributes[SlotName] = %q", got)
	}
	if got := exec.Attributes["CondorScratchDir"]; got != "/scratch/condor/dir_12345" {
		t.Errorf("Execute: Attributes[CondorScratchDir] = %q (expected unquoted)", got)
	}

	// Terminated event: normal exit, return value 0.
	term := events[5]
	if !term.TerminatedNormally {
		t.Errorf("JobTerminated: TerminatedNormally = false, want true")
	}
	if term.ReturnValue == nil || *term.ReturnValue != 0 {
		t.Errorf("JobTerminated: ReturnValue = %v, want 0", term.ReturnValue)
	}
	if term.TerminatedBySignal != nil {
		t.Errorf("JobTerminated: TerminatedBySignal = %v, want nil", term.TerminatedBySignal)
	}

	// Body roundtrip: the verbatim body of the terminated event
	// should preserve the partitionable-resources block.
	if !strings.Contains(term.Body, "Partitionable Resources") {
		t.Errorf("JobTerminated: Body missing Partitionable Resources line\n%s", term.Body)
	}
}

func TestParse_AbnormalExit(t *testing.T) {
	in := `005 (1.0.0) 2024-09-15 10:24:02 Job terminated.
	(0) Abnormal termination (signal 9)
		Usr 0 00:00:00, Sys 0 00:00:00  -  Run Remote Usage
...
`
	events, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.TerminatedNormally {
		t.Errorf("TerminatedNormally = true, want false")
	}
	if ev.ReturnValue != nil {
		t.Errorf("ReturnValue = %v, want nil", ev.ReturnValue)
	}
	if ev.TerminatedBySignal == nil || *ev.TerminatedBySignal != 9 {
		t.Errorf("TerminatedBySignal = %v, want 9", ev.TerminatedBySignal)
	}
}

func TestParse_AbortedJob(t *testing.T) {
	in := `009 (42.0.0) 2024-09-15 10:24:02 Job was aborted.
	via condor_rm (by user vscode)
...
`
	events, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(events) != 1 || events[0].Kind != KindJobAborted {
		t.Fatalf("got %#v", events)
	}
	if !strings.HasPrefix(events[0].AbortReason, "via condor_rm") {
		t.Errorf("AbortReason = %q", events[0].AbortReason)
	}
}

func TestParse_LegacyDateFormat(t *testing.T) {
	// Pre-8.8 condor wrote MM/DD HH:MM:SS without a year. Year is
	// inferred from the local clock.
	in := `000 (1.0.0) 09/15 10:23:45 Job submitted from host: <127.0.0.1:9618>
...
`
	events, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	t0 := events[0].EventTime
	if t0.Year() != time.Now().Year() {
		t.Errorf("legacy date: year = %d, want current %d", t0.Year(), time.Now().Year())
	}
	if t0.Month() != time.September || t0.Day() != 15 {
		t.Errorf("legacy date: %v, want 9/15", t0)
	}
}

func TestParse_ISO8601WithTimezone(t *testing.T) {
	in := `000 (1.0.0) 2024-09-15 10:23:45-04:00 Job submitted from host: <127.0.0.1:9618>
...
`
	events, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	t0 := events[0].EventTime
	// 10:23:45 -04:00 == 14:23:45 UTC
	if got := t0.UTC().Format("15:04:05"); got != "14:23:45" {
		t.Errorf("UTC time = %s, want 14:23:45", got)
	}
}

func TestParse_TrailingPartialEventDropped(t *testing.T) {
	in := `000 (1.0.0) 2024-09-15 10:23:45 Job submitted from host: <127.0.0.1:9618>
...
001 (1.0.0) 2024-09-15 10:23:50 Job executing on host: <10.0.0.1:9618>
	(no terminator yet — the schedd hasn't flushed it)`
	events, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("non-strict Parse should not error on partial trailing event: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1 (the complete one)", len(events))
	}
	if events[0].Kind != KindSubmit {
		t.Errorf("event kind = %q", events[0].Kind)
	}
}

func TestParseStrict_TrailingPartialEvent(t *testing.T) {
	in := `000 (1.0.0) 2024-09-15 10:23:45 Job submitted from host: <127.0.0.1:9618>
...
001 (1.0.0) 2024-09-15 10:23:50 Job executing on host: <10.0.0.1:9618>
	(no terminator)`
	events, err := ParseStrict(strings.NewReader(in))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
	}
	// The complete event still comes through.
	if len(events) != 1 {
		t.Errorf("got %d events, want 1", len(events))
	}
}

func TestParse_MalformedHeaderHaltsButReturnsPriorEvents(t *testing.T) {
	in := `000 (1.0.0) 2024-09-15 10:23:45 Job submitted from host: <127.0.0.1:9618>
...
this is not a valid header line
...
`
	events, err := Parse(strings.NewReader(in))
	if err == nil {
		t.Fatalf("expected error on malformed header")
	}
	if !strings.Contains(err.Error(), "malformed header") {
		t.Errorf("error %q does not mention malformed header", err)
	}
	if len(events) != 1 {
		t.Errorf("got %d events, want 1 (the one before the bad line)", len(events))
	}
}

func TestParse_UnknownEventNumber(t *testing.T) {
	// 099 is not in our enum (yet). Parser should still take it,
	// label it KindUnknown, and keep the EventNumber.
	in := `099 (1.0.0) 2024-09-15 10:23:45 Some new event we don't know about.
	WhateverField: 42
...
`
	events, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	if events[0].Kind != KindUnknown {
		t.Errorf("kind = %q, want %q", events[0].Kind, KindUnknown)
	}
	if events[0].EventNumber != 99 {
		t.Errorf("event number = %d, want 99", events[0].EventNumber)
	}
	// Generic key/value extraction should still work.
	if got := events[0].Attributes["WhateverField"]; got != "42" {
		t.Errorf("Attributes[WhateverField] = %q", got)
	}
}

func TestParse_SubProcID(t *testing.T) {
	// DAGMan and parallel jobs use non-zero subproc.
	in := `001 (12345.0.7) 2024-09-15 10:23:50 Job executing on host: <10.0.0.1:9618>
...
`
	events, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if events[0].SubProcID != 7 {
		t.Errorf("SubProcID = %d, want 7", events[0].SubProcID)
	}
}

func TestParse_EmptyInput(t *testing.T) {
	events, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse(empty): %v", err)
	}
	if len(events) != 0 {
		t.Errorf("got %d events from empty input", len(events))
	}
}
