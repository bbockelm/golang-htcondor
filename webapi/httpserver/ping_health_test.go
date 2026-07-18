package httpserver

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPingHealthDisabled(t *testing.T) {
	// Zero ping interval = ping disabled = health reporting disabled. Both
	// daemons report "disabled" and overall is "ok" (we don't want a server
	// without periodic pings to fail readiness).
	p := newPingHealth(0)
	p.markCollectorEnabled()
	p.markScheddEnabled()
	p.recordCollectorFailure(errors.New("ignored"), connErrorOther)

	snap := p.snapshot()
	if snap.Collector.Status != "disabled" {
		t.Errorf("Collector.Status = %q, want disabled", snap.Collector.Status)
	}
	if snap.Schedd.Status != "disabled" {
		t.Errorf("Schedd.Status = %q, want disabled", snap.Schedd.Status)
	}
	// Both daemons disabled → overall "disabled". /readyz still returns 200
	// for this state (see handleReadyz), so the only consequence of
	// reporting "disabled" rather than "ok" is that the JSON body honestly
	// tells the operator that pings aren't running.
	if snap.Status != "disabled" {
		t.Errorf("Overall = %q, want disabled", snap.Status)
	}
}

func TestPingHealthInitialDownAfterFirstFailure(t *testing.T) {
	// A daemon that is enabled but has only ever failed (never succeeded)
	// should report "down", not "unknown". This is the case where we know
	// the daemon is configured but unreachable from the very first tick.
	p := newPingHealth(time.Second)
	p.markCollectorEnabled()
	p.recordCollectorFailure(errors.New("conn refused"), connErrorRefused)

	snap := p.snapshot()
	if snap.Collector.Status != "down" {
		t.Errorf("Collector.Status = %q, want down", snap.Collector.Status)
	}
	if snap.Collector.LastError != "conn refused" {
		t.Errorf("LastError = %q, want %q", snap.Collector.LastError, "conn refused")
	}
	if snap.Collector.LastErrorKind != string(connErrorRefused) {
		t.Errorf("LastErrorKind = %q, want %q", snap.Collector.LastErrorKind, connErrorRefused)
	}
}

func TestPingHealthOK(t *testing.T) {
	p := newPingHealth(time.Second)
	p.markCollectorEnabled()
	p.markScheddEnabled()
	p.recordCollectorSuccess()
	p.recordScheddSuccess()

	snap := p.snapshot()
	if snap.Collector.Status != "ok" {
		t.Errorf("Collector.Status = %q, want ok", snap.Collector.Status)
	}
	if snap.Schedd.Status != "ok" {
		t.Errorf("Schedd.Status = %q, want ok", snap.Schedd.Status)
	}
	if snap.Status != "ok" {
		t.Errorf("Overall = %q, want ok", snap.Status)
	}
}

func TestPingHealthWarningAfterRecentFailure(t *testing.T) {
	// Success first, then failure. Failure timestamp is later than success →
	// status is "warning" (we have a baseline ok, but it's currently broken).
	p := newPingHealth(time.Hour) // big interval so staleness doesn't trip
	p.markScheddEnabled()
	p.recordScheddSuccess()
	time.Sleep(2 * time.Millisecond)
	p.recordScheddFailure(errors.New("transient"), connErrorTimeout)

	snap := p.snapshot()
	if snap.Schedd.Status != "warning" {
		t.Errorf("Schedd.Status = %q, want warning", snap.Schedd.Status)
	}
	if snap.Status != "warning" {
		t.Errorf("Overall = %q, want warning", snap.Status)
	}
}

func TestPingHealthWarningOnStaleness(t *testing.T) {
	// Ping interval is small. Successful ping was a long time ago, no
	// recorded failures → "warning" via staleness gate. The test
	// fast-forwards by manually setting the lastOK timestamp to the past;
	// time.Sleep in tests is unreliable for any meaningful interval.
	p := newPingHealth(time.Millisecond)
	p.markScheddEnabled()
	p.scheddLastOK = time.Now().Add(-1 * time.Hour) // way past staleness
	p.scheddEnabled = true                          // already true but explicit

	snap := p.snapshot()
	if snap.Schedd.Status != "warning" {
		t.Errorf("Schedd.Status = %q, want warning (lastOK far in the past)", snap.Schedd.Status)
	}
}

func TestPingHealthRecoveryClearsError(t *testing.T) {
	// After a failure, a successful ping must clear the recorded error so
	// /readyz reverts to "ok" rather than carrying stale failure metadata.
	p := newPingHealth(time.Hour)
	p.markCollectorEnabled()
	p.recordCollectorFailure(errors.New("transient"), connErrorTimeout)
	p.recordCollectorSuccess()

	snap := p.snapshot()
	if snap.Collector.Status != "ok" {
		t.Errorf("Collector.Status = %q, want ok after recovery", snap.Collector.Status)
	}
	if snap.Collector.LastError != "" {
		t.Errorf("LastError = %q, want empty after recovery", snap.Collector.LastError)
	}
	if snap.Collector.LastErrorKind != "" {
		t.Errorf("LastErrorKind = %q, want empty after recovery", snap.Collector.LastErrorKind)
	}
}

func TestPingHealthOverallIsWorseOfTwo(t *testing.T) {
	// Collector is fine, schedd is down → overall "down". Operators should
	// see the worst component reflected in the top-level status.
	p := newPingHealth(time.Hour)
	p.markCollectorEnabled()
	p.markScheddEnabled()
	p.recordCollectorSuccess()
	p.recordScheddFailure(errors.New("nope"), connErrorRefused)

	snap := p.snapshot()
	if snap.Status != "down" {
		t.Errorf("Overall = %q, want down (schedd is down even though collector is ok)", snap.Status)
	}
	if snap.Collector.Status != "ok" {
		t.Errorf("Collector.Status = %q, want ok", snap.Collector.Status)
	}
	if snap.Schedd.Status != "down" {
		t.Errorf("Schedd.Status = %q, want down", snap.Schedd.Status)
	}
}

func TestPingHealthNilReceiver(t *testing.T) {
	// /readyz on a server that never enabled pings (no h.pingHealth) must
	// not nil-panic. snapshot() on a nil receiver returns a benign "ok" view.
	var p *pingHealth
	snap := p.snapshot()
	if snap.Status != "ok" {
		t.Errorf("nil-receiver snapshot Status = %q, want ok", snap.Status)
	}
	if snap.Collector.Status != "disabled" || snap.Schedd.Status != "disabled" {
		t.Errorf("nil-receiver: per-daemon should be disabled, got %+v", snap)
	}
	// And the record/mark methods must be no-ops, not panic.
	p.markCollectorEnabled()
	p.recordCollectorSuccess()
	p.recordScheddFailure(errors.New("x"), connErrorOther)
}

// TestDaemonHealthStatusJSONOmitsEmptyAddressAge guards the JSON contract
// for /readyz: AddressAge fields are populated only for daemons whose
// address we discover (schedd today; potentially others later). Verifying
// they're omitted when empty keeps the collector entry from accumulating
// confusing zero-valued fields once we wire it up similarly.
func TestDaemonHealthStatusJSONOmitsEmptyAddressAge(t *testing.T) {
	d := daemonHealthStatus{Status: "ok"}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(b); strings.Contains(got, "address_age") {
		t.Errorf("AddressAge should be omitted when empty, got: %s", got)
	}
	if got := string(b); strings.Contains(got, "address_last_confirmed_age") {
		t.Errorf("AddressLastConfirmedAge should be omitted when empty, got: %s", got)
	}
}

func TestWorseStatus(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"ok", "ok", "ok"},
		{"ok", "warning", "warning"},
		{"warning", "ok", "warning"},
		{"warning", "down", "down"},
		{"down", "warning", "down"},
		{"unknown", "ok", "unknown"},
		{"down", "unknown", "down"},
		{"disabled", "ok", "ok"},
		{"disabled", "disabled", "disabled"},
	}
	for _, tc := range cases {
		got := worseStatus(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("worseStatus(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}
