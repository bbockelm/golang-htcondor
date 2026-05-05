package httpserver

import (
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestUpdateScheddAddrAgeTracking pins the contract that scheddAddrAges
// returns sensible values across each Handler state transition: just
// constructed → not yet refreshed → refreshed-but-unchanged → refreshed-and-
// changed. This is the data structure that powers the "address age" log
// fields and /readyz output, so a regression here would silently strip the
// most useful diagnostic.
func TestUpdateScheddAddrAgeTracking(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	const initialAddr = "<127.0.0.1:9618?sock=schedd_1_1>"
	now := time.Now()
	h := &Handler{
		schedd:                    htcondor.NewSchedd("test", initialAddr),
		scheddName:                "test",
		scheddAddrSetAt:           now,
		scheddAddrLastConfirmedAt: now,
		logger:                    logger,
	}

	// Initial state — both ages should be 0 to a few hundred microseconds,
	// well under a second. We don't assert "exactly zero" because clocks
	// move; the assertion is that the timestamps were initialized at all.
	sinceSet, sinceConfirmed := h.scheddAddrAges()
	if sinceSet > time.Second {
		t.Errorf("freshly constructed handler should have small AddressAge, got %s", sinceSet)
	}
	if sinceConfirmed > time.Second {
		t.Errorf("freshly constructed handler should have small AddressLastConfirmedAge, got %s", sinceConfirmed)
	}

	// Backdate scheddAddrSetAt so we can detect that
	// "refreshed-but-unchanged" updates lastConfirmed but does NOT reset
	// setAt — which is the whole reason these fields are tracked separately.
	h.scheddMu.Lock()
	h.scheddAddrSetAt = now.Add(-10 * time.Minute)
	h.scheddAddrLastConfirmedAt = now.Add(-9 * time.Minute)
	h.scheddMu.Unlock()

	// Re-confirm with the SAME address. The collector successfully returned
	// the same value we already had → setAt unchanged, lastConfirmed reset
	// to ~now.
	h.UpdateSchedd(initialAddr)
	sinceSet, sinceConfirmed = h.scheddAddrAges()
	if sinceSet < 9*time.Minute {
		t.Errorf("re-confirming same address should NOT reset setAt, got %s (expected ≥ 9m)", sinceSet)
	}
	if sinceConfirmed > time.Second {
		t.Errorf("re-confirming same address should reset lastConfirmed, got %s", sinceConfirmed)
	}

	// Now update with a different address. setAt should reset; lastConfirmed
	// should also reset. The schedd instance should reflect the new address.
	const newAddr = "<127.0.0.1:9618?sock=schedd_2_2>"
	h.UpdateSchedd(newAddr)
	if got := h.GetSchedd().Address(); got != newAddr {
		t.Errorf("schedd address after UpdateSchedd = %q, want %q", got, newAddr)
	}
	sinceSet, sinceConfirmed = h.scheddAddrAges()
	if sinceSet > time.Second {
		t.Errorf("address change should reset setAt, got %s", sinceSet)
	}
	if sinceConfirmed > time.Second {
		t.Errorf("address change should reset lastConfirmed, got %s", sinceConfirmed)
	}
}

// TestConfirmScheddAddressOperatorPinned exercises the failure mode that
// drove the "address_last_confirmed_age=45m" report on a deployed pod:
// the operator passed an explicit ScheddAddr (so scheddDiscovered=false),
// the address-updater wasn't running, and the timestamp was frozen at
// startup. The fix runs the updater unconditionally; on each tick it
// calls confirmScheddAddress, which must (a) advance the freshness
// timestamp, and (b) NOT replace the operator-pinned address even when
// the collector reports something different.
func TestConfirmScheddAddressOperatorPinned(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	const pinned = "<127.0.0.1:9618?sock=pinned>"
	const collectorReports = "<127.0.0.1:9618?sock=different>"

	now := time.Now()
	h := &Handler{
		schedd:                    htcondor.NewSchedd("test", pinned),
		scheddName:                "test",
		scheddDiscovered:          false, // operator-pinned via ScheddAddr
		scheddAddrSetAt:           now.Add(-30 * time.Minute),
		scheddAddrLastConfirmedAt: now.Add(-30 * time.Minute),
		logger:                    logger,
	}

	// Collector says a different address. confirmScheddAddress must
	// keep the configured value but advance the freshness timestamp.
	h.confirmScheddAddress(collectorReports)

	if got := h.GetSchedd().Address(); got != pinned {
		t.Errorf("address swapped despite scheddDiscovered=false: got %q, want %q", got, pinned)
	}
	_, sinceConfirmed := h.scheddAddrAges()
	if sinceConfirmed > time.Second {
		t.Errorf("confirm should reset lastConfirmed even when not swapping, got %s", sinceConfirmed)
	}
}

// TestConfirmScheddAddressDiscovered checks the converse: when the
// address came from collector discovery initially, confirm DOES swap
// to the new address — same authoritative-collector behavior the
// updater had before the refactor.
func TestConfirmScheddAddressDiscovered(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	const initial = "<127.0.0.1:9618?sock=v1>"
	const updated = "<127.0.0.1:9618?sock=v2>"

	now := time.Now()
	h := &Handler{
		schedd:                    htcondor.NewSchedd("test", initial),
		scheddName:                "test",
		scheddDiscovered:          true,
		scheddAddrSetAt:           now.Add(-30 * time.Minute),
		scheddAddrLastConfirmedAt: now.Add(-30 * time.Minute),
		logger:                    logger,
	}

	h.confirmScheddAddress(updated)
	if got := h.GetSchedd().Address(); got != updated {
		t.Errorf("address not swapped: got %q, want %q", got, updated)
	}
	sinceSet, sinceConfirmed := h.scheddAddrAges()
	if sinceSet > time.Second {
		t.Errorf("address change should reset setAt, got %s", sinceSet)
	}
	if sinceConfirmed > time.Second {
		t.Errorf("address change should reset lastConfirmed, got %s", sinceConfirmed)
	}
}
