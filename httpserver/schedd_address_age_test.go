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
