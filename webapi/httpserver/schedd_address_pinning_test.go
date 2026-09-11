package httpserver

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

const (
	oldScheddAddr = "<10.0.0.1:9618?addrs=10.0.0.1-9618&noUDP&sock=schedd_111_aaaa>"
	newScheddAddr = "<10.0.0.1:9618?addrs=10.0.0.1-9618&noUDP&sock=schedd_222_bbbb>"
)

func pinningTestServer(t *testing.T, discovered bool) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	s, err := NewServer(Config{
		Logger:               logger,
		ScheddName:           "head04.example.org",
		ScheddAddr:           oldScheddAddr,
		ScheddAddrDiscovered: discovered,
		OAuth2DBPath:         t.TempDir() + "/oauth2.db",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return s
}

// An address the daemon resolved from the collector must follow the
// collector.
//
// The daemon resolves it in main() and hands the result to the server as
// ScheddAddr, which is indistinguishable from an operator having pinned
// one. So a deployment that set only SCHEDD_NAME was treated as pinned:
// when the schedd restarted onto a new shared-port socket, the periodic
// updater saw the collector advertising the new address, logged that it
// was "keeping operator-configured value", and went on dialling a socket
// that no longer existed until the process was restarted. Issue #308.
func TestDiscoveredScheddAddressFollowsTheCollector(t *testing.T) {
	s := pinningTestServer(t, true)

	if got := s.getSchedd().Address(); got != oldScheddAddr {
		t.Fatalf("precondition: address = %q, want the configured one", got)
	}

	s.confirmScheddAddress(newScheddAddr)

	if got := s.getSchedd().Address(); got != newScheddAddr {
		t.Errorf("address = %q, want the collector's %q; the daemon would keep dialling a dead socket",
			got, newScheddAddr)
	}
}

// An address an operator pinned is still honoured. The point of the fix is
// to tell the two apart, not to stop honouring configuration.
func TestOperatorPinnedScheddAddressIsKept(t *testing.T) {
	s := pinningTestServer(t, false)

	s.confirmScheddAddress(newScheddAddr)

	if got := s.getSchedd().Address(); got != oldScheddAddr {
		t.Errorf("address = %q, want the operator's %q left alone", got, oldScheddAddr)
	}
}

// Confirmation advances the freshness timestamp either way -- that is what
// /readyz reports, and it is about the collector having answered, not about
// whether the address moved.
func TestConfirmationAdvancesFreshnessEvenWhenPinned(t *testing.T) {
	s := pinningTestServer(t, false)

	s.confirmScheddAddress(newScheddAddr)

	_, sinceConfirmed := s.scheddAddrAges()
	if sinceConfirmed == 0 {
		t.Error("the confirmation timestamp did not advance")
	}
}
