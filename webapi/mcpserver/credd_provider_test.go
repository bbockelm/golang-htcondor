package mcpserver

import (
	"context"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// An access point commonly discovers its credd after this server is
// built. A snapshot taken at construction stays nil for the life of the
// process, and because the catalogue offers the credential tools only
// when a credd is present, that silently withholds all four of them.
func TestCreddProviderIsConsultedPerCall(t *testing.T) {
	var current htcondor.CreddClient
	s, err := NewServer(Config{
		ScheddProvider: func() *htcondor.Schedd { return htcondor.NewSchedd("nowhere", "127.0.0.1:1") },
		CreddProvider:  func() htcondor.CreddClient { return current },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.Close)

	if s.getCredd() != nil {
		t.Fatal("getCredd returned a credd before one was discovered")
	}
	if hasCredentialTools(s.toolsFor(context.Background())) {
		t.Fatal("the credential tools were offered with no credd")
	}

	// Discovery happens.
	current = htcondor.NewInMemoryCredd()

	if s.getCredd() == nil {
		t.Fatal("getCredd still reports no credd after discovery; the provider was not consulted")
	}
	if !hasCredentialTools(s.toolsFor(context.Background())) {
		t.Fatal("the credential tools are still withheld after discovery")
	}
}

// A snapshot still works for callers that have a credd up front.
func TestCreddSnapshotStillWorks(t *testing.T) {
	s, err := NewServer(Config{
		ScheddProvider: func() *htcondor.Schedd { return htcondor.NewSchedd("nowhere", "127.0.0.1:1") },
		Credd:          htcondor.NewInMemoryCredd(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.Close)

	if s.getCredd() == nil {
		t.Fatal("a credd passed as a snapshot did not come back from getCredd")
	}
	if !hasCredentialTools(s.toolsFor(context.Background())) {
		t.Fatal("the credential tools were withheld despite a credd")
	}
}

// A provider that answers nil falls back to the snapshot rather than
// reporting no credd, so supplying both is not a way to lose one.
func TestCreddProviderFallsBackToTheSnapshot(t *testing.T) {
	s, err := NewServer(Config{
		ScheddProvider: func() *htcondor.Schedd { return htcondor.NewSchedd("nowhere", "127.0.0.1:1") },
		Credd:          htcondor.NewInMemoryCredd(),
		CreddProvider:  func() htcondor.CreddClient { return nil },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.Close)

	if s.getCredd() == nil {
		t.Fatal("a nil provider answer lost the snapshot beside it")
	}
}

func hasCredentialTools(tools []Tool) bool {
	for _, tool := range tools {
		if strings.HasSuffix(tool.Name, "_service_credential") ||
			strings.HasSuffix(tool.Name, "_service_credentials") {
			return true
		}
	}
	return false
}
