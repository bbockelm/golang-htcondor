package httpserver

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// The setting has to survive the trip from Config to the field the SSH
// handler reads. Nothing else observes it, so if the assignment were
// dropped the only symptom would be condor_ssh_to_job timing out against
// a CCB'd execute node -- a failure that needs a firewall to reproduce
// and looks like a network problem when it happens.
func TestCCBStreamingReachesTheHandler(t *testing.T) {
	for _, want := range []bool{true, false} {
		logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
		if err != nil {
			t.Fatalf("logger: %v", err)
		}
		s, err := NewServer(Config{
			Logger:       logger,
			ScheddName:   "test-schedd",
			ScheddAddr:   "127.0.0.1:9618",
			OAuth2DBPath: t.TempDir() + "/oauth2.db",
			CCBStreaming: want,
		})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		if s.ccbStreaming != want {
			t.Errorf("CCBStreaming=%v did not reach the handler (got %v)", want, s.ccbStreaming)
		}
	}
}
