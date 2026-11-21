package httpserver

import (
	"path/filepath"
	"testing"

	"github.com/htcondor/golang-htcondor/logging"
	"github.com/htcondor/golang-htcondor/webapi/spool"
)

func newSpoolLimitHandler(t *testing.T, maxUpload int64) *Handler {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	h, err := NewHandler(HandlerConfig{
		ScheddName:          "test-schedd",
		ScheddAddr:          "127.0.0.1:9618",
		Logger:              logger,
		OAuth2DBPath:        filepath.Join(t.TempDir(), "oauth2.db"),
		SpoolMaxUploadBytes: maxUpload,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// The configured ceiling has to survive every hop from HandlerConfig to
// the limits the upload paths actually apply. The chain is four copies
// long and each is a hand-written assignment, so a missing one compiles
// cleanly and silently leaves the default in force.
func TestConfiguredUploadCeilingReachesTheRESTPath(t *testing.T) {
	const want = 7 << 20

	h := newSpoolLimitHandler(t, want)
	if got := h.spoolLimits().MaxVolume; got != want {
		t.Errorf("Handler.spoolLimits().MaxVolume = %d, want %d; "+
			"SpoolMaxUploadBytes did not reach the REST upload paths", got, want)
	}

	// Unset must still be a ceiling, not the absence of one.
	if got := newSpoolLimitHandler(t, 0).spoolLimits().MaxVolume; got != spool.DefaultLimits().MaxVolume {
		t.Errorf("unconfigured Handler.spoolLimits().MaxVolume = %d, want the default %d",
			got, spool.DefaultLimits().MaxVolume)
	}
}

// The MCP server is built inside NewHandler from the handler's own
// fields, so it is a separate copy that can go missing on its own.
// upload_job_input must be bounded exactly as the REST upload is --
// otherwise lowering the knob quietly leaves one of the two surfaces
// at the old default.
func TestConfiguredUploadCeilingReachesTheMCPServer(t *testing.T) {
	const want = 7 << 20

	h := newSpoolLimitHandler(t, want)
	if h.mcpServer == nil {
		t.Skip("this handler builds no MCP server; nothing to check")
	}
	got := h.mcpServer.SpoolLimits().MaxVolume
	if got != want {
		t.Errorf("mcpserver limits MaxVolume = %d, want %d; "+
			"SpoolMaxUploadBytes did not reach upload_job_input", got, want)
	}
	if rest := h.spoolLimits().MaxVolume; got != rest {
		t.Errorf("MCP ceiling %d and REST ceiling %d disagree; "+
			"one knob must bound both surfaces", got, rest)
	}
}
