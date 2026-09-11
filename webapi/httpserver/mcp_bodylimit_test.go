package httpserver

import (
	"os"
	"strings"
	"testing"
)

// handleMCPMessage read the request body with io.ReadAll and no limit, so
// one authenticated caller could make the server allocate whatever it
// chose to send. The body is read whole -- twice on the OAuth path, which
// buffers and re-reads it -- so the bound has to be in place before the
// first read.
// The bound must be applied before anything reads the body.
//
// This asserts it structurally rather than behaviourally, and the reason
// is worth stating: handleMCPMessage validates the token first and
// returns on failure without reading the body at all, so a request with
// an invalid token consumes nothing whether the bound is there or not.
// A test driving the handler that way passes with the MaxBytesReader
// deleted -- it was written, it did, and it was measuring nothing.
// Reaching the read needs a genuinely valid OAuth2 token against a live
// provider, which is the integration suite's territory.
//
// So: check the source. Brittle in the usual way, but it fails when
// someone removes the line, which behavioural coverage here does not.
func TestMCPBodyBoundIsAppliedBeforeAnyRead(t *testing.T) {
	src, err := os.ReadFile("mcp_handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	fn := strings.Index(text, "func (h *Handler) handleMCPMessage(")
	if fn < 0 {
		t.Fatal("handleMCPMessage not found; this test needs updating")
	}
	body := text[fn:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}

	bound := strings.Index(body, "http.MaxBytesReader")
	if bound < 0 {
		t.Fatal("handleMCPMessage does not bound the request body: " +
			"io.ReadAll on an unbounded body lets one caller decide how much " +
			"the server allocates")
	}
	firstRead := strings.Index(body, "io.ReadAll(r.Body)")
	if firstRead >= 0 && bound > firstRead {
		t.Error("the body is read before it is bounded; MaxBytesReader has to come first")
	}
}

// The limit must leave room for what the tools actually advise:
// upload_job_input's 100 KB guidance is advisory, and a larger upload
// warns rather than failing. A bound at or near that size would turn
// advice into a hard limit.
func TestMCPBodyLimitLeavesRoomForAdvisedUploads(t *testing.T) {
	const advisedContent = 100 * 1024
	// base64 inflates by 4/3 and JSON escaping adds more; a caller may
	// also send several files in one call.
	const realistic = advisedContent * 4 / 3 * 8
	if maxMCPBody <= realistic {
		t.Errorf("maxMCPBody = %d, which is not comfortably above a realistic "+
			"advised upload (%d); it would reject calls that work today",
			maxMCPBody, realistic)
	}
}
