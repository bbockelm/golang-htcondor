package httpserver

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

func newMultipartTestServer(t *testing.T) *Server {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	server, err := NewServer(Config{
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		Logger:       logger,
		OAuth2DBPath: t.TempDir() + "/sessions.db",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return server
}

// TestHandleJobInputMultipart_WrongMethod tests with wrong HTTP method
func TestHandleJobInputMultipart_WrongMethod(t *testing.T) {
	server := newMultipartTestServer(t)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/jobs/123.0/input/multipart", nil)
			w := httptest.NewRecorder()

			server.handleJobInputMultipart(w, req, "123.0")

			resp := w.Result()
			defer func() {
				_ = resp.Body.Close()
			}()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("Expected status 405 for method %s, got %d", method, resp.StatusCode)
			}
		})
	}
}

// TestHandleJobInputMultipart_NoAuth tests without authentication
func TestHandleJobInputMultipart_NoAuth(t *testing.T) {
	server := newMultipartTestServer(t)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/123.0/input/multipart", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()

	server.handleJobInputMultipart(w, req, "123.0")

	resp := w.Result()
	defer func() {
		_ = resp.Body.Close()
	}()

	// Without authentication, should return 401
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

// TestRouting_JobInputMultipart tests that the routing works for the new endpoint
func TestRouting_JobInputMultipart(t *testing.T) {
	server := newMultipartTestServer(t)

	testCases := []struct {
		name        string
		path        string
		shouldMatch bool
	}{
		{"valid path", "/api/v1/jobs/123.0/input/multipart", true},
		{"valid path with high proc", "/api/v1/jobs/999.999/input/multipart", true},
		{"wrong path - no multipart", "/api/v1/jobs/123.0/input", false},
		{"wrong path - extra segment", "/api/v1/jobs/123.0/input/multipart/extra", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			w := httptest.NewRecorder()

			// Test via handleJobByID which does routing
			server.handleJobByID(w, req)

			resp := w.Result()
			defer func() {
				_ = resp.Body.Close()
			}()

			if tc.shouldMatch {
				// Should hit handleJobInputMultipart, which will return 401 (no auth)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("Expected 401 for matched route, got %d", resp.StatusCode)
				}
			}
			// For non-matching paths, just verify they don't crash
		})
	}
}
