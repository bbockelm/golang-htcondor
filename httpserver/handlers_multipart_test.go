package httpserver

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestJobInputSpoolProjectionIncludesExecutableAttrs locks in the fix
// for an inline-script submit that held with
// "Transfer input files failure ... run.sh: (errno 2)" — the projection
// used to look up the proc ad before tar-streaming files into the spool
// must carry Cmd and TransferExecutable, otherwise getInputFilesFromJobAd
// (over in schedd_transfer.go) doesn't add the executable's basename to
// its allow-set and sendJobFilesFromTar silently drops it.
//
// If anyone trims this list back to just {ClusterId, ProcId, TransferInput}
// the regression returns and the SPA's "Write executable script inline"
// affordance breaks again.
func TestJobInputSpoolProjectionIncludesExecutableAttrs(t *testing.T) {
	for _, attr := range []string{"Cmd", "TransferExecutable", "TransferInput"} {
		if !slices.Contains(jobInputSpoolProjection, attr) {
			t.Errorf("jobInputSpoolProjection is missing %q; getInputFilesFromJobAd needs it to include the executable in the spool allow-set, "+
				"the multipart handler will silently drop it from the tar, and the job will hold with ENOENT", attr)
		}
	}
}

// TestOverlayClusterOntoProc covers the cluster→proc attribute
// overlay used by fetchProcAdForSpool. The HTCondor schedd stores
// attributes shared across all procs of a cluster (Cmd,
// TransferExecutable, …) on the cluster ad; a proc-only query
// returns them as absent. Without overlaying the cluster ad,
// getInputFilesFromJobAd never sees Cmd, the executable's basename
// never makes it into the spool allow-set, and inline-script jobs
// hold with ENOENT.
//
// Each subtest pins one behavior so a regression that breaks any
// invariant (cluster attrs added, proc wins on conflict, nil-cluster
// safe) names itself precisely.
func TestOverlayClusterOntoProc(t *testing.T) {
	t.Run("ClusterAttrsCopiedWhenAbsentOnProc", func(t *testing.T) {
		// This is the load-bearing case: the proc-only query strips
		// out cluster-level Cmd / TransferExecutable, and we have to
		// copy them in for the spool allow-set to include the
		// executable's basename.
		cluster := classad.New()
		_ = cluster.Set("ProcId", int64(-1))
		_ = cluster.Set("Cmd", "run.sh")
		_ = cluster.Set("TransferExecutable", true)

		proc := classad.New()
		_ = proc.Set("ClusterId", int64(7))
		_ = proc.Set("ProcId", int64(0))
		_ = proc.Set("TransferInput", "input.txt")

		overlayClusterOntoProc(cluster, proc)

		if got, _ := proc.EvaluateAttrString("Cmd"); got != "run.sh" {
			t.Errorf("Cmd not overlaid from cluster: got %q", got)
		}
		if got, _ := proc.EvaluateAttrBool("TransferExecutable"); !got {
			t.Errorf("TransferExecutable not overlaid from cluster")
		}
		if got, _ := proc.EvaluateAttrString("TransferInput"); got != "input.txt" {
			t.Errorf("proc-level TransferInput got clobbered: %q", got)
		}
	})

	t.Run("ProcWinsOnConflict", func(t *testing.T) {
		// HTCondor semantics: per-proc attributes are overrides of
		// cluster defaults. An overlay that overwrote proc values
		// would silently corrupt jobs whose Cmd / Args were
		// deliberately customised per-proc.
		cluster := classad.New()
		_ = cluster.Set("ProcId", int64(-1))
		_ = cluster.Set("Cmd", "/bin/cluster-default")

		proc := classad.New()
		_ = proc.Set("ProcId", int64(2))
		_ = proc.Set("Cmd", "/bin/proc-override")

		overlayClusterOntoProc(cluster, proc)

		if got, _ := proc.EvaluateAttrString("Cmd"); got != "/bin/proc-override" {
			t.Errorf("proc Cmd was overwritten by cluster Cmd: got %q, want /bin/proc-override", got)
		}
	})

	t.Run("NilClusterIsNoOp", func(t *testing.T) {
		// Some submits land everything on the proc ad and there's no
		// distinct cluster ad to fetch. The overlay must tolerate
		// that without panicking — this is the small-batch path.
		proc := classad.New()
		_ = proc.Set("ClusterId", int64(1))
		_ = proc.Set("ProcId", int64(0))
		_ = proc.Set("Cmd", "run.sh")

		overlayClusterOntoProc(nil, proc)

		if got, _ := proc.EvaluateAttrString("Cmd"); got != "run.sh" {
			t.Errorf("nil-cluster overlay disturbed proc Cmd: got %q", got)
		}
	})

	t.Run("NilProcIsNoOp", func(t *testing.T) {
		// Defensive: fetchProcAdForSpool returns (nil, nil) when no
		// proc ad matched, in which case its caller surfaces a 404
		// instead of calling overlay — but be explicit that overlay
		// itself doesn't dereference.
		cluster := classad.New()
		_ = cluster.Set("Cmd", "run.sh")

		overlayClusterOntoProc(cluster, nil) // must not panic
	})
}

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
			req := httptest.NewRequestWithContext(context.Background(), method, "/api/v1/jobs/123.0/input/multipart", nil)
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

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs/123.0/input/multipart", body)
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
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, tc.path, nil)
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
