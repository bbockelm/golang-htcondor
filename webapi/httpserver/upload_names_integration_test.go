//go:build integration

package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

// Both raw-tar upload routes -- the job's own and a share URL -- refuse a
// tar holding a name that is not a canonical path inside the sandbox,
// directory or file, with 400 and without releasing the job; a clean tar
// to the same job then succeeds.
func TestRawTarUploadRefusesNonCanonicalNamesIntegration(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}
	_, _, baseURL, cleanup := setupIntegrationTest(t)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}
	const user = "testuser"
	_, jobID := submitJob(t, client, baseURL, user,
		"executable = /bin/true\ntransfer_executable = false\ntransfer_input_files = bar\nqueue\n")

	put := func(url string, entries []tar.Header, asUser bool) (int, string) {
		t.Helper()
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for i := range entries {
			h := entries[i]
			if h.Typeflag == tar.TypeReg {
				h.Size = 1
			}
			if err := tw.WriteHeader(&h); err != nil {
				t.Fatalf("tar header: %v", err)
			}
			if h.Typeflag == tar.TypeReg {
				_, _ = tw.Write([]byte("x"))
			}
		}
		_ = tw.Close()
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, url, &buf)
		req.Header.Set("Content-Type", "application/x-tar")
		if asUser {
			req.Header.Set("X-Test-User", user)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("PUT %s: %v", url, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// Mint a share URL for the same job.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+"/api/v1/jobs/"+jobID+"/input/share", nil)
	req.Header.Set("X-Test-User", user)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("mint share URL: %v", err)
	}
	var minted ShareInputResponse
	_ = json.NewDecoder(resp.Body).Decode(&minted)
	resp.Body.Close()
	if len(minted.Uploads) != 1 {
		t.Fatalf("mint share URL: status %d, %+v", resp.StatusCode, minted)
	}

	bad := map[string][]tar.Header{
		"traversal dir":      {{Name: "../x/", Typeflag: tar.TypeDir, Mode: 0o755}, {Name: "bar", Typeflag: tar.TypeReg, Mode: 0o644}},
		"non-canonical file": {{Name: "foo/../bar", Typeflag: tar.TypeReg, Mode: 0o644}},
	}
	for label, entries := range bad {
		if code, body := put(baseURL+"/api/v1/jobs/"+jobID+"/input", entries, true); code != http.StatusBadRequest {
			t.Errorf("%s via /jobs/{id}/input: %d, want 400: %s", label, code, body)
		}
		if code, body := put(minted.Uploads[0].URL, entries, false); code != http.StatusBadRequest {
			t.Errorf("%s via share URL: %d, want 400: %s", label, code, body)
		}
	}

	// Still awaiting input, so the share URL still redeems -- with a
	// clean tar.
	clean := []tar.Header{{Name: "bar", Typeflag: tar.TypeReg, Mode: 0o644}}
	if code, body := put(minted.Uploads[0].URL, clean, false); code != http.StatusOK {
		t.Errorf("a clean tar after the refusals: %d, want 200: %s", code, body)
	}
}
