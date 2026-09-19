package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
)

func uploadURLServer(t *testing.T) *Server {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "POOL")
	if err := os.WriteFile(keyPath, []byte("test pool signing key"), 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	key, err := shareurl.KeyFromSigningKeyFile(keyPath)
	if err != nil {
		t.Fatalf("derive share key: %v", err)
	}
	signer, err := shareurl.NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return &Server{
		shareSigner:    signer,
		signingKeyPath: keyPath,
		httpBaseURL:    "https://ap.example.org",
		// Unreachable on purpose: every case here is decided before the
		// query lands, and a nil schedd would panic instead of failing.
		schedd: htcondor.NewSchedd("nowhere", "127.0.0.1:1"),
	}
}

// A deployment without a signing key, or without knowing the REST
// daemon's address, cannot produce a usable URL. It has to say which,
// because the two have different fixes.
func TestCreateInputUploadURLNamesWhatIsMissing(t *testing.T) {
	args := map[string]interface{}{"job_id": "42.0"}

	s := uploadURLServer(t)
	s.shareSigner = nil
	_, err := s.toolCreateInputUploadURL(context.Background(), args)
	if err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("without a signer, error = %v; want one naming the signing key", err)
	}

	s = uploadURLServer(t)
	s.httpBaseURL = ""
	_, err = s.toolCreateInputUploadURL(context.Background(), args)
	if err == nil || !strings.Contains(err.Error(), "HTTP_API_BASE_URL") {
		t.Fatalf("without a base URL, error = %v; want one naming HTTP_API_BASE_URL", err)
	}

	// A base URL that is only whitespace is the same situation as none.
	s = uploadURLServer(t)
	s.httpBaseURL = "   "
	_, err = s.toolCreateInputUploadURL(context.Background(), args)
	if err == nil || !strings.Contains(err.Error(), "HTTP_API_BASE_URL") {
		t.Fatalf("with a blank base URL, error = %v; want one naming HTTP_API_BASE_URL", err)
	}
}

func TestCreateInputUploadURLValidatesTheJobID(t *testing.T) {
	s := uploadURLServer(t)
	for _, tc := range []struct{ name, jobID string }{
		{"absent", ""},
		{"not a job id", "not-a-job"},
		{"negative proc", "42.-1"},
		{"zero cluster", "0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]interface{}{}
			if tc.jobID != "" {
				args["job_id"] = tc.jobID
			}
			_, err := s.toolCreateInputUploadURL(context.Background(), args)
			if err == nil {
				t.Fatalf("job_id %q was accepted", tc.jobID)
			}
			// Assert it failed on the job id and not on some unrelated
			// guard that happens to fire first.
			if !strings.Contains(err.Error(), "job_id") {
				t.Fatalf("job_id %q failed for an unrelated reason: %v", tc.jobID, err)
			}
		})
	}
}

func TestArgDuration(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  interface{}
		want time.Duration
	}{
		{"absent", nil, 0},
		{"json number", float64(900), 900 * time.Second},
		{"int", 900, 900 * time.Second},
		{"int64", int64(900), 900 * time.Second},
		{"stringified by a model", "900", 900 * time.Second},
		{"padded string", "  900 ", 900 * time.Second},
		{"nonsense", "soon", 0},
		{"wrong type", []string{"900"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]interface{}{}
			if tc.val != nil {
				args["ttl_seconds"] = tc.val
			}
			if got := argDuration(args, "ttl_seconds"); got != tc.want {
				t.Fatalf("argDuration = %v, want %v", got, tc.want)
			}
		})
	}
}

// The tool has to be offered, classified, and described, or it is either
// invisible to a model or misclassified by the scope gate. The tool-list
// and instructions coverage tests check the first and last; this pins
// the classification, which is the one with a security consequence.
func TestCreateInputUploadURLIsNotReadOnly(t *testing.T) {
	if IsReadOnlyTool("create_input_upload_url") {
		t.Fatal("create_input_upload_url is classified read-only; it mints a write capability")
	}
	ann, ok := toolAnnotations["create_input_upload_url"]
	if !ok {
		t.Fatal("create_input_upload_url has no annotation")
	}
	if ann.ReadOnlyHint {
		t.Fatal("create_input_upload_url is annotated read-only")
	}
}

// A bare cluster id is not a mistake: HTCondor spools per proc, so a
// `queue N` submission needs one URL per proc, and this tool mints them
// all. The id must get past validation and reach the schedd lookup.
func TestCreateInputUploadURLAcceptsABareClusterID(t *testing.T) {
	s := uploadURLServer(t)
	_, err := s.toolCreateInputUploadURL(context.Background(), map[string]interface{}{"job_id": "42"})
	if err == nil {
		t.Fatal("expected the unreachable schedd to fail the lookup")
	}
	// It must fail on the lookup, not on the id.
	if strings.Contains(err.Error(), "invalid job_id") {
		t.Fatalf("a bare cluster id was rejected as malformed: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to look up") {
		t.Fatalf("expected a lookup failure, got: %v", err)
	}
}
