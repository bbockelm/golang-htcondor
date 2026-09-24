package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
)

// A deployment without a signing key, or without knowing the REST
// daemon's address, cannot produce a usable URL. It has to say which,
// because the two have different fixes.
//
// Covers both share-URL tools together: they have the same two
// preconditions for the same reason, and pinning them in one place is
// what keeps the two messages from drifting apart.
func TestShareURLToolsNameWhatIsMissing(t *testing.T) {
	tools := map[string]func(*Server) func(context.Context, map[string]interface{}) (interface{}, error){
		"create_input_upload_url": func(s *Server) func(context.Context, map[string]interface{}) (interface{}, error) {
			return s.toolCreateInputUploadURL
		},
		"create_output_download_url": func(s *Server) func(context.Context, map[string]interface{}) (interface{}, error) {
			return s.toolCreateOutputDownloadURL
		},
	}
	cases := []struct {
		name     string
		sabotage func(*Server)
		wantSub  string
	}{
		{"no signing key", func(s *Server) { s.shareSigner = nil }, "signing key"},
		{"no base URL", func(s *Server) { s.httpBaseURL = "" }, "HTTP_API_BASE_URL"},
		{"blank base URL", func(s *Server) { s.httpBaseURL = "   " }, "HTTP_API_BASE_URL"},
	}

	for toolName, get := range tools {
		for _, tc := range cases {
			t.Run(toolName+"/"+tc.name, func(t *testing.T) {
				s := uploadURLServer(t)
				tc.sabotage(s)
				_, err := get(s)(context.Background(), map[string]interface{}{"job_id": "42.0"})
				if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("error = %v; want one naming %q", err, tc.wantSub)
				}
			})
		}
	}
}

func TestCreateOutputDownloadURLValidatesTheJobID(t *testing.T) {
	s := uploadURLServer(t)
	for _, jobID := range []string{"", "   ", "abc", "-1.0"} {
		t.Run(jobID, func(t *testing.T) {
			_, err := s.toolCreateOutputDownloadURL(context.Background(),
				map[string]interface{}{"job_id": jobID})
			if err == nil {
				t.Fatalf("job_id %q was accepted", jobID)
			}
		})
	}
	// A missing argument is its own message, not a parse failure.
	_, err := s.toolCreateOutputDownloadURL(context.Background(), map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "job_id is required") {
		t.Fatalf("missing job_id, error = %v; want one saying it is required", err)
	}
}

// The token this tool mints must be an OUTPUT token, and the URL must
// point at the endpoint that redeems that kind. Get either wrong and
// nothing fails until somebody fetches the URL, where it surfaces as
// "invalid or expired token" -- nowhere near the mistake.
func TestMintOutputURLSignsAnOutputTokenForTheOutputEndpoint(t *testing.T) {
	s := uploadURLServer(t)
	exp := time.Now().Add(10 * time.Minute)

	u, err := mintOutputURL(s.shareSigner, "https://ap.example.org", 42, 3, "alice", exp)
	if err != nil {
		t.Fatalf("mintOutputURL: %v", err)
	}
	if !strings.HasPrefix(u, "https://ap.example.org/api/v1/share/output?t=") {
		t.Fatalf("URL = %q, want the share/output endpoint", u)
	}

	tok := strings.TrimPrefix(u, "https://ap.example.org/api/v1/share/output?t=")
	payload, err := s.shareSigner.Verify(tok, shareurl.KindOutput)
	if err != nil {
		t.Fatalf("the minted token does not verify as an output token: %v", err)
	}
	if payload.Cluster != 42 || payload.Proc != 3 {
		t.Errorf("token names job %d.%d, want 42.3", payload.Cluster, payload.Proc)
	}
	if payload.Owner != "alice" {
		t.Errorf("token owner = %q, want alice", payload.Owner)
	}

	// And it must NOT be usable to upload into the same job. An output
	// capability that also authorizes writes would be a privilege
	// escalation handed out to whoever holds the link.
	if _, err := s.shareSigner.Verify(tok, shareurl.KindInput); err == nil {
		t.Error("the download token was also accepted as an input upload token")
	}
}

// The catalogue entry has to exist, and has to say which tool this
// replaces -- an agent reaches for it at the moment get_job_output has
// just failed, and that is the only cue it gets.
func TestCreateOutputDownloadURLIsAdvertised(t *testing.T) {
	s := uploadURLServer(t)
	found := false
	for _, tool := range s.toolsFor(context.Background()) {
		if tool.Name != "create_output_download_url" {
			continue
		}
		found = true
		if !strings.Contains(tool.Description, "get_job_output") {
			t.Error("the description does not name the tool this replaces")
		}
		props, _ := tool.InputSchema["properties"].(map[string]interface{})
		if _, ok := props["job_id"]; !ok {
			t.Error("no job_id property")
		}
	}
	if !found {
		t.Fatal("create_output_download_url is not in the tool catalogue")
	}
}

// Minting a capability is not a read-only act, whatever it does to the
// job. A client that trusts readOnlyHint would otherwise hand these out
// without the confirmation a write gets.
func TestCreateOutputDownloadURLIsNotReadOnly(t *testing.T) {
	if IsReadOnlyTool("create_output_download_url") {
		t.Fatal("create_output_download_url is classified read-only; it mints a bearer capability")
	}
	ann, ok := toolAnnotations["create_output_download_url"]
	if !ok {
		t.Fatal("create_output_download_url has no annotation")
	}
	if ann.ReadOnlyHint {
		t.Fatal("create_output_download_url is annotated read-only")
	}
}

// A bare cluster id is not a mistake: a sandbox is per proc, so a
// `queue N` submission has N of them. The id must get past validation
// and reach the schedd lookup.
func TestCreateOutputDownloadURLAcceptsABareClusterID(t *testing.T) {
	s := uploadURLServer(t)
	_, err := s.toolCreateOutputDownloadURL(context.Background(),
		map[string]interface{}{"job_id": "42"})
	if err == nil {
		t.Fatal("expected the unreachable schedd to fail the lookup")
	}
	if strings.Contains(err.Error(), "invalid job_id") {
		t.Errorf("a bare cluster id was rejected as malformed: %v", err)
	}
}
