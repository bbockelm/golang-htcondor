package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
)

// The single-job action tools are owner-scoped at the mutate tier, like
// remove_jobs. These call them through HandleMessage against a fake
// CEDAR schedd holding alice's job 1.0 and bob's job 2.0; the fake
// applies no owner filter, so a job it acts on is one the constraint this
// server sent admitted.

type actionScopeFixture struct {
	server  *Server
	schedd  *fakeschedd.Schedd
	keyFile string
}

func newActionScopeFixture(t *testing.T) *actionScopeFixture {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	fs := fakeschedd.Start(t, keyFile, "test.domain")
	fs.AddJobs(fakeschedd.JobAd(1, 0, "alice", 2), fakeschedd.JobAd(2, 0, "bob", 2))
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	return &actionScopeFixture{
		server: &Server{
			schedd:    htcondor.NewSchedd("fake", fs.Addr()),
			logger:    logger,
			delegated: true,
		},
		schedd:  fs,
		keyFile: keyFile,
	}
}

// as returns a context for user@test.domain over an HTTP grant of scopes,
// presenting an IDTOKEN for that user to the schedd.
func (f *actionScopeFixture) as(t *testing.T, user string, scopes ...string) context.Context {
	t.Helper()
	identity := user + "@test.domain"
	now := time.Now().Unix()
	tok, err := security.GenerateJWT(filepath.Dir(f.keyFile), filepath.Base(f.keyFile), identity, "test.domain", now, now+3600, nil)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	ctx := htcondor.WithSecurityConfig(context.Background(), &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Token:          tok,
		SessionCache:   security.NewSessionCache(),
	})
	ctx = htcondor.WithAuthenticatedUser(ctx, identity)
	return WithGrantedScopes(ctx, scopes)
}

// call runs one tools/call and returns the text and whether it failed.
func (f *actionScopeFixture) call(ctx context.Context, t *testing.T, name string, args map[string]interface{}) (string, bool) {
	t.Helper()
	params, err := json.Marshal(map[string]interface{}{"name": name, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp := f.server.HandleMessage(ctx, &MCPMessage{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params})
	if resp.Error != nil {
		t.Fatalf("%s: protocol error %v", name, resp.Error)
	}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	var text strings.Builder
	for _, c := range parsed.Content {
		text.WriteString(c.Text)
	}
	return text.String(), parsed.IsError
}

// A caller without mcp:superuser cannot hold, release or remove another
// user's job: the schedd is asked with a constraint that matches nothing,
// and the answer is "not found". Its own job still works.
func TestSingleJobActionsAreOwnerScoped(t *testing.T) {
	for _, tool := range []string{"hold_job", "release_job", "remove_job"} {
		t.Run(tool, func(t *testing.T) {
			f := newActionScopeFixture(t)
			bob := f.as(t, "bob", "mcp:read", "mcp:write", "mcp:admin")

			text, isErr := f.call(bob, t, tool, map[string]interface{}{"job_id": "1.0"})
			if !isErr || !strings.Contains(text, "not found") {
				t.Errorf("%s on alice's job as bob: isError=%v %q, want not found", tool, isErr, text)
			}
			if acted := f.schedd.ActedOn(); len(acted) != 0 {
				t.Fatalf("%s as bob acted on %v; alice's job must be untouched", tool, acted)
			}

			if text, isErr := f.call(bob, t, tool, map[string]interface{}{"job_id": "2.0"}); isErr {
				t.Errorf("%s on bob's own job failed: %s", tool, text)
			}
			if acted := f.schedd.ActedOn(); !slices.Equal(acted, []string{"2.0"}) {
				t.Errorf("%s as bob acted on %v, want [2.0]", tool, acted)
			}
		})
	}
}

// mcp:superuser is the grant for acting on other users' jobs, and still
// works.
func TestSuperuserGrantActsOnAnyJob(t *testing.T) {
	f := newActionScopeFixture(t)
	carol := f.as(t, "carol", "mcp:read", "mcp:write", "mcp:superuser")

	if text, isErr := f.call(carol, t, "hold_job", map[string]interface{}{"job_id": "1.0"}); isErr {
		t.Fatalf("hold_job with mcp:superuser on alice's job failed: %s", text)
	}
	if acted := f.schedd.ActedOn(); !slices.Equal(acted, []string{"1.0"}) {
		t.Errorf("hold_job with mcp:superuser acted on %v, want [1.0]", acted)
	}
}

// edit_job is scoped the same way. The fake has no QMGMT, so only the
// refusal is observable: another user's job is not found before any edit
// is attempted.
func TestEditJobIsOwnerScoped(t *testing.T) {
	f := newActionScopeFixture(t)
	bob := f.as(t, "bob", "mcp:read", "mcp:write")

	text, isErr := f.call(bob, t, "edit_job", map[string]interface{}{
		"job_id": "1.0", "attributes": map[string]interface{}{"Foo": 1},
	})
	if !isErr || !strings.Contains(text, "not found") {
		t.Errorf("edit_job on alice's job as bob: isError=%v %q, want not found", isErr, text)
	}
	// His own job gets past the scope and fails later, at the QMGMT
	// connection the fake does not serve.
	text, _ = f.call(bob, t, "edit_job", map[string]interface{}{
		"job_id": "2.0", "attributes": map[string]interface{}{"Foo": 1},
	})
	if strings.Contains(text, "not found") {
		t.Errorf("edit_job on bob's own job was not found: %q", text)
	}
}

// An actor that names no owner cannot be confined, so it is refused
// rather than run unscoped.
func TestQueryJobsRefusesAnActorWithNoOwner(t *testing.T) {
	for _, delegated := range []bool{true, false} {
		s := scopeTestServer(t, delegated)
		ctx := htcondor.WithAuthenticatedUser(context.Background(), "@test.domain")
		_, err := s.toolQueryJobs(ctx, map[string]interface{}{"constraint": "true"})
		if err == nil || !strings.Contains(err.Error(), "uthentication required") {
			t.Errorf("delegated=%v: query_jobs for actor \"@test.domain\" = %v, want an authentication refusal", delegated, err)
		}
	}
}

// Over stdio the process is the user and no actor is on the context: the
// id clause goes to the schedd as it is, which checks ownership itself.
// Behind HTTP the same call with no actor is refused.
func TestSingleJobActionWithoutAnActor(t *testing.T) {
	var sent string
	record := func(_ context.Context, constraint, _ string) (*htcondor.JobActionResults, error) {
		sent = constraint
		return &htcondor.JobActionResults{Success: 1, TotalJobs: 1}, nil
	}
	args := map[string]interface{}{"job_id": "12.0"}

	if _, err := (&Server{}).performJobAction(context.Background(), args, record, "Held via MCP", "hold"); err != nil {
		t.Fatalf("stdio hold: %v", err)
	}
	if sent != "ClusterId == 12 && ProcId == 0" {
		t.Errorf("stdio hold sent %q, want the bare id clause", sent)
	}

	sent = ""
	_, err := (&Server{delegated: true}).performJobAction(context.Background(), args, record, "Held via MCP", "hold")
	if err == nil || !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("delegated hold with no actor = %v, want an authentication refusal", err)
	}
	if sent != "" {
		t.Errorf("delegated hold with no actor reached the schedd with %q", sent)
	}
}
