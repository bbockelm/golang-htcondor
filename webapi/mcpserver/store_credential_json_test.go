package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// recordingCredd captures whether a store actually reached the credd.
type recordingCredd struct {
	htcondor.CreddClient
	stored [][]byte
}

func (c *recordingCredd) PutServiceCred(_ context.Context, _ htcondor.CredType, credential []byte,
	_ string, _ string, _ string, _ *bool) error {
	c.stored = append(c.stored, credential)
	return nil
}

// A non-JSON OAuth credential must be refused at the door.
//
// The credd accepts it -- it only parses the bytes when the request
// carries scopes or an audience -- and then fails every query that names
// the service, while a list, which names none, keeps reporting the
// credential as present. Storing it is what creates two read paths that
// disagree, so this is the place to stop it.
func TestStoreServiceCredentialRejectsNonJSON(t *testing.T) {
	rec := &recordingCredd{}
	s := scopeTestServer(t, true)
	s.credd = rec

	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
	_, err := s.toolStoreServiceCredential(ctx, map[string]interface{}{
		"service":    "scitokens",
		"credential": "placeholder",
	})
	if err == nil {
		t.Fatal("a placeholder string was accepted; it will break every later read")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
	if !strings.Contains(err.Error(), "access_token") {
		t.Errorf("the error does not show what a valid credential looks like: %v", err)
	}
	if len(rec.stored) != 0 {
		t.Errorf("the credential reached the credd anyway: %q", rec.stored)
	}
}

// A real credential still stores.
func TestStoreServiceCredentialAcceptsJSON(t *testing.T) {
	rec := &recordingCredd{}
	s := scopeTestServer(t, true)
	s.credd = rec

	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
	if _, err := s.toolStoreServiceCredential(ctx, map[string]interface{}{
		"service":    "scitokens",
		"credential": `{"access_token":"abc","expires_in":3600}`,
	}); err != nil {
		t.Fatalf("a JSON credential was refused: %v", err)
	}
	if len(rec.stored) != 1 {
		t.Fatalf("stored %d credentials, want 1", len(rec.stored))
	}
	if !strings.Contains(string(rec.stored[0]), "access_token") {
		t.Errorf("the stored bytes are not what was passed: %q", rec.stored[0])
	}
}

// base64 is accepted on the way in, so the check must run on the DECODED
// bytes -- otherwise a valid credential sent base64-encoded would be
// refused for not looking like JSON.
func TestStoreServiceCredentialChecksDecodedBytes(t *testing.T) {
	rec := &recordingCredd{}
	s := scopeTestServer(t, true)
	s.credd = rec

	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
	// base64 of {"access_token":"abc"}
	if _, err := s.toolStoreServiceCredential(ctx, map[string]interface{}{ //nolint:gosec // G101: test data
		"service":    "scitokens",
		"credential": "eyJhY2Nlc3NfdG9rZW4iOiJhYmMifQ==",
	}); err != nil {
		t.Fatalf("a base64-encoded JSON credential was refused: %v", err)
	}
	if len(rec.stored) != 1 || !strings.Contains(string(rec.stored[0]), "access_token") {
		t.Errorf("stored %q, want the decoded JSON", rec.stored)
	}
}

// An empty credential is a request for a credmon-minted token, not a
// malformed credential -- the credmon watches for the stored file and never
// reads what is in it. checkOAuthServicesNeeded tells callers to store exactly
// that for services a job transform added, and this tool used to refuse it, so
// the advice the server gave could not be followed through the server.
func TestStoreServiceCredentialAcceptsEmpty(t *testing.T) {
	rec := &recordingCredd{}
	s := scopeTestServer(t, true)
	s.credd = rec

	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
	if _, err := s.toolStoreServiceCredential(ctx, map[string]interface{}{
		"service":    "scitokens",
		"credential": "",
	}); err != nil {
		t.Fatalf("an empty credential was refused: %v", err)
	}
	if len(rec.stored) != 1 {
		t.Fatalf("stored %d credentials, want 1", len(rec.stored))
	}
	if len(rec.stored[0]) != 0 {
		t.Errorf("stored %q, want nothing", rec.stored[0])
	}
}

// Omitting the argument altogether is still an error. Empty means "mint me
// one"; absent means the caller forgot, and silently treating it as a mint
// request would store a credential nobody asked for.
func TestStoreServiceCredentialRequiresTheArgument(t *testing.T) {
	rec := &recordingCredd{}
	s := scopeTestServer(t, true)
	s.credd = rec

	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
	if _, err := s.toolStoreServiceCredential(ctx, map[string]interface{}{
		"service": "scitokens",
	}); err == nil {
		t.Fatal("a missing credential argument was accepted")
	}
	if len(rec.stored) != 0 {
		t.Errorf("something reached the credd anyway: %q", rec.stored)
	}
}

// The tool's own description is the last thing a caller reads before storing.
// It used to say the credential could be plain text, which is the trap: plain
// text stores and then fails every read. Guidance that contradicts the rule is
// worse than no guidance, because it is guidance people follow.
func TestStoreServiceCredentialDescriptionMatchesTheRule(t *testing.T) {
	s := newTestServerWithCredd(t)

	blob, err := json.Marshal(s.handleListTools(context.Background(), nil))
	if err != nil {
		t.Fatalf("failed to marshal the tool list: %v", err)
	}
	var listing struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(blob, &listing); err != nil {
		t.Fatalf("failed to decode the tool list: %v", err)
	}
	var desc string
	for _, tool := range listing.Tools {
		if tool.Name != "store_service_credential" {
			continue
		}
		one, err := json.Marshal(tool)
		if err != nil {
			t.Fatalf("failed to marshal the tool definition: %v", err)
		}
		desc = string(one)
	}
	if desc == "" {
		t.Fatal("store_service_credential is not in the tool list")
	}
	if strings.Contains(desc, "plain text") {
		t.Errorf("the description still offers plain text, which the tool refuses: %s", desc)
	}
	if !strings.Contains(desc, "JSON") {
		t.Errorf("the description never mentions the JSON requirement: %s", desc)
	}
	if !strings.Contains(desc, "empty") {
		t.Errorf("the description does not mention the empty-credential case: %s", desc)
	}
}
