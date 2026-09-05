package mcpserver

import (
	"context"
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
	if _, err := s.toolStoreServiceCredential(ctx, map[string]interface{}{
		"service":    "scitokens",
		"credential": "eyJhY2Nlc3NfdG9rZW4iOiJhYmMifQ==",
	}); err != nil {
		t.Fatalf("a base64-encoded JSON credential was refused: %v", err)
	}
	if len(rec.stored) != 1 || !strings.Contains(string(rec.stored[0]), "access_token") {
		t.Errorf("stored %q, want the decoded JSON", rec.stored)
	}
}
