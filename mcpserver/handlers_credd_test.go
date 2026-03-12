package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

func newTestServerWithCredd(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return &Server{
		schedd:          htcondor.NewSchedd("test_schedd", "localhost:9618"),
		credd:           htcondor.NewInMemoryCredd(),
		logger:          logger,
		validatedTokens: make(map[string]TokenInfo),
	}
}

func TestToolListServiceCredentials_Empty(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	result, err := s.toolListServiceCredentials(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := json.Marshal(result)
	if got := string(data); got == "" {
		t.Fatal("expected non-empty result")
	}

	// Should say no credentials found
	resultMap := result.(map[string]interface{})
	content := resultMap["content"].([]map[string]interface{})
	text := content[0]["text"].(string)
	if text != "No OAuth service credentials found." {
		t.Errorf("expected 'No OAuth service credentials found.', got: %s", text)
	}
}

func TestToolListServiceCredentials_WithCreds(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	// Store a credential first
	if err := s.credd.PutServiceCred(ctx, htcondor.CredTypeOAuth, []byte("token123"), "scitokens", "", "", nil); err != nil {
		t.Fatalf("failed to store cred: %v", err)
	}

	result, err := s.toolListServiceCredentials(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap := result.(map[string]interface{})
	content := resultMap["content"].([]map[string]interface{})
	text := content[0]["text"].(string)
	if text == "No OAuth service credentials found." {
		t.Error("expected credentials to be listed")
	}
}

func TestToolGetCredentialStatus_NotFound(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	result, err := s.toolGetCredentialStatus(ctx, map[string]interface{}{
		"service": "nonexistent",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap := result.(map[string]interface{})
	content := resultMap["content"].([]map[string]interface{})
	text := content[0]["text"].(string)
	if text == "" {
		t.Error("expected non-empty status text")
	}
}

func TestToolGetCredentialStatus_Exists(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	if err := s.credd.PutServiceCred(ctx, htcondor.CredTypeOAuth, []byte("token"), "myservice", "", "", nil); err != nil {
		t.Fatalf("failed to store cred: %v", err)
	}

	result, err := s.toolGetCredentialStatus(ctx, map[string]interface{}{
		"service": "myservice",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap := result.(map[string]interface{})
	content := resultMap["content"].([]map[string]interface{})
	text := content[0]["text"].(string)
	if text == "" {
		t.Error("expected non-empty status text")
	}
}

func TestToolGetCredentialStatus_MissingService(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	_, err := s.toolGetCredentialStatus(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing service")
	}
}

func TestToolStoreServiceCredential(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	result, err := s.toolStoreServiceCredential(ctx, map[string]interface{}{
		"service":    "scitokens",
		"credential": "refresh_token_value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap := result.(map[string]interface{})
	content := resultMap["content"].([]map[string]interface{})
	text := content[0]["text"].(string)
	if text == "" {
		t.Error("expected non-empty result text")
	}

	// Verify credential was stored
	status, err := s.credd.GetServiceCredStatus(ctx, htcondor.CredTypeOAuth, "scitokens", "", "")
	if err != nil {
		t.Fatalf("failed to check status: %v", err)
	}
	if !status.Exists {
		t.Error("expected credential to exist after storing")
	}
}

func TestToolStoreServiceCredential_WithHandle(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	_, err := s.toolStoreServiceCredential(ctx, map[string]interface{}{
		"service":    "scitokens",
		"handle":     "myhandle",
		"credential": "refresh_token_value",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status, err := s.credd.GetServiceCredStatus(ctx, htcondor.CredTypeOAuth, "scitokens", "myhandle", "")
	if err != nil {
		t.Fatalf("failed to check status: %v", err)
	}
	if !status.Exists {
		t.Error("expected credential to exist after storing")
	}
}

func TestToolStoreServiceCredential_MissingArgs(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	_, err := s.toolStoreServiceCredential(ctx, map[string]interface{}{
		"service": "scitokens",
	})
	if err == nil {
		t.Fatal("expected error for missing credential")
	}

	_, err = s.toolStoreServiceCredential(ctx, map[string]interface{}{
		"credential": "token",
	})
	if err == nil {
		t.Fatal("expected error for missing service")
	}
}

func TestToolDeleteServiceCredential(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	// Store first
	if err := s.credd.PutServiceCred(ctx, htcondor.CredTypeOAuth, []byte("token"), "scitokens", "", "", nil); err != nil {
		t.Fatalf("failed to store cred: %v", err)
	}

	result, err := s.toolDeleteServiceCredential(ctx, map[string]interface{}{
		"service": "scitokens",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap := result.(map[string]interface{})
	content := resultMap["content"].([]map[string]interface{})
	text := content[0]["text"].(string)
	if text == "" {
		t.Error("expected non-empty result text")
	}

	// Verify deleted
	status, err := s.credd.GetServiceCredStatus(ctx, htcondor.CredTypeOAuth, "scitokens", "", "")
	if err != nil && !errors.Is(err, htcondor.ErrCredentialNotFound) {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Exists {
		t.Error("expected credential to not exist after deletion")
	}
}

func TestToolDeleteServiceCredential_NotFound(t *testing.T) {
	s := newTestServerWithCredd(t)
	ctx := context.Background()

	_, err := s.toolDeleteServiceCredential(ctx, map[string]interface{}{
		"service": "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for non-existent credential")
	}
}

func TestCredentialToolsNilCredd(t *testing.T) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	s := &Server{
		schedd:          htcondor.NewSchedd("test_schedd", "localhost:9618"),
		credd:           nil,
		logger:          logger,
		validatedTokens: make(map[string]TokenInfo),
	}
	ctx := context.Background()

	_, err := s.toolListServiceCredentials(ctx, nil)
	if err == nil {
		t.Error("expected error when credd is nil")
	}

	_, err = s.toolGetCredentialStatus(ctx, map[string]interface{}{"service": "x"})
	if err == nil {
		t.Error("expected error when credd is nil")
	}

	_, err = s.toolStoreServiceCredential(ctx, map[string]interface{}{"service": "x", "credential": "y"})
	if err == nil {
		t.Error("expected error when credd is nil")
	}

	_, err = s.toolDeleteServiceCredential(ctx, map[string]interface{}{"service": "x"})
	if err == nil {
		t.Error("expected error when credd is nil")
	}
}

func TestHandleListTools_IncludesCredentialTools(t *testing.T) {
	s := newTestServerWithCredd(t)
	result := s.handleListTools(context.Background(), nil)

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	str := string(data)

	expectedTools := []string{
		"list_service_credentials",
		"get_credential_status",
		"store_service_credential",
		"delete_service_credential",
	}
	for _, tool := range expectedTools {
		if !strings.Contains(str, tool) {
			t.Errorf("expected tools list to contain '%s'", tool)
		}
	}
}

func TestHandleListTools_ExcludesCredentialToolsWithoutCredd(t *testing.T) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	s := &Server{
		schedd:          htcondor.NewSchedd("test_schedd", "localhost:9618"),
		credd:           nil,
		logger:          logger,
		validatedTokens: make(map[string]TokenInfo),
	}
	result := s.handleListTools(context.Background(), nil)

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	str := string(data)

	credTools := []string{
		"list_service_credentials",
		"get_credential_status",
		"store_service_credential",
		"delete_service_credential",
	}
	for _, tool := range credTools {
		if strings.Contains(str, tool) {
			t.Errorf("credential tool '%s' should not appear when credd is nil", tool)
		}
	}
}
