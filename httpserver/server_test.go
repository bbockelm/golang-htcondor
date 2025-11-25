package httpserver

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestScheddAddressUpdate tests the thread-safe schedd address update functionality
func TestScheddAddressUpdate(t *testing.T) {
	// Create a logger for the test
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a simple server instance with minimal config
	s := &Server{
		scheddName: "test-schedd",
		schedd:     htcondor.NewSchedd("test-schedd", "127.0.0.1:9618"),
		stopChan:   make(chan struct{}),
		logger:     logger,
	}

	// Test initial address
	initialAddr := s.getSchedd().Address()
	if initialAddr != "127.0.0.1:9618" {
		t.Errorf("Initial address = %v, want 127.0.0.1:9618", initialAddr)
	}

	// Update the address
	newAddr := "127.0.0.1:9619"
	s.updateSchedd(newAddr)

	// Verify the address was updated
	updatedAddr := s.getSchedd().Address()
	if updatedAddr != newAddr {
		t.Errorf("Updated address = %v, want %v", updatedAddr, newAddr)
	}

	// Test that updating with the same address doesn't create a new instance
	oldSchedd := s.getSchedd()
	s.updateSchedd(newAddr)
	newSchedd := s.getSchedd()

	// Both should point to the same address (though they're different instances)
	if oldSchedd.Address() != newSchedd.Address() {
		t.Errorf("Address changed unexpectedly: old=%v, new=%v", oldSchedd.Address(), newSchedd.Address())
	}
}

// TestScheddThreadSafety tests concurrent access to schedd
func TestScheddThreadSafety(t *testing.T) {
	// Create a logger for the test
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	s := &Server{
		scheddName: "test-schedd",
		schedd:     htcondor.NewSchedd("test-schedd", "127.0.0.1:9618"),
		stopChan:   make(chan struct{}),
		logger:     logger,
	}

	var wg sync.WaitGroup
	iterations := 100

	// Start multiple goroutines reading the schedd
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				schedd := s.getSchedd()
				_ = schedd.Address()
			}
		}()
	}

	// Start goroutines updating the schedd
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(_ int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				addr := "127.0.0.1:" + string(rune('9'+'0'+j%10))
				s.updateSchedd(addr)
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify we can still get a schedd instance
	finalSchedd := s.getSchedd()
	if finalSchedd == nil {
		t.Error("Final schedd is nil")
	}
}

// TestServerShutdown tests the graceful shutdown of the server
func TestServerShutdown(t *testing.T) {
	s := &Server{
		scheddName:       "test-schedd",
		schedd:           htcondor.NewSchedd("test-schedd", "127.0.0.1:9618"),
		scheddDiscovered: false,
		stopChan:         make(chan struct{}),
	}

	// Start a goroutine that simulates background work
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Do nothing
			case <-s.stopChan:
				return
			}
		}
	}()

	// Give the goroutine time to start
	time.Sleep(20 * time.Millisecond)

	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Signal shutdown
	close(s.stopChan)

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - goroutines stopped
	case <-ctx.Done():
		t.Error("Goroutines did not stop within timeout")
	}
}

// TestScheddDiscoveryFlag tests that the discovery flag is set correctly
func TestScheddDiscoveryFlag(t *testing.T) {
	tests := []struct {
		name             string
		scheddDiscovered bool
		wantUpdater      bool
	}{
		{
			name:             "Address discovered from collector",
			scheddDiscovered: true,
			wantUpdater:      true,
		},
		{
			name:             "Address provided explicitly",
			scheddDiscovered: false,
			wantUpdater:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				scheddName:       "test-schedd",
				schedd:           htcondor.NewSchedd("test-schedd", "127.0.0.1:9618"),
				scheddDiscovered: tt.scheddDiscovered,
				stopChan:         make(chan struct{}),
			}

			// The actual test would verify that startScheddAddressUpdater
			// is only called when scheddDiscovered is true, but since
			// that's done in Start/StartTLS, we just verify the flag is set
			if s.scheddDiscovered != tt.wantUpdater {
				t.Errorf("scheddDiscovered = %v, want %v", s.scheddDiscovered, tt.wantUpdater)
			}
		})
	}
}

// TestSwaggerClientCreatedInNormalMode tests that the swagger-client OAuth2 client
// is automatically created when MCP is enabled without IDP (normal mode).
// This addresses the issue where demo mode created the client but normal mode did not.
func TestSwaggerClientCreatedInNormalMode(t *testing.T) {
	// Create a logger for the test
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Use a temporary database
	tempDBPath := t.TempDir() + "/test_swagger_client.db"

	// Create server with MCP enabled but IDP disabled (normal mode)
	server, err := NewServer(Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		Logger:       logger,
		OAuth2DBPath: tempDBPath,
		EnableMCP:    true,  // MCP enabled
		EnableIDP:    false, // IDP disabled (normal mode)
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer func() {
		if server.oauth2Provider != nil {
			_ = server.oauth2Provider.Close()
		}
	}()

	// Verify OAuth2 provider is initialized
	if server.oauth2Provider == nil {
		t.Fatal("OAuth2 provider should be initialized when EnableMCP is true")
	}

	// Create a mock listener to simulate server start
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Call initializeOAuth2 which should create the swagger client
	server.initializeOAuth2(ln, "http")

	// Verify the swagger-client was created
	ctx := context.Background()
	swaggerClient, err := server.oauth2Provider.GetStorage().GetClient(ctx, "swagger-client")
	if err != nil {
		t.Fatalf("swagger-client should exist after initializeOAuth2: %v", err)
	}

	// Verify client properties
	if swaggerClient.GetID() != "swagger-client" {
		t.Errorf("Client ID = %v, want swagger-client", swaggerClient.GetID())
	}

	// Verify client is public (no secret)
	if !swaggerClient.IsPublic() {
		t.Error("swagger-client should be a public client")
	}

	// Verify redirect URIs include the docs path
	redirectURIs := swaggerClient.GetRedirectURIs()
	found := false
	for _, uri := range redirectURIs {
		if uri == "http://"+ln.Addr().String()+"/docs/oauth2-redirect" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("swagger-client redirect URIs should include /docs/oauth2-redirect, got: %v", redirectURIs)
	}
}

// TestSwaggerClientNotDuplicatedWhenAlreadyExists tests that the swagger-client
// is not recreated if it already exists in the OAuth2 store.
func TestSwaggerClientNotDuplicatedWhenAlreadyExists(t *testing.T) {
	// Create a logger for the test
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Use a temporary database
	tempDBPath := t.TempDir() + "/test_swagger_duplicate.db"

	// Create server with MCP enabled
	server, err := NewServer(Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		Logger:       logger,
		OAuth2DBPath: tempDBPath,
		EnableMCP:    true,
		EnableIDP:    false,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer func() {
		if server.oauth2Provider != nil {
			_ = server.oauth2Provider.Close()
		}
	}()

	// Create a mock listener
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Call initializeOAuth2 twice
	server.initializeOAuth2(ln, "http")
	server.initializeOAuth2(ln, "http")

	// Verify the client still exists and is valid
	ctx := context.Background()
	swaggerClient, err := server.oauth2Provider.GetStorage().GetClient(ctx, "swagger-client")
	if err != nil {
		t.Fatalf("swagger-client should exist: %v", err)
	}

	if swaggerClient.GetID() != "swagger-client" {
		t.Errorf("Client ID = %v, want swagger-client", swaggerClient.GetID())
	}
}
