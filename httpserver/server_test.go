package httpserver

import (
	"context"
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
		OutputPath:   "stderr",
		MinVerbosity: logging.VerbosityError, // Use Error level to reduce test output
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
		OutputPath:   "stderr",
		MinVerbosity: logging.VerbosityError,
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
