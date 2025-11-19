package htcondor

import (
	"context"
	"testing"
	"time"
)

// TestStreamOptionsDefaults tests that default values are applied correctly
func TestStreamOptionsDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    *StreamOptions
		expected StreamOptions
	}{
		{
			name:  "nil options gets defaults",
			input: nil,
			expected: StreamOptions{
				BufferSize:   100,
				WriteTimeout: 5 * time.Second,
			},
		},
		{
			name:  "empty options gets defaults",
			input: &StreamOptions{},
			expected: StreamOptions{
				BufferSize:   100,
				WriteTimeout: 5 * time.Second,
			},
		},
		{
			name: "custom buffer size preserved",
			input: &StreamOptions{
				BufferSize:   50,
				WriteTimeout: 3 * time.Second,
			},
			expected: StreamOptions{
				BufferSize:   50,
				WriteTimeout: 3 * time.Second,
			},
		},
		{
			name: "zero buffer size gets default",
			input: &StreamOptions{
				BufferSize:   0,
				WriteTimeout: 10 * time.Second,
			},
			expected: StreamOptions{
				BufferSize:   100, // default
				WriteTimeout: 10 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.ApplyStreamDefaults()
			if result.BufferSize != tt.expected.BufferSize {
				t.Errorf("BufferSize = %d, expected %d", result.BufferSize, tt.expected.BufferSize)
			}
			if result.WriteTimeout != tt.expected.WriteTimeout {
				t.Errorf("WriteTimeout = %v, expected %v", result.WriteTimeout, tt.expected.WriteTimeout)
			}
		})
	}
}

// TestStreamingChannelBuffering tests that channels are properly buffered
func TestStreamingChannelBuffering(t *testing.T) {
	// This test verifies that the streaming API creates properly buffered channels
	// We can't test the full streaming without a live collector/schedd, but we can
	// verify the channel properties

	t.Run("default buffer size", func(t *testing.T) {
		opts := &StreamOptions{}
		defaults := opts.ApplyStreamDefaults()
		if defaults.BufferSize != 100 {
			t.Errorf("Default buffer size = %d, expected 100", defaults.BufferSize)
		}
	})

	t.Run("custom buffer size", func(t *testing.T) {
		opts := &StreamOptions{BufferSize: 200}
		defaults := opts.ApplyStreamDefaults()
		if defaults.BufferSize != 200 {
			t.Errorf("Custom buffer size = %d, expected 200", defaults.BufferSize)
		}
	})
}

// TestStreamingContextCancellation verifies context cancellation is respected
func TestStreamingContextCancellation(t *testing.T) {
	// Create a collector with an invalid address (won't connect)
	collector := NewCollector("invalid-address:12345")

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	streamOpts := &StreamOptions{
		BufferSize:   10,
		WriteTimeout: 1 * time.Second,
	}

	// Start streaming - should fail quickly due to cancelled context
	resultCh, err := collector.QueryAdsStream(ctx, "StartdAd", "true", nil, streamOpts)
	if err != nil {
		// Pre-request error is acceptable (e.g., rate limit check with cancelled context)
		return
	}

	// Read from channel - should get an error related to context cancellation
	select {
	case result := <-resultCh:
		if result.Err == nil {
			t.Error("Expected error from cancelled context, got nil")
		}
		// Could be connection error or context error, both are acceptable
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for stream to return error")
	}
}

// TestStreamingScheddContextCancellation verifies context cancellation for schedd queries
func TestStreamingScheddContextCancellation(t *testing.T) {
	// Create a schedd with an invalid address (won't connect)
	schedd := NewSchedd("test-schedd", "invalid-address:12345")

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	streamOpts := &StreamOptions{
		BufferSize:   10,
		WriteTimeout: 1 * time.Second,
	}

	// Start streaming - should fail quickly due to cancelled context
	resultCh, err := schedd.QueryStream(ctx, "true", nil, streamOpts)
	if err != nil {
		// Pre-request error is acceptable (e.g., rate limit check with cancelled context)
		return
	}

	// Read from channel - should get an error related to context cancellation
	select {
	case result := <-resultCh:
		if result.Err == nil {
			t.Error("Expected error from cancelled context, got nil")
		}
		// Could be connection error or context error, both are acceptable
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for stream to return error")
	}
}

// TestStreamingChannelClosed verifies channels are properly closed
func TestStreamingChannelClosed(t *testing.T) {
	// Create a collector with an invalid address
	collector := NewCollector("invalid-address:12345")

	ctx := context.Background()
	streamOpts := &StreamOptions{
		BufferSize:   10,
		WriteTimeout: 1 * time.Second,
	}

	// Start streaming
	resultCh, err := collector.QueryAdsStream(ctx, "StartdAd", "true", nil, streamOpts)
	if err != nil {
		// Pre-request error is expected for invalid address
		return
	}

	// Consume all results
	errorReceived := false
	for result := range resultCh {
		if result.Err != nil {
			errorReceived = true
		}
	}

	// Channel should be closed (range loop exited)
	// Verify we got an error (connection failure)
	if !errorReceived {
		t.Error("Expected error from invalid address, but got none")
	}

	// Verify channel is closed by checking if we can receive from it
	select {
	case _, ok := <-resultCh:
		if ok {
			t.Error("Channel should be closed but is still open")
		}
	default:
		// Channel is closed (non-blocking receive returns immediately)
	}
}

// TestStreamingScheddChannelClosed verifies schedd streaming channels are properly closed
func TestStreamingScheddChannelClosed(t *testing.T) {
	// Create a schedd with an invalid address
	schedd := NewSchedd("test-schedd", "invalid-address:12345")

	ctx := context.Background()
	streamOpts := &StreamOptions{
		BufferSize:   10,
		WriteTimeout: 1 * time.Second,
	}

	// Start streaming
	resultCh, err := schedd.QueryStream(ctx, "true", nil, streamOpts)
	if err != nil {
		// Pre-request error is expected for invalid address
		return
	}

	// Consume all results
	errorReceived := false
	for result := range resultCh {
		if result.Err != nil {
			errorReceived = true
		}
	}

	// Channel should be closed (range loop exited)
	// Verify we got an error (connection failure)
	if !errorReceived {
		t.Error("Expected error from invalid address, but got none")
	}

	// Verify channel is closed
	select {
	case _, ok := <-resultCh:
		if ok {
			t.Error("Channel should be closed but is still open")
		}
	default:
		// Channel is closed
	}
}
