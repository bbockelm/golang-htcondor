package mcpserver

import (
	"context"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

func TestParseAdvertiseCommand(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldExist bool
	}{
		{
			name:        "UPDATE_STARTD_AD",
			input:       "UPDATE_STARTD_AD",
			shouldExist: true,
		},
		{
			name:        "lowercase",
			input:       "update_schedd_ad",
			shouldExist: true,
		},
		{
			name:        "Invalid command",
			input:       "INVALID_CMD",
			shouldExist: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := htcondor.ParseAdvertiseCommand(tt.input)
			if ok != tt.shouldExist {
				t.Errorf("Expected existence %v, got %v", tt.shouldExist, ok)
			}
		})
	}
}

func TestToolAdvertiseToCollector_NoCollector(t *testing.T) {
	server := &Server{
		collector: nil,
	}

	args := map[string]interface{}{
		"ad": map[string]interface{}{
			"MyType": "Generic",
			"Name":   "test",
		},
	}

	ctx := context.Background()
	_, err := server.toolAdvertiseToCollector(ctx, args)
	if err == nil {
		t.Error("Expected error when collector not configured")
	}
	if err.Error() != "collector not configured" {
		t.Errorf("Expected 'collector not configured' error, got: %v", err)
	}
}

func TestToolAdvertiseToCollector_InvalidAd(t *testing.T) {
	server := &Server{
		collector: htcondor.NewCollector("localhost:9618"),
	}

	tests := []struct {
		name string
		args map[string]interface{}
	}{
		{
			name: "Missing ad",
			args: map[string]interface{}{},
		},
		{
			name: "Ad not an object",
			args: map[string]interface{}{
				"ad": "not an object",
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := server.toolAdvertiseToCollector(ctx, tt.args)
			if err == nil {
				t.Error("Expected error for invalid ad")
			}
		})
	}
}

func TestToolAdvertiseToCollector_ValidAd(t *testing.T) {
	// This test verifies argument parsing but will fail to connect
	server := &Server{
		collector: htcondor.NewCollector("localhost:9618"),
	}

	args := map[string]interface{}{
		"ad": map[string]interface{}{
			"MyType": "Generic",
			"Name":   "test-ad",
		},
		"with_ack": false,
	}

	ctx := context.Background()
	_, err := server.toolAdvertiseToCollector(ctx, args)

	// Should fail to connect, but that's expected
	if err == nil {
		t.Error("Expected connection error")
	}
	// Verify it's a connection error, not a parsing error
	if err.Error() == "ad must be a JSON object" {
		t.Errorf("Ad parsing failed when it should have succeeded: %v", err)
	}
}

func TestHandleListTools_IncludesAdvertise(t *testing.T) {
	server := &Server{}

	result := server.handleListTools(context.Background(), nil)

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("Result is not a map")
	}

	tools, ok := resultMap["tools"].([]Tool)
	if !ok {
		t.Fatal("tools is not a []Tool")
	}

	// Check that advertise_to_collector tool exists
	found := false
	for _, tool := range tools {
		if tool.Name == "advertise_to_collector" {
			found = true
			if tool.Description == "" {
				t.Error("advertise_to_collector tool has no description")
			}
			if tool.InputSchema == nil {
				t.Error("advertise_to_collector tool has no input schema")
			}
			break
		}
	}

	if !found {
		t.Error("advertise_to_collector tool not found in list")
	}
}

func TestToolAdvertiseToCollector_WithCommand(t *testing.T) {
	server := &Server{
		collector: htcondor.NewCollector("localhost:9618"),
	}

	args := map[string]interface{}{
		"ad": map[string]interface{}{
			"MyType": "Machine",
			"Name":   "slot1@host",
		},
		"command":  "UPDATE_STARTD_AD",
		"with_ack": true,
	}

	ctx := context.Background()
	_, err := server.toolAdvertiseToCollector(ctx, args)

	// Should fail to connect
	if err == nil {
		t.Error("Expected connection error")
	}

	// Verify command was parsed (no "invalid command" error)
	if err.Error() == "invalid command: UPDATE_STARTD_AD" {
		t.Error("Valid command was rejected")
	}
}

func TestToolAdvertiseToCollector_InvalidCommand(t *testing.T) {
	server := &Server{
		collector: htcondor.NewCollector("localhost:9618"),
	}

	args := map[string]interface{}{
		"ad": map[string]interface{}{
			"MyType": "Generic",
			"Name":   "test",
		},
		"command": "INVALID_COMMAND",
	}

	ctx := context.Background()
	_, err := server.toolAdvertiseToCollector(ctx, args)

	if err == nil {
		t.Error("Expected error for invalid command")
	}

	if err.Error() != "invalid command: INVALID_COMMAND" {
		t.Errorf("Expected 'invalid command' error, got: %v", err)
	}
}
