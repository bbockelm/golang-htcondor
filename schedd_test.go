package htcondor

import (
	"context"
	"testing"
)

func TestNewSchedd(t *testing.T) {
	schedd := NewSchedd("test_schedd", "schedd.example.com:9618")
	if schedd == nil {
		t.Fatal("NewSchedd returned nil")
	}
	if schedd.name != "test_schedd" {
		t.Errorf("Expected name 'test_schedd', got '%s'", schedd.name)
	}
	if schedd.address != "schedd.example.com:9618" {
		t.Errorf("Expected address 'schedd.example.com:9618', got '%s'", schedd.address)
	}
}

func TestScheddQuery(t *testing.T) {
	schedd := NewSchedd("test_schedd", "schedd.example.com:9618")
	ctx := context.Background()

	_, err := schedd.Query(ctx, "Owner == \"user\"", []string{"ClusterId", "ProcId"})
	// Expect error because we're not connected to a real schedd
	if err == nil {
		t.Error("Expected error when not connected to schedd")
	}
}

func TestScheddSubmit(t *testing.T) {
	schedd := NewSchedd("test_schedd", "schedd.example.com:9618")
	ctx := context.Background()

	submitFile := `
universe = vanilla
executable = /bin/echo
arguments = hello
queue
`
	_, err := schedd.Submit(ctx, submitFile)
	// Expect error because we're not connected to a real schedd
	if err == nil {
		t.Error("Expected error when not connected to schedd")
	}
}

func TestScheddRemoveJobs(t *testing.T) {
	schedd := NewSchedd("test_schedd", "schedd.example.com:9618")
	ctx := context.Background()

	// Test with invalid constraint (should fail to connect)
	_, err := schedd.RemoveJobs(ctx, "ClusterId == 1", "test reason")
	// Expect error because we're not connected to a real schedd
	if err == nil {
		t.Error("Expected error when not connected to schedd")
	}
}

func TestScheddEdit(t *testing.T) {
	schedd := NewSchedd("test_schedd", "schedd.example.com:9618")
	ctx := context.Background()

	err := schedd.Edit(ctx, "ClusterId == 1", "JobPrio", "10")
	if err == nil {
		t.Error("Expected error for unimplemented method")
	}
}
