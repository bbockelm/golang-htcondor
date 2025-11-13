package htcondor

import (
	"strings"
	"testing"
)

func TestValidateAttributeForEdit(t *testing.T) {
	tests := []struct {
		name        string
		attrName    string
		opts        *EditJobOptions
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Allow normal attribute",
			attrName:    "JobPrio",
			opts:        nil,
			expectError: true, // JobPrio is protected by default
			errorMsg:    "protected",
		},
		{
			name:        "Allow normal attribute with custom field",
			attrName:    "MyCustomAttribute",
			opts:        nil,
			expectError: false,
		},
		{
			name:        "Reject immutable ClusterId",
			attrName:    "ClusterId",
			opts:        nil,
			expectError: true,
			errorMsg:    "immutable",
		},
		{
			name:        "Reject immutable ProcId",
			attrName:    "ProcId",
			opts:        nil,
			expectError: true,
			errorMsg:    "immutable",
		},
		{
			name:        "Reject immutable Owner",
			attrName:    "Owner",
			opts:        nil,
			expectError: true,
			errorMsg:    "immutable",
		},
		{
			name:        "Reject protected JobStatus without permission",
			attrName:    "JobStatus",
			opts:        &EditJobOptions{AllowProtectedAttrs: false},
			expectError: true,
			errorMsg:    "protected",
		},
		{
			name:        "Allow protected JobStatus with permission",
			attrName:    "JobStatus",
			opts:        &EditJobOptions{AllowProtectedAttrs: true},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttributeForEdit(tt.attrName, tt.opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestImmutableAttributes(t *testing.T) {
	immutableAttrs := []string{
		"ClusterId",
		"ProcId",
		"Owner",
		"User",
		"QDate",
		"CompletionDate",
		"JobStartDate",
		"GlobalJobId",
	}

	for _, attr := range immutableAttrs {
		t.Run(attr, func(t *testing.T) {
			err := ValidateAttributeForEdit(attr, nil)
			if err == nil {
				t.Errorf("Attribute %s should be immutable but validation passed", attr)
			}
			if !strings.Contains(err.Error(), "immutable") {
				t.Errorf("Expected immutable error for %s, got: %v", attr, err)
			}
		})
	}
}

func TestProtectedAttributes(t *testing.T) {
	protectedAttrs := []string{
		"AccountingGroup",
		"JobStatus",
		"HoldReason",
		"RemoveReason",
		"NumJobStarts",
	}

	for _, attr := range protectedAttrs {
		t.Run(attr+"_denied", func(t *testing.T) {
			err := ValidateAttributeForEdit(attr, nil)
			if err == nil {
				t.Errorf("Attribute %s should be protected but validation passed", attr)
			}
			if !strings.Contains(err.Error(), "protected") {
				t.Errorf("Expected protected error for %s, got: %v", attr, err)
			}
		})

		t.Run(attr+"_allowed_with_permission", func(t *testing.T) {
			err := ValidateAttributeForEdit(attr, &EditJobOptions{AllowProtectedAttrs: true})
			if err != nil {
				t.Errorf("Attribute %s should be allowed with permission but got error: %v", attr, err)
			}
		})
	}
}

func TestMutableAttributes(t *testing.T) {
	mutableAttrs := []string{
		"Environment",
		"Requirements",
		"Rank",
		"MyCustomAttribute",
		"+CustomClassAdAttr",
	}

	for _, attr := range mutableAttrs {
		t.Run(attr, func(t *testing.T) {
			err := ValidateAttributeForEdit(attr, nil)
			if err != nil {
				t.Errorf("Attribute %s should be mutable but got error: %v", attr, err)
			}
		})
	}
}
