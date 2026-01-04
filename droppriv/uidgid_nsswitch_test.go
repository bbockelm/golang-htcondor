package droppriv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNSSwitch(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []NSSSwitchMethod
	}{
		{
			name:     "sss then files",
			content:  "passwd: sss files\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodSSS, NSSSwitchMethodFiles},
		},
		{
			name:     "files only",
			content:  "passwd: files\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles},
		},
		{
			name:     "sss only",
			content:  "passwd: sss\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodSSS},
		},
		{
			name:     "files then sss",
			content:  "passwd: files sss\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles, NSSSwitchMethodSSS},
		},
		{
			name:     "with unsupported methods",
			content:  "passwd: files ldap sss nis\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles, NSSSwitchMethodSSS},
		},
		{
			name:     "with systemd (ignored)",
			content:  "passwd: sss files systemd\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodSSS, NSSSwitchMethodFiles},
		},
		{
			name:     "with actions",
			content:  "passwd: files [NOTFOUND=return] sss\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles, NSSSwitchMethodSSS},
		},
		{
			name:     "no passwd line",
			content:  "group: files\nshadow: files\n",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles},
		},
		{
			name:     "empty file",
			content:  "",
			expected: []NSSSwitchMethod{NSSSwitchMethodFiles},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file with test content
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "nsswitch.conf")
			err := os.WriteFile(tmpFile, []byte(tt.content), 0644) // #nosec G306 - test file
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Parse the file
			methods, err := ParseNSSwitch(tmpFile)
			if err != nil {
				t.Fatalf("ParseNSSwitch failed: %v", err)
			}

			// Verify results
			if len(methods) != len(tt.expected) {
				t.Errorf("Expected %d methods, got %d: %v", len(tt.expected), len(methods), methods)
				return
			}

			for i, method := range methods {
				if method != tt.expected[i] {
					t.Errorf("Method %d: expected %s, got %s", i, tt.expected[i], method)
				}
			}
		})
	}
}

func TestParseNSSwitchRealFile(t *testing.T) {
	// Try to parse the actual /etc/nsswitch.conf if it exists
	methods, err := ParseNSSwitch("/etc/nsswitch.conf")
	if err != nil {
		t.Logf("Cannot read /etc/nsswitch.conf (expected in some environments): %v", err)
		return
	}

	t.Logf("Real nsswitch.conf passwd methods: %v", methods)

	// Should have at least one method
	if len(methods) == 0 {
		t.Error("Expected at least one method from real nsswitch.conf")
	}
}
