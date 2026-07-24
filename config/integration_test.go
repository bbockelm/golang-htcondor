package config

// Integration tests for HTCondor configuration file loading
// as specified in: https://htcondor.readthedocs.io/en/main/admin-manual/introduction-to-configuration.html#ordered-evaluation-to-set-the-configuration
//
// Tests cover:
// - Configuration file resolution order (CONDOR_CONFIG environment variable)
// - LOCAL_CONFIG_DIR: comma/space-separated list of directories
// - LOCAL_CONFIG_FILE: comma/space-separated list of files
// - Include directives: include, include ifexist, include command
//
// Syntax supported:
// - 'include : <file>' - HTCondor standard syntax with colon
// - 'include "<file>"' - Alternative syntax without colon (backward compatibility)
// - 'include ifexist : <file>' - Optional include with colon
// - 'include command : <cmdline>' - Command execution with colon
// - 'include : <cmdline>|' - Command execution with pipe syntax

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestConfigResolutionOrder tests the configuration file resolution order
// as specified in HTCondor documentation
func TestConfigResolutionOrder(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create root config file
	rootConfig := filepath.Join(tmpDir, "condor_config")
	if err := os.WriteFile(rootConfig, []byte(`
# Root configuration
ROOT_VAR = from_root
SHARED_VAR = from_root
`), 0600); err != nil {
		t.Fatalf("Failed to create root config: %v", err)
	}

	// Load from root config
	cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
	if err != nil {
		t.Fatalf("Failed to load root config: %v", err)
	}

	// Verify root values
	if val, ok := cfg.Get("ROOT_VAR"); !ok || val != "from_root" {
		t.Errorf("ROOT_VAR: got %q, want %q", val, "from_root")
	}
	if val, ok := cfg.Get("SHARED_VAR"); !ok || val != "from_root" {
		t.Errorf("SHARED_VAR: got %q, want %q", val, "from_root")
	}
}

// TestLOCAL_CONFIG_DIR tests loading configuration from LOCAL_CONFIG_DIR
// The documentation specifies:
// - Can be a comma or space-separated list of directories
// - Files within each directory are loaded in lexicographical order
// - Leftmost directory is processed first
func TestLOCAL_CONFIG_DIR(t *testing.T) {
	tmpDir := t.TempDir()

	// Create directory structure:
	// config.d/
	//   ├── 10-first.config
	//   ├── 20-second.config
	//   └── 30-third.config
	// config2.d/
	//   └── 40-fourth.config

	configDir1 := filepath.Join(tmpDir, "config.d")
	configDir2 := filepath.Join(tmpDir, "config2.d")

	if err := os.MkdirAll(configDir1, 0750); err != nil {
		t.Fatalf("Failed to create config.d: %v", err)
	}
	if err := os.MkdirAll(configDir2, 0750); err != nil {
		t.Fatalf("Failed to create config2.d: %v", err)
	}

	// Create config files with values that show load order
	files := map[string]string{
		filepath.Join(configDir1, "10-first.config"):  "ORDER = 1\nSHARED = first",
		filepath.Join(configDir1, "20-second.config"): "ORDER = 2\nSHARED = second",
		filepath.Join(configDir1, "30-third.config"):  "ORDER = 3\nSHARED = third",
		filepath.Join(configDir2, "40-fourth.config"): "ORDER = 4\nSHARED = fourth",
	}

	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create %s: %v", path, err)
		}
	}

	// Test with comma-separated list
	t.Run("CommaSeparated", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_comma.config")
		content := fmt.Sprintf("LOCAL_CONFIG_DIR = %s,%s\n", configDir1, configDir2)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Process LOCAL_CONFIG_DIR
		if err := cfg.processLocalConfigDir(); err != nil {
			t.Fatalf("Failed to process LOCAL_CONFIG_DIR: %v", err)
		}

		// SHARED should be "fourth" (last value loaded)
		if val, ok := cfg.Get("SHARED"); !ok || val != "fourth" {
			t.Errorf("SHARED: got %q, want %q", val, "fourth")
		}

		// Verify ORDER was set by last file
		if val, ok := cfg.Get("ORDER"); !ok || val != "4" {
			t.Errorf("ORDER: got %q, want %q", val, "4")
		}
	})

	// Test with space-separated list
	t.Run("SpaceSeparated", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_space.config")
		content := fmt.Sprintf("LOCAL_CONFIG_DIR = %s %s\n", configDir1, configDir2)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if err := cfg.processLocalConfigDir(); err != nil {
			t.Fatalf("Failed to process LOCAL_CONFIG_DIR: %v", err)
		}

		if val, ok := cfg.Get("SHARED"); !ok || val != "fourth" {
			t.Errorf("SHARED: got %q, want %q", val, "fourth")
		}
	})

	// Test lexicographical ordering within directory
	t.Run("LexicographicalOrder", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_lex.config")
		content := fmt.Sprintf("LOCAL_CONFIG_DIR = %s\n", configDir1)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if err := cfg.processLocalConfigDir(); err != nil {
			t.Fatalf("Failed to process LOCAL_CONFIG_DIR: %v", err)
		}

		// SHARED should be "third" (last in lexicographical order)
		if val, ok := cfg.Get("SHARED"); !ok || val != "third" {
			t.Errorf("SHARED: got %q, want %q", val, "third")
		}
	})
}

// TestLOCAL_CONFIG_DIR_Reprocessing tests that if LOCAL_CONFIG_DIR is changed
// during processing, it gets reprocessed with the new value
func TestLOCAL_CONFIG_DIR_Reprocessing(t *testing.T) {
	tmpDir := t.TempDir()

	// Create directory structure
	configDir1 := filepath.Join(tmpDir, "config.d")
	configDir2 := filepath.Join(tmpDir, "config2.d")

	if err := os.MkdirAll(configDir1, 0750); err != nil {
		t.Fatalf("Failed to create config.d: %v", err)
	}
	if err := os.MkdirAll(configDir2, 0750); err != nil {
		t.Fatalf("Failed to create config2.d: %v", err)
	}

	// Create files that will modify LOCAL_CONFIG_DIR
	file1 := filepath.Join(configDir1, "10-first.config")
	content1 := fmt.Sprintf("FROM_DIR1 = yes\nLOCAL_CONFIG_DIR = %s\n", configDir2)
	if err := os.WriteFile(file1, []byte(content1), 0600); err != nil {
		t.Fatalf("Failed to create file1: %v", err)
	}

	file2 := filepath.Join(configDir2, "20-second.config")
	if err := os.WriteFile(file2, []byte("FROM_DIR2 = yes\n"), 0600); err != nil {
		t.Fatalf("Failed to create file2: %v", err)
	}

	// Root config sets initial LOCAL_CONFIG_DIR
	rootConfig := filepath.Join(tmpDir, "root.config")
	content := fmt.Sprintf("LOCAL_CONFIG_DIR = %s\n", configDir1)
	if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create root config: %v", err)
	}

	cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Process LOCAL_CONFIG_DIR (should process configDir1, which changes LOCAL_CONFIG_DIR)
	if err := cfg.processLocalConfigDir(); err != nil {
		t.Fatalf("First processLocalConfigDir failed: %v", err)
	}

	// Verify FROM_DIR1 was loaded
	if val, ok := cfg.Get("FROM_DIR1"); !ok || val != "yes" {
		t.Errorf("FROM_DIR1: got %q, want %q", val, "yes")
	}

	// Process LOCAL_CONFIG_DIR again (should now process configDir2)
	if err := cfg.processLocalConfigDir(); err != nil {
		t.Fatalf("Second processLocalConfigDir failed: %v", err)
	}

	// Verify FROM_DIR2 was loaded
	if val, ok := cfg.Get("FROM_DIR2"); !ok || val != "yes" {
		t.Errorf("FROM_DIR2: got %q, want %q", val, "yes")
	}
}

// TestLOCAL_CONFIG_FILE tests loading configuration from LOCAL_CONFIG_FILE
// The documentation specifies:
// - Can be a comma or space-separated list of files
// - Files are loaded left to right (first to last)
func TestLOCAL_CONFIG_FILE(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test config files
	file1 := filepath.Join(tmpDir, "local1.config")
	file2 := filepath.Join(tmpDir, "local2.config")
	file3 := filepath.Join(tmpDir, "local3.config")

	if err := os.WriteFile(file1, []byte("VAR = from_file1\nSHARED = file1"), 0600); err != nil {
		t.Fatalf("Failed to create file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("VAR = from_file2\nSHARED = file2"), 0600); err != nil {
		t.Fatalf("Failed to create file2: %v", err)
	}
	if err := os.WriteFile(file3, []byte("VAR = from_file3\nSHARED = file3"), 0600); err != nil {
		t.Fatalf("Failed to create file3: %v", err)
	}

	// Test with comma-separated list
	t.Run("CommaSeparated", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_comma.config")
		content := fmt.Sprintf("LOCAL_CONFIG_FILE = %s,%s,%s\n", file1, file2, file3)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if err := cfg.processLocalConfigFile(); err != nil {
			t.Fatalf("Failed to process LOCAL_CONFIG_FILE: %v", err)
		}

		// SHARED should be "file3" (last file loaded)
		if val, ok := cfg.Get("SHARED"); !ok || val != "file3" {
			t.Errorf("SHARED: got %q, want %q", val, "file3")
		}
	})

	// Test with space-separated list
	t.Run("SpaceSeparated", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_space.config")
		content := fmt.Sprintf("LOCAL_CONFIG_FILE = %s %s %s\n", file1, file2, file3)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if err := cfg.processLocalConfigFile(); err != nil {
			t.Fatalf("Failed to process LOCAL_CONFIG_FILE: %v", err)
		}

		if val, ok := cfg.Get("SHARED"); !ok || val != "file3" {
			t.Errorf("SHARED: got %q, want %q", val, "file3")
		}
	})

	// Test with mixed separators
	t.Run("MixedSeparators", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_mixed.config")
		content := fmt.Sprintf("LOCAL_CONFIG_FILE = %s, %s %s\n", file1, file2, file3)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if err := cfg.processLocalConfigFile(); err != nil {
			t.Fatalf("Failed to process LOCAL_CONFIG_FILE: %v", err)
		}

		if val, ok := cfg.Get("SHARED"); !ok || val != "file3" {
			t.Errorf("SHARED: got %q, want %q", val, "file3")
		}
	})
}

// TestIncludeDirectiveFile tests the "include : <file>" directive
func TestIncludeDirectiveFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create included file
	includedFile := filepath.Join(tmpDir, "included.config")
	if err := os.WriteFile(includedFile, []byte("INCLUDED_VAR = from_included\n"), 0600); err != nil {
		t.Fatalf("Failed to create included file: %v", err)
	}

	// Create root config with include directive using HTCondor standard colon syntax
	rootConfig := filepath.Join(tmpDir, "root.config")
	content := fmt.Sprintf("ROOT_VAR = from_root\ninclude : \"%s\"\n", includedFile)
	if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create root config: %v", err)
	}

	cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify both values are present
	if val, ok := cfg.Get("ROOT_VAR"); !ok || val != "from_root" {
		t.Errorf("ROOT_VAR: got %q, want %q", val, "from_root")
	}
	if val, ok := cfg.Get("INCLUDED_VAR"); !ok || val != "from_included" {
		t.Errorf("INCLUDED_VAR: got %q, want %q", val, "from_included")
	}
}

// TestIncludeIfExist tests the "include ifexist : <file>" directive
func TestIncludeIfExist(t *testing.T) {
	tmpDir := t.TempDir()

	existingFile := filepath.Join(tmpDir, "existing.config")
	if err := os.WriteFile(existingFile, []byte("EXISTING = yes\n"), 0600); err != nil {
		t.Fatalf("Failed to create existing file: %v", err)
	}

	nonExistingFile := filepath.Join(tmpDir, "nonexisting.config")

	// Test that existing file is included
	t.Run("ExistingFile", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_exist.config")
		content := fmt.Sprintf("include ifexist : \"%s\"\n", existingFile)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if val, ok := cfg.Get("EXISTING"); !ok || val != "yes" {
			t.Errorf("EXISTING: got %q, want %q", val, "yes")
		}
	})

	// Test that non-existing file doesn't cause error
	t.Run("NonExistingFile", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_noexist.config")
		content := fmt.Sprintf("TEST = value\ninclude ifexist : \"%s\"\n", nonExistingFile)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		// Should not error, and TEST should be set
		if val, ok := cfg.Get("TEST"); !ok || val != "value" {
			t.Errorf("TEST: got %q, want %q", val, "value")
		}
	})

	// Test that regular include fails for non-existing file
	t.Run("RegularIncludeFails", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_fail.config")
		content := fmt.Sprintf("include : \"%s\"\n", nonExistingFile)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		_, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err == nil {
			t.Error("Expected error for non-existing file with regular include, got nil")
		}
	})
}

// TestIncludeCommand tests the "include command : <cmdline>" directive
func TestIncludeCommand(t *testing.T) {
	tmpDir := t.TempDir()

	// Test basic command execution
	t.Run("BasicCommand", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_cmd.config")
		// Use echo to output config
		content := "include command : \"echo 'CMD_VAR = from_command'\"\n"
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if val, ok := cfg.Get("CMD_VAR"); !ok || val != "from_command" {
			t.Errorf("CMD_VAR: got %q, want %q", val, "from_command")
		}
	})

	// Unquoted command with arguments — the HTCondor-native form
	// (`include command : /usr/bin/foo -a -b`), which motivated the fix.
	t.Run("UnquotedCommandWithArgs", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_unquoted_cmd.config")
		content := "include command : /bin/echo UNQUOTED_VAR = from_unquoted\n"
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if val, ok := cfg.Get("UNQUOTED_VAR"); !ok || val != "from_unquoted" {
			t.Errorf("UNQUOTED_VAR: got %q, want %q", val, "from_unquoted")
		}
	})
}

// TestIncludeUnquotedFile checks an unquoted `include : <path>` (HTCondor's
// native form — no quotes, path runs to end of line).
func TestIncludeUnquotedFile(t *testing.T) {
	tmpDir := t.TempDir()
	includedFile := filepath.Join(tmpDir, "included.config")
	if err := os.WriteFile(includedFile, []byte("FROM_UNQUOTED_INCLUDE = yes\n"), 0600); err != nil {
		t.Fatalf("Failed to create included file: %v", err)
	}
	rootConfig := filepath.Join(tmpDir, "root_unquoted.config")
	content := fmt.Sprintf("ROOT_VAR = from_root\ninclude : %s\n", includedFile)
	if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create root config: %v", err)
	}

	cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if val, ok := cfg.Get("FROM_UNQUOTED_INCLUDE"); !ok || val != "yes" {
		t.Errorf("FROM_UNQUOTED_INCLUDE: got %q, want %q", val, "yes")
	}
}

// TestIncludeCommandWithCache tests "include command into <cache> : <cmdline>"
// Note: Caching functionality may need to be implemented separately
func TestIncludeCommandWithCache(t *testing.T) {
	t.Skip("Cache functionality not yet implemented in parser")

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "cache.config")

	t.Run("CacheCreation", func(t *testing.T) {
		rootConfig := filepath.Join(tmpDir, "root_cache1.config")
		content := fmt.Sprintf("include ifexist command into %s : echo 'CACHED = first_run'\n", cacheFile)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		// First run - should execute command and create cache
		cfg1, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("First run failed: %v", err)
		}

		if val, ok := cfg1.Get("CACHED"); !ok || val != "first_run" {
			t.Errorf("First run CACHED: got %q, want %q", val, "first_run")
		}

		// Verify cache file was created
		if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
			t.Error("Cache file was not created")
		}
	})

	t.Run("CacheReuse", func(t *testing.T) {
		// Modify the command but keep same cache file
		rootConfig := filepath.Join(tmpDir, "root_cache2.config")
		content := fmt.Sprintf("include ifexist command into %s : echo 'CACHED = second_run'\n", cacheFile)
		if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create root config: %v", err)
		}

		// Second run - should read from cache, not execute command
		cfg2, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
		if err != nil {
			t.Fatalf("Second run failed: %v", err)
		}

		// Should still have "first_run" from cache
		if val, ok := cfg2.Get("CACHED"); !ok || val != "first_run" {
			t.Errorf("Second run CACHED: got %q, want %q (should use cache)", val, "first_run")
		}
	})
}

// TestCompleteConfigurationLoading tests the full configuration loading sequence
// as specified in HTCondor documentation
func TestCompleteConfigurationLoading(t *testing.T) {
	tmpDir := t.TempDir()

	// Set up directory structure
	configDir := filepath.Join(tmpDir, "config.d")
	if err := os.MkdirAll(configDir, 0750); err != nil {
		t.Fatalf("Failed to create config.d: %v", err)
	}

	// Create files in config.d with lexicographical ordering
	dirFile1 := filepath.Join(configDir, "10-base.config")
	if err := os.WriteFile(dirFile1, []byte("FROM_DIR = dir_file_1\nOVERRIDE = from_dir\n"), 0600); err != nil {
		t.Fatalf("Failed to create dir file 1: %v", err)
	}

	dirFile2 := filepath.Join(configDir, "20-override.config")
	if err := os.WriteFile(dirFile2, []byte("FROM_DIR = dir_file_2\n"), 0600); err != nil {
		t.Fatalf("Failed to create dir file 2: %v", err)
	}

	// Create LOCAL_CONFIG_FILE
	localFile := filepath.Join(tmpDir, "local.config")
	if err := os.WriteFile(localFile, []byte("FROM_LOCAL_FILE = yes\nOVERRIDE = from_local_file\n"), 0600); err != nil {
		t.Fatalf("Failed to create local file: %v", err)
	}

	// Create include file
	includeFile := filepath.Join(tmpDir, "included.config")
	if err := os.WriteFile(includeFile, []byte("FROM_INCLUDE = yes\nOVERRIDE = from_include\n"), 0600); err != nil {
		t.Fatalf("Failed to create include file: %v", err)
	}

	// Create root config that sets up LOCAL_CONFIG_DIR and LOCAL_CONFIG_FILE
	rootConfig := filepath.Join(tmpDir, "condor_config")
	content := fmt.Sprintf(`
ROOT = yes
OVERRIDE = from_root
LOCAL_CONFIG_DIR = %s
LOCAL_CONFIG_FILE = %s
include : "%s"
`, configDir, localFile, includeFile)
	if err := os.WriteFile(rootConfig, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create root config: %v", err)
	}

	// Load configuration
	cfg, err := NewFromReaderWithOptions(mustOpen(t, rootConfig), ConfigOptions{})
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Process LOCAL_CONFIG_DIR and LOCAL_CONFIG_FILE
	if err := cfg.processLocalConfigDir(); err != nil {
		t.Fatalf("Failed to process LOCAL_CONFIG_DIR: %v", err)
	}
	if err := cfg.processLocalConfigFile(); err != nil {
		t.Fatalf("Failed to process LOCAL_CONFIG_FILE: %v", err)
	}

	// Verify loading order (later definitions override earlier ones):
	// 1. Root config (including inline include directives)
	// 2. LOCAL_CONFIG_DIR files (in lexicographical order)
	// 3. LOCAL_CONFIG_FILE
	// Note: include directives in root config are processed inline, so they happen
	// before LOCAL_CONFIG_DIR and LOCAL_CONFIG_FILE

	if val, ok := cfg.Get("ROOT"); !ok || val != "yes" {
		t.Errorf("ROOT: got %q, want %q", val, "yes")
	}

	// FROM_DIR should be from the last file in config.d (20-override.config)
	if val, ok := cfg.Get("FROM_DIR"); !ok || val != "dir_file_2" {
		t.Errorf("FROM_DIR: got %q, want %q", val, "dir_file_2")
	}

	if val, ok := cfg.Get("FROM_LOCAL_FILE"); !ok || val != "yes" {
		t.Errorf("FROM_LOCAL_FILE: got %q, want %q", val, "yes")
	}

	if val, ok := cfg.Get("FROM_INCLUDE"); !ok || val != "yes" {
		t.Errorf("FROM_INCLUDE: got %q, want %q", val, "yes")
	}

	// OVERRIDE should be from LOCAL_CONFIG_FILE (last in processing order)
	// since include directives are processed inline in the root config
	if val, ok := cfg.Get("OVERRIDE"); !ok || val != "from_local_file" {
		t.Errorf("OVERRIDE: got %q, want %q (should be from local_file)", val, "from_local_file")
	}
}

// Helper function to open a file for testing
func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	//nolint:gosec // G304: Test helper for opening test files
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
