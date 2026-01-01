package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestCreateInputSandboxTar_Simple tests basic input sandbox creation
func TestCreateInputSandboxTar_Simple(t *testing.T) {
	// Create temporary directory with test files
	tempDir := t.TempDir()

	// Create test files
	createTestFile(t, filepath.Join(tempDir, "input.txt"), "input data", 0644)
	createTestFile(t, filepath.Join(tempDir, "script.sh"), "#!/bin/bash\necho hello", 0755)

	// Create job ad
	jobAd := classad.New()
	_ = jobAd.Set("Iwd", tempDir)
	_ = jobAd.Set("TransferInput", "input.txt")
	_ = jobAd.Set("Cmd", filepath.Join(tempDir, "script.sh"))
	_ = jobAd.Set("TransferExecutable", true)

	// Create input sandbox
	var buf bytes.Buffer
	err := CreateInputSandboxTar(context.Background(), jobAd, &buf)
	if err != nil {
		t.Fatalf("CreateInputSandboxTar failed: %v", err)
	}

	// Verify tar contents
	tarFiles := readTarContents(t, &buf)

	// Should contain executable and input file
	if len(tarFiles) != 2 {
		t.Errorf("Expected 2 files in tar, got %d", len(tarFiles))
	}

	// Check executable
	scriptContent, ok := tarFiles["script.sh"]
	switch {
	case !ok:
		t.Errorf("Expected script.sh in tar")
	case scriptContent.Content != "#!/bin/bash\necho hello":
		t.Errorf("Unexpected script.sh content: %s", scriptContent.Content)
	case scriptContent.Mode != 0755:
		t.Errorf("Expected script.sh mode 0755, got %o", scriptContent.Mode)
	}

	// Check input file
	inputContent, ok := tarFiles["input.txt"]
	switch {
	case !ok:
		t.Errorf("Expected input.txt in tar")
	case inputContent.Content != "input data":
		t.Errorf("Unexpected input.txt content: %s", inputContent.Content)
	case inputContent.Mode != 0644:
		t.Errorf("Expected input.txt mode 0644, got %o", inputContent.Mode)
	}
}

// TestCreateInputSandboxTar_WithSubdirectories tests input sandbox with directory structure
func TestCreateInputSandboxTar_WithSubdirectories(t *testing.T) {
	tempDir := t.TempDir()

	// Create files in subdirectories
	dataDir := filepath.Join(tempDir, "data")
	if err := os.Mkdir(dataDir, 0750); err != nil { // #nosec G301 - test code
		t.Fatalf("Failed to create data dir: %v", err)
	}
	createTestFile(t, filepath.Join(dataDir, "params.json"), `{"key":"value"}`, 0644)

	sharedDir := filepath.Join(tempDir, "shared")
	if err := os.Mkdir(sharedDir, 0750); err != nil { // #nosec G301 - test code
		t.Fatalf("Failed to create shared dir: %v", err)
	}
	createTestFile(t, filepath.Join(sharedDir, "config.cfg"), "setting=1", 0644)

	// Create job ad
	jobAd := classad.New()
	_ = jobAd.Set("Iwd", tempDir)
	_ = jobAd.Set("TransferInput", "data/params.json,shared/config.cfg")
	_ = jobAd.Set("TransferExecutable", false)

	// Create input sandbox
	var buf bytes.Buffer
	err := CreateInputSandboxTar(context.Background(), jobAd, &buf)
	if err != nil {
		t.Fatalf("CreateInputSandboxTar failed: %v", err)
	}

	// Verify tar contents
	tarFiles := readTarContents(t, &buf)

	// Check file paths preserve directory structure
	if _, ok := tarFiles["data/params.json"]; !ok {
		t.Errorf("Expected data/params.json in tar")
	}
	if _, ok := tarFiles["shared/config.cfg"]; !ok {
		t.Errorf("Expected shared/config.cfg in tar")
	}
}

// TestCreateInputSandboxTar_AbsolutePath tests handling of absolute paths
func TestCreateInputSandboxTar_AbsolutePath(t *testing.T) {
	tempDir := t.TempDir()

	// Create file outside Iwd
	externalDir := t.TempDir()
	externalFile := filepath.Join(externalDir, "external.txt")
	createTestFile(t, externalFile, "external data", 0644)

	// Create job ad with absolute path
	jobAd := classad.New()
	_ = jobAd.Set("Iwd", tempDir)
	_ = jobAd.Set("TransferInput", externalFile)
	_ = jobAd.Set("TransferExecutable", false)

	// Create input sandbox
	var buf bytes.Buffer
	err := CreateInputSandboxTar(context.Background(), jobAd, &buf)
	if err != nil {
		t.Fatalf("CreateInputSandboxTar failed: %v", err)
	}

	// Verify tar contents - absolute paths outside Iwd should use basename
	tarFiles := readTarContents(t, &buf)
	if _, ok := tarFiles["external.txt"]; !ok {
		t.Errorf("Expected external.txt in tar (basename of absolute path)")
	}
}

// TestCreateInputSandboxTar_MissingFile tests error handling for missing files
func TestCreateInputSandboxTar_MissingFile(t *testing.T) {
	tempDir := t.TempDir()

	jobAd := classad.New()
	_ = jobAd.Set("Iwd", tempDir)
	_ = jobAd.Set("TransferInput", "nonexistent.txt")
	_ = jobAd.Set("TransferExecutable", false)

	var buf bytes.Buffer
	err := CreateInputSandboxTar(context.Background(), jobAd, &buf)
	if err == nil {
		t.Errorf("Expected error for missing file, got nil")
	}
}

// TestCreateInputSandboxTar_WithURLs tests that URLs are skipped in input files
func TestCreateInputSandboxTar_WithURLs(t *testing.T) {
	tempDir := t.TempDir()

	// Create a local file
	createTestFile(t, filepath.Join(tempDir, "local.txt"), "local data", 0644)

	// Create job ad with mix of local files and URLs
	jobAd := classad.New()
	_ = jobAd.Set("Iwd", tempDir)
	_ = jobAd.Set("TransferInput", "local.txt,https://example.com/remote.txt,http://data.org/file.dat")
	_ = jobAd.Set("TransferExecutable", false)

	// Create input sandbox
	var buf bytes.Buffer
	err := CreateInputSandboxTar(context.Background(), jobAd, &buf)
	if err != nil {
		t.Fatalf("CreateInputSandboxTar failed: %v", err)
	}

	// Verify tar contents - should only have local file
	tarFiles := readTarContents(t, &buf)

	if len(tarFiles) != 1 {
		t.Errorf("Expected 1 file in tar (URLs should be skipped), got %d", len(tarFiles))
	}

	if _, ok := tarFiles["local.txt"]; !ok {
		t.Errorf("Expected local.txt in tar")
	}
}

// TestExtractOutputSandbox_Simple tests basic output sandbox extraction
func TestExtractOutputSandbox_Simple(t *testing.T) {
	// Create temporary output directory
	outputDir := t.TempDir()

	// Create a tar with output files
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	addTarFile(t, tw, "output.txt", "result data")
	addTarFile(t, tw, "stdout.log", "standard output")

	if err := tw.Close(); err != nil {
		t.Fatalf("Failed to close tar writer: %v", err)
	}

	// Create job ad
	jobAd := classad.New()
	_ = jobAd.Set("Iwd", outputDir)
	_ = jobAd.Set("TransferOutput", "output.txt,stdout.log")

	// Extract output sandbox
	err := ExtractOutputSandbox(context.Background(), jobAd, &buf)
	if err != nil {
		t.Fatalf("ExtractOutputSandbox failed: %v", err)
	}

	// Verify files were created
	verifyFileContent(t, filepath.Join(outputDir, "output.txt"), "result data")
	verifyFileContent(t, filepath.Join(outputDir, "stdout.log"), "standard output")
}

// TestExtractOutputSandbox_WithRemaps tests output remapping
func TestExtractOutputSandbox_WithRemaps(t *testing.T) {
	outputDir := t.TempDir()

	// Create results directory for remap destination
	resultsDir := filepath.Join(outputDir, "results")
	if err := os.Mkdir(resultsDir, 0750); err != nil { // #nosec G301 - test code
		t.Fatalf("Failed to create results dir: %v", err)
	}

	// Create tar with output files
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	addTarFile(t, tw, "output.txt", "result data")
	addTarFile(t, tw, "data.json", `{"result":42}`)

	if err := tw.Close(); err != nil {
		t.Fatalf("Failed to close tar writer: %v", err)
	}

	// Create job ad with remaps
	jobAd := classad.New()
	_ = jobAd.Set("Iwd", outputDir)
	_ = jobAd.Set("TransferOutput", "output.txt,data.json")
	_ = jobAd.Set("TransferOutputRemaps", "output.txt=results/final.txt")

	// Extract output sandbox
	err := ExtractOutputSandbox(context.Background(), jobAd, &buf)
	if err != nil {
		t.Fatalf("ExtractOutputSandbox failed: %v", err)
	}

	// Verify output.txt was remapped
	verifyFileContent(t, filepath.Join(resultsDir, "final.txt"), "result data")

	// Verify data.json was not remapped
	verifyFileContent(t, filepath.Join(outputDir, "data.json"), `{"result":42}`)
}

// TestExtractOutputSandbox_WithSubdirectories tests output with directory structure
func TestExtractOutputSandbox_WithSubdirectories(t *testing.T) {
	outputDir := t.TempDir()

	// Create tar with nested directories
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	addTarFile(t, tw, "results/data.json", `{"result":42}`)
	addTarFile(t, tw, "results/summary.txt", "summary")

	if err := tw.Close(); err != nil {
		t.Fatalf("Failed to close tar writer: %v", err)
	}

	// Create job ad
	jobAd := classad.New()
	_ = jobAd.Set("Iwd", outputDir)
	_ = jobAd.Set("TransferOutput", "") // Empty = extract all

	// Extract output sandbox
	err := ExtractOutputSandbox(context.Background(), jobAd, &buf)
	if err != nil {
		t.Fatalf("ExtractOutputSandbox failed: %v", err)
	}

	// Verify files were created with directory structure
	verifyFileContent(t, filepath.Join(outputDir, "results", "data.json"), `{"result":42}`)
	verifyFileContent(t, filepath.Join(outputDir, "results", "summary.txt"), "summary")
}

// TestExtractOutputSandbox_WithURLRemaps tests that files remapped to URLs are skipped
func TestExtractOutputSandbox_WithURLRemaps(t *testing.T) {
	outputDir := t.TempDir()

	// Create tar with output files
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	addTarFile(t, tw, "upload.txt", "upload data")
	addTarFile(t, tw, "local.txt", "local data")

	if err := tw.Close(); err != nil {
		t.Fatalf("Failed to close tar writer: %v", err)
	}

	// Create job ad with remap to URL
	jobAd := classad.New()
	_ = jobAd.Set("Iwd", outputDir)
	_ = jobAd.Set("TransferOutput", "")
	_ = jobAd.Set("TransferOutputRemaps", "upload.txt=https://example.com/upload")

	// Extract output sandbox
	err := ExtractOutputSandbox(context.Background(), jobAd, &buf)
	if err != nil {
		t.Fatalf("ExtractOutputSandbox failed: %v", err)
	}

	// Verify local.txt was extracted
	verifyFileContent(t, filepath.Join(outputDir, "local.txt"), "local data")

	// Verify upload.txt was not extracted (remapped to URL)
	if _, err := os.Stat(filepath.Join(outputDir, "upload.txt")); err == nil {
		t.Errorf("upload.txt should not have been extracted (remapped to URL)")
	}
}

// TestExtractOutputSandbox_ExtractAll tests extracting all files when TransferOutput is empty
func TestExtractOutputSandbox_ExtractAll(t *testing.T) {
	outputDir := t.TempDir()

	// Create tar with multiple files
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	addTarFile(t, tw, "file1.txt", "content 1")
	addTarFile(t, tw, "file2.txt", "content 2")
	addTarFile(t, tw, "file3.txt", "content 3")

	if err := tw.Close(); err != nil {
		t.Fatalf("Failed to close tar writer: %v", err)
	}

	// Create job ad with empty TransferOutput
	jobAd := classad.New()
	_ = jobAd.Set("Iwd", outputDir)
	_ = jobAd.Set("TransferOutput", "")

	// Extract output sandbox
	err := ExtractOutputSandbox(context.Background(), jobAd, &buf)
	if err != nil {
		t.Fatalf("ExtractOutputSandbox failed: %v", err)
	}

	// Verify all files were extracted
	verifyFileContent(t, filepath.Join(outputDir, "file1.txt"), "content 1")
	verifyFileContent(t, filepath.Join(outputDir, "file2.txt"), "content 2")
	verifyFileContent(t, filepath.Join(outputDir, "file3.txt"), "content 3")
}

// TestParseFileList tests file list parsing
func TestParseFileList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple list",
			input:    "file1.txt,file2.txt,file3.txt",
			expected: []string{"file1.txt", "file2.txt", "file3.txt"},
		},
		{
			name:     "with spaces",
			input:    "file1.txt, file2.txt , file3.txt",
			expected: []string{"file1.txt", "file2.txt", "file3.txt"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single file",
			input:    "file.txt",
			expected: []string{"file.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFileList(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d files, got %d", len(tt.expected), len(result))
				return
			}
			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("Expected file[%d]=%s, got %s", i, expected, result[i])
				}
			}
		})
	}
}

// TestParseRemaps tests remap parsing
func TestParseRemaps(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []remap
	}{
		{
			name:  "simple remaps",
			input: "file1.txt=output1.txt;file2.txt=output2.txt",
			expected: []remap{
				{Source: "file1.txt", Dest: "output1.txt"},
				{Source: "file2.txt", Dest: "output2.txt"},
			},
		},
		{
			name:  "with spaces",
			input: "file1.txt = output1.txt ; file2.txt = output2.txt",
			expected: []remap{
				{Source: "file1.txt", Dest: "output1.txt"},
				{Source: "file2.txt", Dest: "output2.txt"},
			},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []remap{},
		},
		{
			name:  "single remap",
			input: "file.txt=output.txt",
			expected: []remap{
				{Source: "file.txt", Dest: "output.txt"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRemaps(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d remaps, got %d", len(tt.expected), len(result))
				return
			}
			for i, expected := range tt.expected {
				if result[i].Source != expected.Source {
					t.Errorf("remap[%d]: expected Source=%s, got %s", i, expected.Source, result[i].Source)
				}
				if result[i].Dest != expected.Dest {
					t.Errorf("remap[%d]: expected Dest=%s, got %s", i, expected.Dest, result[i].Dest)
				}
			}
		})
	}
}

// TestIsURL tests URL detection
func TestIsURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "http URL",
			input:    "http://example.com/file.txt",
			expected: true,
		},
		{
			name:     "https URL",
			input:    "https://example.com/file.txt",
			expected: true,
		},
		{
			name:     "ftp URL",
			input:    "ftp://ftp.example.com/file.txt",
			expected: true,
		},
		{
			name:     "file URL",
			input:    "file:///path/to/file",
			expected: true,
		},
		{
			name:     "custom scheme",
			input:    "s3://bucket/key",
			expected: true,
		},
		{
			name:     "scheme with plus",
			input:    "osdf+https://origin.com/path",
			expected: true,
		},
		{
			name:     "local file path",
			input:    "/path/to/file.txt",
			expected: false,
		},
		{
			name:     "relative path",
			input:    "file.txt",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "scheme starting with digit (invalid)",
			input:    "3gp://example.com",
			expected: false,
		},
		{
			name:     "scheme with invalid char",
			input:    "ht-tp://example.com",
			expected: false,
		},
		{
			name:     "no scheme separator",
			input:    "notaurl",
			expected: false,
		},
		{
			name:     "scheme only",
			input:    "http://",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isURL(tt.input)
			if result != tt.expected {
				t.Errorf("isURL(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

// Helper functions for tests

type tarFileInfo struct {
	Content string
	Mode    int64
}

// readTarContents reads all files from a tar archive
func readTarContents(t *testing.T, r io.Reader) map[string]tarFileInfo {
	t.Helper()

	files := make(map[string]tarFileInfo)
	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read tar: %v", err)
		}

		if header.Typeflag == tar.TypeReg {
			content, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", header.Name, err)
			}
			files[header.Name] = tarFileInfo{
				Content: string(content),
				Mode:    header.Mode,
			}
		}
	}

	return files
}

// createTestFile creates a file with specified content and permissions
func createTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("Failed to create test file %s: %v", path, err)
	}
}

// addTarFile adds a file to a tar archive
func addTarFile(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()

	header := &tar.Header{
		Name: name,
		Size: int64(len(content)),
		Mode: 0644,
	}

	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("Failed to write tar header for %s: %v", name, err)
	}

	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write tar content for %s: %v", name, err)
	}
}

// verifyFileContent checks that a file exists and has expected content
func verifyFileContent(t *testing.T, path, expectedContent string) {
	t.Helper()

	content, err := os.ReadFile(path) // #nosec G304 - test code, path from test
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", path, err)
	}

	if string(content) != expectedContent {
		t.Errorf("File %s has unexpected content.\nExpected: %s\nGot: %s", path, expectedContent, string(content))
	}
}
