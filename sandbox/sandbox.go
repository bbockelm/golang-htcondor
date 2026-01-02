// Package sandbox provides utilities for creating and extracting HTCondor job sandboxes.
//
// The sandbox package implements filesystem-level operations for managing job input and output sandboxes,
// mimicking the logic that the HTCondor shadow uses when interacting with the starter.
//
// Key Operations:
//   - CreateInputSandboxTar: Creates a tarball from files specified in a job ad
//   - ExtractOutputSandbox: Extracts a tarball to the appropriate filesystem locations
//
// See design_notes/SANDBOX_API.md for detailed design and examples.
package sandbox

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/droppriv"
)

// remap represents a path remapping from Source to Dest.
// Remaps are applied as prefix matches: if a file path starts with Source,
// that prefix is replaced with Dest.
type remap struct {
	Source string
	Dest   string
}

// CreateInputSandboxTar creates a tarball containing all input files specified in the job ad.
// The tarball layout matches what the shadow sends to the starter.
//
// The function reads these job ad attributes:
//   - TransferInput: Comma-separated list of input files
//   - Iwd: Initial working directory (base path for relative files)
//   - Cmd: Executable path (included if TransferExecutable is true)
//   - TransferExecutable: Whether to include the executable
//   - In: Standard input file (included if set)
//
// Parameters:
//   - ctx: Context for cancellation
//   - jobAd: Job ClassAd containing file transfer attributes
//   - w: Writer where the tar archive will be written
//
// Returns error if:
//   - Required attributes are missing from job ad
//   - Input files cannot be read
//   - Tar archive cannot be created
func CreateInputSandboxTar(ctx context.Context, jobAd *classad.ClassAd, w io.Writer) (err error) {
	// Get Iwd (initial working directory)
	iwd, ok := classad.GetAs[string](jobAd, "Iwd")
	if !ok {
		return fmt.Errorf("iwd is not a string in job ad")
	}

	userName, err := getSandboxUser(jobAd)
	if err != nil {
		return err
	}
	mgr := droppriv.DefaultManager()

	// Create tar writer
	tw := tar.NewWriter(w)
	defer func() {
		if cerr := tw.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	// Get TransferExecutable flag
	transferExec, ok := classad.GetAs[bool](jobAd, "TransferExecutable")

	// Add executable if needed
	if ok && transferExec {
		execPath, ok := classad.GetAs[string](jobAd, "Cmd")
		if !ok {
			return fmt.Errorf("TransferExecutable is true but Cmd is missing")
		}

		if err := addFileToTar(tw, execPath, iwd, userName, mgr); err != nil {
			return fmt.Errorf("failed to add executable %s: %w", execPath, err)
		}
	}

	// Add stdin file if specified
	stdinPath, hasStdin := classad.GetAs[string](jobAd, "In")
	if hasStdin && stdinPath != "" {
		// Skip URLs for stdin
		if !isURL(stdinPath) {
			if err := addFileToTar(tw, stdinPath, iwd, userName, mgr); err != nil {
				return fmt.Errorf("failed to add stdin file %s: %w", stdinPath, err)
			}
		}
	}

	// Get TransferInput list
	transferInput, ok := classad.GetAs[string](jobAd, "TransferInput")
	if !ok {
		// TransferInput is optional
		transferInput = ""
	}

	if transferInput != "" {
		// Parse comma-separated file list
		files := parseFileList(transferInput)

		// Add each file to the tar
		for _, filePath := range files {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("context cancelled: %w", err)
			}
			// Skip URLs - they will be downloaded by the execution node
			if isURL(filePath) {
				continue
			}
			if err := addFileToTar(tw, filePath, iwd, userName, mgr); err != nil {
				return fmt.Errorf("failed to add file %s: %w", filePath, err)
			}
		}
	}

	return nil
}

// addFileToTar adds a single file to the tar archive.
// If filePath is relative, it's resolved relative to baseDir.
// The file is added to the tar with a path relative to baseDir.
func addFileToTar(tw *tar.Writer, filePath string, baseDir string, userName string, mgr *droppriv.Manager) error {
	// Resolve the full path
	var fullPath string
	if filepath.IsAbs(filePath) {
		fullPath = filePath
	} else {
		fullPath = filepath.Join(baseDir, filePath)
	}

	// Open the file
	file, err := mgr.Open(userName, fullPath) // #nosec G304 - file path comes from job ad, expected behavior
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Determine the path in the tar archive
	// For files under baseDir, use relative path
	// For absolute paths outside baseDir, use just the basename
	var tarPath string
	if filepath.IsAbs(filePath) {
		// Check if file is under baseDir
		relPath, err := filepath.Rel(baseDir, fullPath)
		if err == nil && !strings.HasPrefix(relPath, "..") {
			// File is under baseDir, use relative path
			tarPath = relPath
		} else {
			// File is outside baseDir, use basename
			tarPath = filepath.Base(fullPath)
		}
	} else {
		// Relative path, use as-is
		tarPath = filepath.ToSlash(filePath)
	}

	// Create tar header
	header, err := tar.FileInfoHeader(fileInfo, "")
	if err != nil {
		return fmt.Errorf("failed to create tar header: %w", err)
	}
	header.Name = tarPath

	// Write header
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}

	// Write file contents
	if _, err := io.Copy(tw, file); err != nil {
		return fmt.Errorf("failed to write file contents: %w", err)
	}

	return nil
}

// ExtractOutputSandbox extracts files from an output sandbox tarball and places them
// in the appropriate locations based on the job ad.
//
// The function reads these job ad attributes:
//   - Iwd: Initial working directory (default location for files)
//   - TransferOutput: Comma-separated list of files to extract (empty = extract all)
//   - TransferOutputRemaps: Semicolon-separated "src=dest" remappings
//   - Out: Standard output file path
//   - Err: Standard error file path
//
// Parameters:
//   - ctx: Context for cancellation
//   - jobAd: Job ClassAd containing output transfer attributes
//   - r: Reader providing the tar archive
//
// Returns error if:
//   - Required attributes are missing from job ad
//   - Tarball cannot be read
//   - Files cannot be written to filesystem
func ExtractOutputSandbox(ctx context.Context, jobAd *classad.ClassAd, r io.Reader) error {
	// Get Iwd (initial working directory)
	iwd, ok := classad.GetAs[string](jobAd, "Iwd")
	if !ok {
		return fmt.Errorf("iwd is not a string in job ad")
	}

	userName, err := getSandboxUser(jobAd)
	if err != nil {
		return err
	}
	mgr := droppriv.DefaultManager()

	// Get TransferOutput list (optional - if empty, extract all files)
	transferOutput, ok := classad.GetAs[string](jobAd, "TransferOutput")
	var outputFiles map[string]bool
	if ok && transferOutput != "" {
		files := parseFileList(transferOutput)
		outputFiles = make(map[string]bool, len(files))
		for _, f := range files {
			outputFiles[f] = true
		}
	}

	// Parse TransferOutputRemaps
	var remaps []remap
	remapsStr, ok := classad.GetAs[string](jobAd, "TransferOutputRemaps")
	if ok && remapsStr != "" {
		remaps = parseRemaps(remapsStr)
	}

	// Get standard output/error file paths
	stdoutPath, hasStdout := classad.GetAs[string](jobAd, "Out")
	stderrPath, hasStderr := classad.GetAs[string](jobAd, "Err")

	// Create tar reader
	tr := tar.NewReader(r)

	// Extract each file from the tar
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled: %w", err)
		}

		header, err := tr.Next()
		if err == io.EOF {
			break // End of tar archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Skip directories (they will be created as needed)
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Handle special HTCondor files
		var destPath string
		switch header.Name {
		case "_condor_stdout":
			// Map to Out attribute, skip if not set
			if !hasStdout {
				continue
			}
			if filepath.IsAbs(stdoutPath) {
				destPath = stdoutPath
			} else {
				destPath = filepath.Join(iwd, stdoutPath)
			}
		case "_condor_stderr":
			// Map to Err attribute, skip if not set
			if !hasStderr {
				continue
			}
			if filepath.IsAbs(stderrPath) {
				destPath = stderrPath
			} else {
				destPath = filepath.Join(iwd, stderrPath)
			}
		default:
			// Check if this file should be extracted
			if outputFiles != nil && !outputFiles[header.Name] {
				continue
			}

			// Determine destination path using normal rules
			destPath = getDestinationPath(header.Name, iwd, remaps)
		}

		// Skip files that map to URLs (e.g., remapped to upload endpoints)
		if isURL(destPath) {
			continue
		}

		// Extract the file
		if err := extractFile(mgr, userName, tr, destPath, header); err != nil {
			return fmt.Errorf("failed to extract file %s to %s: %w", header.Name, destPath, err)
		}
	}

	return nil
}

// getDestinationPath determines where a file from the tar should be written.
// Applies remaps if present (using prefix matching), otherwise writes to Iwd.
// Remaps are checked in order; the first matching prefix is used.
func getDestinationPath(tarPath string, iwd string, remaps []remap) string {
	// Check remaps in order (first match wins)
	for _, remap := range remaps {
		// Check if tarPath starts with the remap source
		if strings.HasPrefix(tarPath, remap.Source) {
			// Replace the prefix and append the remainder
			remainder := strings.TrimPrefix(tarPath, remap.Source)
			// Remove leading slash from remainder if present
			remainder = strings.TrimPrefix(remainder, "/")

			var remappedPath string
			if remainder != "" {
				remappedPath = filepath.Join(remap.Dest, remainder)
			} else {
				remappedPath = remap.Dest
			}

			if filepath.IsAbs(remappedPath) {
				return remappedPath
			}
			return filepath.Join(iwd, remappedPath)
		}
	}

	// No remap matched, write to Iwd
	return filepath.Join(iwd, tarPath)
}

// extractFile writes a single file from the tar to the filesystem.
func extractFile(mgr *droppriv.Manager, userName string, tr *tar.Reader, destPath string, header *tar.Header) error {
	// Create parent directories
	destDir := filepath.Dir(destPath)
	if err := mgr.MkdirAll(userName, destDir, 0750); err != nil { // #nosec G301 - 0750 is secure
		return fmt.Errorf("failed to create directory %s: %w", destDir, err)
	}

	// Create the file
	// Mask mode to 0777 to avoid potential overflow from int64 to uint32
	fileMode := os.FileMode(header.Mode & 0777)                                                 // #nosec G115 - mode masked to valid range
	file, err := mgr.OpenFile(userName, destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode) // #nosec G304 - destPath derived from job ad, expected
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	// Write contents
	if _, err := io.Copy(file, tr); err != nil {
		return fmt.Errorf("failed to write file contents: %w", err)
	}

	return nil
}

func getSandboxUser(jobAd *classad.ClassAd) (string, error) {
	userName, ok := classad.GetAs[string](jobAd, "OsUser")
	if !ok {
		// Fallback to Owner if OsUser is not set
		userName, ok = classad.GetAs[string](jobAd, "Owner")
		if !ok {
			return "", fmt.Errorf("job ad missing both OsUser and Owner attributes")
		}
	}
	return strings.TrimSpace(userName), nil
}

// Helper functions for reading ClassAd attributes

// isURL checks if a string is a URL (starts with a valid scheme).
// A valid URL has the form "scheme://..." where scheme consists of
// alphanumeric characters plus '+' and cannot start with a digit.
func isURL(s string) bool {
	if s == "" {
		return false
	}

	// Look for "://"
	idx := strings.Index(s, "://")
	if idx == -1 {
		return false
	}

	scheme := s[:idx]
	if len(scheme) == 0 {
		return false
	}

	// Scheme cannot start with a digit or `+`
	if (scheme[0] >= '0' && scheme[0] <= '9') || scheme[0] == '+' {
		return false
	}

	// Check that all characters in scheme are alphanumeric or '+'
	for _, ch := range scheme {
		if (ch < 'a' || ch > 'z') &&
			(ch < 'A' || ch > 'Z') &&
			(ch < '0' || ch > '9') &&
			ch != '+' {
			return false
		}
	}

	return true
}

// parseFileList parses a comma-separated list of files.
// Handles quoted filenames and whitespace.
func parseFileList(fileList string) []string {
	if fileList == "" {
		return nil
	}

	var files []string
	parts := strings.Split(fileList, ",")
	for _, part := range parts {
		file := strings.TrimSpace(part)
		if file != "" {
			files = append(files, file)
		}
	}
	return files
}

// parseRemaps parses a semicolon-separated list of "src=dest" remappings.
// Returns a slice to preserve ordering (first match wins).
func parseRemaps(remapStr string) []remap {
	var remaps []remap
	if remapStr == "" {
		return remaps
	}

	parts := strings.Split(remapStr, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split on first '='
		idx := strings.Index(part, "=")
		if idx == -1 {
			continue
		}

		src := strings.TrimSpace(part[:idx])
		dest := strings.TrimSpace(part[idx+1:])
		if src != "" && dest != "" {
			remaps = append(remaps, remap{Source: src, Dest: dest})
		}
	}

	return remaps
}
