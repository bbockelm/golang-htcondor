package httpserver

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// validateTarEntryName rejects filenames that could escape the
// receiving schedd's spool dir when extracted from a tar archive.
// The schedd's tar-extraction code is in C++ and may be permissive
// about traversal; this is a defense-in-depth check applied at the
// API boundary so a bug in the schedd never combines with an
// attacker-controlled filename to write outside the user's spool.
//
// Policy:
//   - Reject empty names.
//   - Reject embedded NUL bytes (some C parsers truncate at \0).
//   - Reject leading "/" — entries are meant to be spool-relative.
//   - Reject any segment that resolves to ".." after path cleaning.
//   - Reject "\\" and other escape attempts (Windows path separator
//     handling on cross-platform extractors).
//
// Mirrors the policy applied on the file-DOWNLOAD path
// (handleJobFile). Both upload and download must agree on what
// constitutes a safe filename, otherwise an attacker can upload a
// name they could later download (or vice versa) using the lax
// side.
func validateTarEntryName(name string) error {
	if name == "" {
		return errors.New("filename must not be empty")
	}
	if strings.ContainsRune(name, 0) {
		return errors.New("filename contains NUL byte")
	}
	if strings.ContainsRune(name, '\\') {
		return errors.New("filename contains backslash")
	}
	if strings.HasPrefix(name, "/") {
		return errors.New("filename must not be absolute")
	}
	cleaned := filepath.Clean(name)
	if cleaned != name {
		// e.g. "foo/../bar" -> "bar"; the difference is itself a
		// signal that traversal was attempted.
		return fmt.Errorf("filename is not in canonical form (got %q, cleans to %q)", name, cleaned)
	}
	for _, segment := range strings.Split(cleaned, "/") {
		if segment == ".." {
			return errors.New("filename contains '..' segment")
		}
	}
	return nil
}
