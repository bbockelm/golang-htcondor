package droppriv

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// NSSSwitchMethod represents a method in nsswitch.conf.
type NSSSwitchMethod string

const (
	// NSSSwitchMethodSSS represents the SSSD method.
	NSSSwitchMethodSSS NSSSwitchMethod = "sss"
	// NSSSwitchMethodFiles represents the files method (traditional /etc/passwd).
	NSSSwitchMethodFiles NSSSwitchMethod = "files"
)

// ParseNSSwitch parses /etc/nsswitch.conf and returns the methods for the passwd database.
// It returns a slice of methods in the order they appear in the configuration.
// Only "sss" and "files" methods are supported; other methods are ignored.
func ParseNSSwitch(path string) ([]NSSSwitchMethod, error) {
	return ParseNSSwitchDB(path, "passwd")
}

// ParseNSSwitchDB is ParseNSSwitch for any database line -- "passwd",
// "group", "shadow". The database that answers "which groups is this
// user in" is `group`, not `passwd`, and the two are routinely
// configured differently, so callers must say which they mean.
//
// Methods other than sss and files are ignored here, which makes the
// returned list a description of what THIS code can speak rather than
// of what the system will do. A caller that cares about the difference
// should compare len(methods) against the line it parsed; see
// idmap.NSSwitchGroupSource, which falls back to asking libc when
// nsswitch names something it cannot speak itself.
func ParseNSSwitchDB(path, database string) ([]NSSSwitchMethod, error) {
	file, err := os.Open(path) // #nosec G304 - path is controlled by configuration
	if err != nil {
		return nil, fmt.Errorf("failed to open nsswitch.conf: %w", err)
	}
	defer func() {
		_ = file.Close() // Best effort close
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for the requested database's line
		if !strings.HasPrefix(line, database+":") {
			continue
		}

		// Parse the methods after "<database>:"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		var methods []NSSSwitchMethod
		for _, part := range parts[1:] {
			// Handle action syntax like [NOTFOUND=return]
			if strings.HasPrefix(part, "[") {
				continue
			}

			switch part {
			case "sss":
				methods = append(methods, NSSSwitchMethodSSS)
			case "files":
				methods = append(methods, NSSSwitchMethodFiles)
				// Ignore other methods (compat, nis, ldap, winbind, etc.)
			}
		}

		return methods, nil
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading nsswitch.conf: %w", err)
	}

	// No passwd line found, default to files
	return []NSSSwitchMethod{NSSSwitchMethodFiles}, nil
}
