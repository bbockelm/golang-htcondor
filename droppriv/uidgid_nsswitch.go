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

		// Look for the passwd line
		if !strings.HasPrefix(line, "passwd:") {
			continue
		}

		// Parse the methods after "passwd:"
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
