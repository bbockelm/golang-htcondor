package siteapps

import (
	"fmt"
	"strings"
)

// maxIDLen bounds an app id. It becomes a URL path segment and a file
// name; nothing legible needs more.
const maxIDLen = 64

// ValidateID checks a candidate app id.
//
// The id is derived from the bundle's file name and used, unescaped,
// as a URL path segment and as a map key. The character set is
// therefore the intersection of what is unambiguous in both: lowercase
// letters, digits, hyphen and underscore. Rejecting at load time means
// no request handler has to wonder whether an id can contain a slash.
//
// Ids beginning with "_" are reserved for the server's own paths under
// /site/ (_shell.js, the switcher). A bundle named _shell.zip is
// refused rather than being allowed to shadow them.
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("site app id is empty")
	}
	if len(id) > maxIDLen {
		return fmt.Errorf("site app id %q is longer than %d characters", id, maxIDLen)
	}
	if strings.HasPrefix(id, "_") {
		return fmt.Errorf("site app id %q begins with an underscore, which is reserved "+
			"for this server's own paths under /site/", id)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return fmt.Errorf("site app id %q contains %q; ids may use only "+
				"lowercase letters, digits, hyphen and underscore", id, r)
		}
	}
	return nil
}
