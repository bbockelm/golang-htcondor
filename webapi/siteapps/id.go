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
	// Must begin and end with a letter or digit. This rules out the
	// leading dot that every scratch and editor-backup file in the
	// bundle directory carries, so a name that is not meant to be a
	// bundle cannot become one even if something manages to offer it
	// to the loader. It also keeps ids from looking like flags or
	// relative paths to whatever reads a log line containing one.
	if !isIDAlnum(rune(id[0])) || !isIDAlnum(rune(id[len(id)-1])) {
		return fmt.Errorf("site app id %q must begin and end with a lowercase letter or digit", id)
	}
	for _, r := range id {
		if isIDAlnum(r) || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("site app id %q contains %q; ids may use only "+
			"lowercase letters, digits, hyphen and underscore", id, r)
	}
	return nil
}

func isIDAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}
