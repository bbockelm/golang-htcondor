package mcpserver

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// validateTarEntryName mirrors httpserver.validateTarEntryName. We
// duplicate the function (rather than introduce a shared package)
// because the rule is tiny and stable; importing httpserver from
// mcpserver would invert the dependency direction. If the rule
// grows, lift it into a shared helper.
//
// See httpserver/tarvalidate.go for the full rationale.
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
		return fmt.Errorf("filename is not in canonical form (got %q, cleans to %q)", name, cleaned)
	}
	for _, segment := range strings.Split(cleaned, "/") {
		if segment == ".." {
			return errors.New("filename contains '..' segment")
		}
	}
	return nil
}
