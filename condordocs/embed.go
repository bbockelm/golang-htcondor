//go:build embed_condor_docs

package condordocs

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var content embed.FS

func docsFS() (fs.FS, error) {
	return fs.Sub(content, "dist")
}

// IsEmbedded reports whether the docs are compiled into this binary.
func IsEmbedded() bool { return true }
