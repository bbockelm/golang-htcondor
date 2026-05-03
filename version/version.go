// Package version exposes build-time version information for the
// golang-htcondor binaries.
//
// The Version and Commit variables are set at build time via -ldflags;
// see the Makefile for the values that get injected.
package version

// Build-time variables. Override via -ldflags "-X .../version.Version=..." etc.
var (
	Version = "dev"
	Commit  = "unknown"
)

// Info is the structured build information returned by the API.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Get returns the current build information.
func Get() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
	}
}
