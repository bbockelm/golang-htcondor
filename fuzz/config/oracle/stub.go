//go:build !libcondor_utils

// Package oracle (stub build): without the `libcondor_utils` tag the C++ oracle
// is not linked, so the package still compiles (and `go vet ./...`, editors,
// and non-fuzz CI work) but ParseExpand is unavailable. The differential test
// guards on Available and skips.
package oracle

// Available reports whether the C++ oracle is linked in (it is not, here).
const Available = false

// Result mirrors the cgo build's type so callers compile either way.
type Result struct {
	Parsed bool
	Table  string
	Panic  bool
}

// ParseExpand panics: callers must check Available (or build with the
// libcondor_utils tag) before invoking the oracle.
func ParseExpand(string) Result {
	panic("oracle.ParseExpand: built without the libcondor_utils tag")
}
