//go:build !libcondor_utils

// Package oracle (stub build): without the `libcondor_utils` tag the C++ oracle
// is not linked, so the package still compiles (and `go vet ./...`, editors,
// and non-fuzz CI work) but MakeAds is unavailable. The differential test
// guards on Available and skips.
package oracle

// Available reports whether the C++ oracle is linked in (it is not, here).
const Available = false

// Mode mirrors the cgo build's type so callers compile either way.
type Mode int

// Mode values, mirroring the cgo build.
const (
	ModeAds Mode = iota
	ModePlacement
)

// Result mirrors the cgo build's type so callers compile either way.
type Result struct {
	OK    bool
	Ads   string
	Err   string
	Panic bool
}

// MakeAds panics: callers must check Available (or build with the
// libcondor_utils tag) before invoking the oracle.
func MakeAds(string, Mode, int) Result {
	panic("oracle.MakeAds: built without the libcondor_utils tag")
}
