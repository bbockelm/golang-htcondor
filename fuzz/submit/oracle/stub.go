//go:build !libcondor_utils

// Package oracle (stub build): without the `libcondor_utils` tag the C++ oracle
// is not linked, so the package still compiles (and `go vet ./...`, editors,
// and non-fuzz CI work) but MakeAds is unavailable. The differential test
// guards on Available and skips.
package oracle

// Available reports whether the C++ oracle is linked in (it is not, here).
const Available = false

// SubmitUser is the submitting account the oracle is pinned to
// (kSubmitUser in shim.cc). The Go side has to be given the same one:
// the accounting group a job is charged to is built from it.
const SubmitUser = "fuzzuser"

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

// Keyword mirrors the cgo build's type so callers compile either way.
type Keyword struct {
	Key  string
	Attr string
	Opts int
}

// Bits of Keyword.Opts, mirroring the cgo build.
const (
	KeyAsBool   = 0x01
	KeyAsInt    = 0x02
	KeyAsUint   = 0x04
	KeyAsString = 0x08
	KeyAsList   = 0x10
	KeyTypeMask = 0x1f

	KeyStripQuotes = 0x20
	KeyError       = 0x40
	KeyAltName     = 0x80
	KeyFileMask    = 0x700
	KeySpecial     = 0x20000
)

// Keywords panics: callers must check Available before invoking the oracle.
func Keywords() []Keyword {
	panic("oracle.Keywords: built without the libcondor_utils tag")
}

// FactoryInfo is what condor_submit would send for a late-materialization
// (job factory) submission: the client-side decision, the materialize limit,
// the queue statement's loop variables and itemdata rows, and the submit
// digest the schedd expands per proc.
type FactoryInfo struct {
	// OK is false when the C++ side rejected the submit file; Err holds why.
	OK bool
	// Factory is want_factory_submit(): the submission is a job factory
	// because the file set max_materialize, max_idle or materialize_max_idle.
	Factory bool
	// MaxMaterialize is the limit sent to SetJobFactory, after
	// condor_submit's clamp.
	MaxMaterialize int64
	// TotalProcs is how many jobs the queue statement asks for.
	TotalProcs int64
	// Vars are the queue statement's loop variables.
	Vars []string
	// Items are the itemdata rows as SendMaterializeData would send them,
	// capped by the caller's maxItems.
	Items []string
	// Digest is the submit digest, which keeps macro references unexpanded
	// so the schedd can expand them per proc.
	Digest string
	Err    string
	Panic  bool
}

// Factory panics: callers must check Available before invoking the oracle.
func Factory(string, int, string) FactoryInfo {
	panic("oracle.Factory: built without the libcondor_utils tag")
}
