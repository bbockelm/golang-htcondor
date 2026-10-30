//go:build libcondor_utils

// Package oracle wraps HTCondor's reference C++ submit-file parser (SubmitHash
// from libcondor_utils) and exposes it as an in-process Go function for
// differential fuzzing against the native Go submit package. The C++ work is
// done by shim.cc, which cgo compiles and links automatically.
//
// Machine-specific include/library paths are supplied via CGO_CXXFLAGS and
// CGO_LDFLAGS (see hack/submit-fuzz-env.sh); the directives below carry only
// the portable bits. Build/run with the `libcondor_utils` tag:
//
//	source hack/submit-fuzz-env.sh
//	go test -tags libcondor_utils ./fuzz/submit/...
//
// Crash isolation caveat: libcondor_utils runs in-process, so a hard crash
// (segfault/abort) there takes the whole process down. The shim catches C++
// exceptions, but a crash is itself a finding — drivers journal the input.
package oracle

/*
#cgo CXXFLAGS: -std=c++20
#cgo linux LDFLAGS: -lstdc++
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

// Available reports whether the C++ oracle is linked in (it is, under this tag).
const Available = true

// SubmitUser is the submitting account the oracle is pinned to
// (kSubmitUser in shim.cc). The Go side has to be given the same one:
// the accounting group a job is charged to is built from it.
const SubmitUser = "fuzzuser"

// Mode selects what the oracle emits.
type Mode int

const (
	// ModeAds emits each proc's complete job ad, parent chain merged in: the
	// ad condor_submit -dry-run shows.
	ModeAds Mode = C.SUBMIT_ORACLE_MODE_ADS
	// ModePlacement emits the cluster ad and each proc's own attributes only,
	// after the fold condor_submit does before sending the cluster ad: the
	// attribute placement the schedd stores.
	ModePlacement Mode = C.SUBMIT_ORACLE_MODE_PLACEMENT
)

// cppMu serializes calls into libcondor_utils. SubmitHash reaches global
// config/macro state, so we keep one call in flight.
var cppMu sync.Mutex

// Result is the outcome of running a submit file through the C++ oracle.
type Result struct {
	// OK is false when the C++ side rejected the submit file (a divergence if
	// the Go parser accepted it). Err then holds its message.
	OK bool
	// Ads is the canonical encoding described in shim.h, populated when OK.
	Ads string
	// Err is the C++ error message when the submit file was rejected.
	Err string
	// Panic is true when a C++ exception escaped the parser.
	Panic bool
}

// MakeAds parses text as a submit file and returns the resulting job ads.
// maxProcs caps how many procs are materialized.
func MakeAds(text string, mode Mode, maxProcs int) Result {
	cppMu.Lock()
	defer cppMu.Unlock()

	ctext := C.CString(text)
	defer C.free(unsafe.Pointer(ctext))

	var out *C.char
	rc := C.submit_make_ads(ctext, C.int(mode), C.int(maxProcs), &out)
	var s string
	if out != nil {
		s = C.GoString(out)
		C.submit_oracle_free(out)
	}

	switch rc {
	case 1:
		return Result{OK: true, Ads: s}
	case 0:
		return Result{Err: s}
	default:
		return Result{Panic: true, Err: s}
	}
}

// Keyword is one entry of HTCondor's own submit-keyword table.
type Keyword struct {
	// Key is the submit-file command, e.g. "request_cpus".
	Key string
	// Attr is the job attribute it sets, empty when there is no single one.
	Attr string
	// Opts is the SimpleSubmitKeyword flag word: value type, file role and
	// special-parsing bits.
	Opts int
}

// Bits of Keyword.Opts, from SimpleSubmitKeyword in submit_utils.cpp.
//
// The value type is the low five bits; f_as_expr is the absence of all of them,
// so a keyword with none of these takes a ClassAd expression. The bits above
// that are modifiers, not types: they say the keyword is an alternate spelling
// of another, or that using it is an error, not what shape its value has.
const (
	KeyAsBool   = 0x01
	KeyAsInt    = 0x02
	KeyAsUint   = 0x04
	KeyAsString = 0x08
	KeyAsList   = 0x10
	KeyTypeMask = 0x1f

	KeyStripQuotes = 0x20  // f_strip_quotes
	KeyError       = 0x40  // f_error: using this keyword is rejected
	KeyAltName     = 0x80  // f_alt_name: another spelling of a previous keyword
	KeyFileMask    = 0x700 // f_filemask: the value names a file
	KeySpecial     = 0x20000
)

// Keywords returns the submit-keyword table the linked HTCondor exposes via
// get_submit_keywords(), so the fuzzer's vocabulary comes from the parser under
// test rather than a hand-maintained list. Returns nil if the table looks wrong.
func Keywords() []Keyword {
	cppMu.Lock()
	defer cppMu.Unlock()

	var out *C.char
	rc := C.submit_keyword_table(&out)
	if out == nil {
		return nil
	}
	s := C.GoString(out)
	C.submit_oracle_free(out)
	if rc != 1 {
		return nil
	}

	var kws []Keyword
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\x1f")
		if len(parts) != 3 {
			continue
		}
		opts, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		kws = append(kws, Keyword{Key: parts[0], Attr: parts[1], Opts: opts})
	}
	return kws
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
	// condor_submit's clamp: an unspecified limit becomes the total job
	// count, and the result is never below one.
	MaxMaterialize int64
	// TotalProcs is how many jobs the queue statement asks for.
	TotalProcs int64
	// Vars are the queue statement's loop variables.
	Vars []string
	// Items are the itemdata rows as SendMaterializeData would send them --
	// multi-field rows joined with \x1f -- minus the newline each carries on
	// the wire. Capped by the caller's maxItems.
	Items []string
	// Digest is the submit digest, which keeps macro references unexpanded
	// so the schedd can expand them per proc, and ends with the queue
	// statement the schedd iterates.
	Digest string
	Err    string
	Panic  bool
}

// Factory reports what a late-materialization submission of text would send.
//
// itemsFilename stands in for the spooled itemdata path the schedd returns
// from SendMaterializeData, which the queue statement at the end of the digest
// names; it is ignored when the queue statement has no items.
func Factory(text string, maxItems int, itemsFilename string) FactoryInfo {
	cppMu.Lock()
	defer cppMu.Unlock()

	ctext := C.CString(text)
	defer C.free(unsafe.Pointer(ctext))
	cfile := C.CString(itemsFilename)
	defer C.free(unsafe.Pointer(cfile))

	var out *C.char
	rc := C.submit_factory_info(ctext, C.int(maxItems), cfile, &out)
	var raw string
	if out != nil {
		raw = C.GoString(out)
		C.submit_oracle_free(out)
	}
	switch rc {
	case 1:
		return parseFactoryInfo(raw)
	case 0:
		return FactoryInfo{Err: raw}
	default:
		return FactoryInfo{Panic: true, Err: raw}
	}
}

func parseFactoryInfo(raw string) FactoryInfo {
	fi := FactoryInfo{OK: true}
	var digest strings.Builder
	inDigest := false
	for _, line := range strings.Split(raw, "\n") {
		switch {
		case line == "#digest":
			inDigest = true
		case line == "#enddigest":
			inDigest = false
		case inDigest:
			digest.WriteString(line)
			digest.WriteString("\n")
		case line == "#factory 1":
			fi.Factory = true
		case strings.HasPrefix(line, "#max_materialize "):
			n, err := strconv.ParseInt(strings.TrimPrefix(line, "#max_materialize "), 10, 64)
			if err == nil {
				fi.MaxMaterialize = n
			}
		case strings.HasPrefix(line, "#total_procs "):
			n, err := strconv.ParseInt(strings.TrimPrefix(line, "#total_procs "), 10, 64)
			if err == nil {
				fi.TotalProcs = n
			}
		case strings.HasPrefix(line, "#vars "):
			v := strings.TrimPrefix(line, "#vars ")
			if v != "" {
				fi.Vars = strings.Split(v, ",")
			}
		case strings.HasPrefix(line, "#item\x1f"):
			fi.Items = append(fi.Items, strings.TrimPrefix(line, "#item\x1f"))
		}
	}
	// Every line of the digest region is written back with the newline it
	// had, so this is the digest byte for byte -- including the trailing
	// newline append_queue_statement leaves on it, which the schedd's parser
	// needs to see the queue statement as a complete line.
	fi.Digest = digest.String()
	return fi
}
