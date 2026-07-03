//go:build libcondor_utils

// Package oracle wraps HTCondor's reference C++ config parser (libcondor_utils)
// and exposes it as an in-process Go function for differential fuzzing against
// the native Go config package. The C++ work is done by shim.cc, which cgo
// compiles and links automatically.
//
// Machine-specific include/library paths are supplied via CGO_CXXFLAGS and
// CGO_LDFLAGS (see hack/config-fuzz-env.sh); the directives below carry only
// the portable bits. Build/run with the `libcondor_utils` tag:
//
//	source hack/config-fuzz-env.sh
//	go test -tags libcondor_utils ./fuzz/config/...
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
	"sync"
	"unsafe"
)

// Available reports whether the C++ oracle is linked in (it is, under this tag).
const Available = true

// cppMu serializes calls into libcondor_utils. The config parser is not written
// for concurrent use from multiple threads, so we keep one call in flight.
var cppMu sync.Mutex

// Result is the outcome of parsing a config source with the C++ oracle.
type Result struct {
	// Parsed is false when Parse_config_string reported an error (a divergence
	// if the Go parser accepted the same input).
	Parsed bool
	// Table is the canonical "KEY\x1Fvalue\n" encoding of the expanded macro
	// set, populated only when Parsed is true.
	Table string
	// Panic is true when a C++ exception escaped the parser.
	Panic bool
}

// ParseExpand parses text with the C++ reference parser (fresh MACRO_SET, NULL
// defaults) and returns the canonical expanded table.
func ParseExpand(text string) Result {
	cppMu.Lock()
	defer cppMu.Unlock()

	ctext := C.CString(text)
	defer C.free(unsafe.Pointer(ctext))

	var out *C.char
	rc := C.config_parse_expand(ctext, &out)
	if out != nil {
		defer C.config_free(out)
	}

	switch rc {
	case 1:
		return Result{Parsed: true, Table: C.GoString(out)}
	case 0:
		return Result{Parsed: false}
	default:
		return Result{Parsed: false, Panic: true}
	}
}
