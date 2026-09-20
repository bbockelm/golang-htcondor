// Package nullfile identifies HTCondor's null file: the name a job ad
// carries for a standard stream that is not a real file.
//
// This is the Go counterpart of nullFile() in
// src/condor_utils/nullfile.cpp. HTCondor has no separate "this stream
// is unused" flag; condor_submit canonicalizes an unnamed stdin, stdout
// or stderr to the null file name and every consumer string-matches it.
// A job submitted by condor_submit therefore always carries In, Out and
// Err, and for most jobs at least one of them is the null file -- so
// code that treats "the attribute is missing" as the only way a stream
// can be unused mishandles the common case rather than an edge one.
package nullfile

import (
	"runtime"
	"strings"
)

const (
	// unixName is UNIX_NULL_FILE from
	// src/condor_includes/condor_constants.h. condor_submit writes this
	// name on every platform: a Windows submit canonicalizes to it too,
	// and the starter translates it locally.
	unixName = "/dev/null"

	// windowsName is the null device's name on Windows, which
	// nullfile.cpp matches case-insensitively -- but only in code
	// compiled for Windows.
	windowsName = "NUL"
)

// Is reports whether name is the null file.
//
// The empty string is NOT the null file. nullfile.cpp matches names, not
// absences, and an unset or empty stream name means only that nobody
// said anything -- callers that also want to treat that as "no file"
// have to say so separately. Conflating the two is how an empty name
// ends up being resolved against the sandbox root and walked as if it
// were a real path.
func Is(name string) bool {
	return is(name, runtime.GOOS)
}

// is carries the OS as a parameter so both arms are reachable from a
// test on any host.
func is(name, goos string) bool {
	if name == unixName {
		return true
	}
	// The NUL arm sits inside #ifdef WIN32 in nullfile.cpp, so it is
	// the running platform that decides, not the job ad.
	return goos == "windows" && strings.EqualFold(name, windowsName)
}
