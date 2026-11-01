//go:build unix

package config

import (
	"strings"

	"golang.org/x/sys/unix"
)

// unameValues returns uname's own strings, untouched. sysapi stores
// buf.machine and buf.sysname verbatim and HTCondor publishes them that way,
// so no case folding happens here.
func unameValues() utsname {
	var buf unix.Utsname
	if err := unix.Uname(&buf); err != nil {
		return utsname{}
	}
	return utsname{
		Sysname:  utsString(buf.Sysname[:]),
		Nodename: utsString(buf.Nodename[:]),
		Release:  utsString(buf.Release[:]),
		Version:  utsString(buf.Version[:]),
		Machine:  utsString(buf.Machine[:]),
	}
}

// utsString trims the NUL padding a utsname field carries.
func utsString(field []byte) string {
	return strings.TrimRight(string(field), "\x00")
}
