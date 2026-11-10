//go:build !unix

package config

// unameValues has nothing to read where there is no uname. HTCondor does not
// define the UTSNAME_* macros on Windows either.
func unameValues() utsname {
	return utsname{}
}
