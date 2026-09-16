//go:build !linux

package idmap

// sssdGroupSource returns nothing off Linux: SSSD's socket protocol is a
// Linux arrangement, and the chain starts at id(1) instead.
func sssdGroupSource() GroupSource { return nil }
