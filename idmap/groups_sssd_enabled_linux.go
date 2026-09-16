//go:build linux

package idmap

// sssdGroupSource returns the native SSSD group reader. It connects
// lazily, so a machine without SSSD costs one failed dial on the first
// lookup and then falls through the chain.
func sssdGroupSource() GroupSource { return &SSSDGroups{} }
