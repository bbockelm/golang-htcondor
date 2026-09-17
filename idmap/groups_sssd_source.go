package idmap

// sssdGroupSource returns the native SSSD group reader.
//
// It connects lazily, so a machine with no SSSD costs one failed dial on
// first use and then falls through the chain. It is only ever reached
// when nsswitch.conf's `group:` line names sss, so a host without SSSD
// never asks for it in the first place.
func sssdGroupSource() GroupSource { return &SSSDGroups{} }
