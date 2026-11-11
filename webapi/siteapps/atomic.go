package siteapps

import "sync/atomic"

// atomicSnapshot is a typed atomic.Pointer to a snapshot, kept in its
// own file so library.go reads as policy rather than as plumbing.
type atomicSnapshot struct {
	p atomic.Pointer[snapshot]
}

func (a *atomicSnapshot) load() *snapshot   { return a.p.Load() }
func (a *atomicSnapshot) store(s *snapshot) { a.p.Store(s) }
