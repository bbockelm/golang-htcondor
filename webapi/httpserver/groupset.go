// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"strings"
	"sync/atomic"
)

// groupSet is an authorization group list that a reconfigure can replace
// while requests are reading it.
//
// Every one of these is consulted on a hot path -- each login, each admin
// page, each superuser action -- and SIGHUP rewrites them from another
// goroutine. The value is therefore swapped as a whole through an atomic
// pointer rather than mutated in place: a reader sees either the old list
// or the new one, never a half-updated one, and pays no lock on the read.
type groupSet struct {
	v atomic.Pointer[[]string]
}

// parseGroupList splits a configured group list.
//
// Commas separate; surrounding whitespace is trimmed, because a list
// written to be read by a human ("chtc_staff, chtc_admin") should mean
// what it looks like. Empty entries are dropped, so a trailing comma is
// not a group named "".
func parseGroupList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	groups := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			groups = append(groups, p)
		}
	}
	if len(groups) == 0 {
		return nil
	}
	return groups
}

// newGroupSet builds a set from a configured list.
func newGroupSet(raw string) *groupSet {
	g := &groupSet{}
	g.set(raw)
	return g
}

// set replaces the list. Safe to call while requests are reading.
func (g *groupSet) set(raw string) {
	groups := parseGroupList(raw)
	g.v.Store(&groups)
}

// list returns the configured groups.
func (g *groupSet) list() []string {
	if g == nil {
		return nil
	}
	p := g.v.Load()
	if p == nil {
		return nil
	}
	return *p
}

// configured reports whether any group is required at all.
func (g *groupSet) configured() bool { return len(g.list()) > 0 }

// allows reports whether the user holds ANY of the required groups.
//
// An unconfigured set allows everyone: these knobs are opt-in, and an
// empty one has always meant "no group requirement" rather than "nobody".
//
// Membership is compared case-insensitively, as it was when each of these
// was a single group -- Unix group names and directory-sourced ones do not
// reliably agree on case.
func (g *groupSet) allows(userGroups []string) bool {
	required := g.list()
	if len(required) == 0 {
		return true
	}
	for _, r := range required {
		for _, u := range userGroups {
			if strings.EqualFold(u, r) {
				return true
			}
		}
	}
	return false
}

// String renders the list for logs and operator-facing messages.
func (g *groupSet) String() string { return strings.Join(g.list(), ", ") }
