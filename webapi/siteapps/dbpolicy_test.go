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

package siteapps

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// fixedPolicy is a source stating one answer, for the chain tests.
type fixedPolicy map[string]Policy

func (f fixedPolicy) Policy(id string) (Policy, bool) {
	p, ok := f[id]
	return p, ok
}

func (f fixedPolicy) DeclaredIDs() []string {
	out := make([]string, 0, len(f))
	for id := range f {
		out = append(out, MacroID(id))
	}
	slices.Sort(out)
	return out
}

// The whole point of a chain: an id the configuration names is the
// configuration's, and the later source is not consulted for it. If
// this ever merged instead, an administrator could widen the groups on
// an app the operator had scoped -- which is the thing keeping policy
// in the configuration exists to prevent.
func TestConfigurationWinsOverAnUpload(t *testing.T) {
	cfg := fixedPolicy{"cryoem": {Groups: []string{"smith_lab"}, Origin: "config"}}
	uploaded := fixedPolicy{"cryoem": {Groups: []string{"everyone", "smith_lab"}, Origin: OriginUpload}}

	got, ok := Chain{cfg, uploaded}.Policy("cryoem")
	if !ok {
		t.Fatal("the chain published nothing for an id both sources name")
	}
	if len(got.Groups) != 1 || got.Groups[0] != "smith_lab" {
		t.Errorf("groups = %v, want only the configuration's", got.Groups)
	}
	if got.Origin != "config" {
		t.Errorf("origin = %q, want the configuration's", got.Origin)
	}
}

// An id only the upload names is served from the upload. Without this
// the second source would be decoration.
func TestUploadDecidesWhatTheConfigurationDoesNot(t *testing.T) {
	cfg := fixedPolicy{"cryoem": {Groups: []string{"smith_lab"}}}
	uploaded := fixedPolicy{"seqqc": {Groups: []string{"jones_lab"}, Origin: OriginUpload}}

	got, ok := Chain{cfg, uploaded}.Policy("seqqc")
	if !ok {
		t.Fatal("an app only the upload names was not published")
	}
	if got.Origin != OriginUpload {
		t.Errorf("origin = %q, want the upload's", got.Origin)
	}
}

// An app nobody names is not published. Fail-closed has to survive
// having more than one way to say yes.
func TestChainPublishesNothingNobodyNames(t *testing.T) {
	c := Chain{fixedPolicy{}, fixedPolicy{}}
	if _, ok := c.Policy("cryoem"); ok {
		t.Error("an app no source names was published")
	}
	if ids := c.DeclaredIDs(); len(ids) != 0 {
		t.Errorf("DeclaredIDs = %v, want none", ids)
	}
}

// A nil source in the chain is skipped rather than panicking: the
// upload source is nil on a server with no database, which is the
// demo server and most tests.
func TestChainSkipsAMissingSource(t *testing.T) {
	c := Chain{nil, fixedPolicy{"cryoem": {Groups: []string{"lab"}}}, nil}
	if _, ok := c.Policy("cryoem"); !ok {
		t.Error("a chain with a nil source published nothing")
	}
}

// DeclaredIDs is the union, deduplicated: it drives the loader's
// "policy names a bundle that is not here" report, and an id named
// twice must not be reported twice.
func TestChainDeclaredIDsAreTheUnion(t *testing.T) {
	c := Chain{
		fixedPolicy{"cryoem": {Groups: []string{"a"}}, "shared": {Groups: []string{"a"}}},
		fixedPolicy{"seqqc": {Groups: []string{"b"}}, "shared": {Groups: []string{"b"}}},
	}
	got := c.DeclaredIDs()
	want := []string{"CRYOEM", "SEQQC", "SHARED"}
	if !slices.Equal(got, want) {
		t.Errorf("DeclaredIDs = %v, want %v", got, want)
	}
}

// An upload row with no groups publishes nothing, the same as an empty
// GROUPS in the configuration. Both are far more likely a mistake than
// a request to publish to nobody.
func TestUploadWithNoGroupsPublishesNothing(t *testing.T) {
	p := &DBPolicy{}
	snap := map[string]Policy{"cryoem": {Groups: nil, Origin: OriginUpload}}
	p.snap.Store(&snap)

	if _, ok := p.Policy("cryoem"); ok {
		t.Error("an upload naming no groups was published")
	}
	if ids := p.DeclaredIDs(); len(ids) != 0 {
		t.Errorf("DeclaredIDs = %v, want none for a row naming no groups", ids)
	}
}

// refreshable counts Refresh calls.
type refreshable struct {
	fixedPolicy
	calls int
}

func (r *refreshable) Refresh(context.Context) error {
	r.calls++
	return nil
}

// The loader refreshes the source it holds, and in every real
// deployment that source is a Chain. A Chain that did not pass Refresh
// along left the database-backed member never read: uploads were
// accepted, written and recorded, and then never published, with
// nothing in the log to say why. That is what this pins.
func TestChainRefreshesItsMembers(t *testing.T) {
	inner := &refreshable{fixedPolicy: fixedPolicy{"cryoem": {Groups: []string{"lab"}}}}
	c := Chain{fixedPolicy{}, inner, nil}

	r, ok := any(c).(interface{ Refresh(context.Context) error })
	if !ok {
		t.Fatal("Chain does not satisfy the loader's refresh hook, so a database-backed source is never read")
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if inner.calls != 1 {
		t.Errorf("member refreshed %d times, want once", inner.calls)
	}
}

// A member that cannot be refreshed is reported, and the others are
// still refreshed: one unreadable source must not stop the rest.
func TestChainRefreshReportsAndContinues(t *testing.T) {
	bad := &failingRefresh{}
	good := &refreshable{fixedPolicy: fixedPolicy{}}
	c := Chain{bad, good}

	if err := c.Refresh(context.Background()); err == nil {
		t.Error("a failing member was not reported")
	}
	if good.calls != 1 {
		t.Errorf("the healthy member refreshed %d times, want once", good.calls)
	}
}

type failingRefresh struct{ fixedPolicy }

func (f *failingRefresh) Refresh(context.Context) error {
	return errRefresh
}

var errRefresh = errors.New("unreadable")
