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

package idmap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeAccounts builds a passwd fixture and returns a resolver over it.
func stripResolver(t *testing.T, body string, strip bool) *Resolver {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(&SystemAccounts{Path: path}, FileGecos{Path: path},
		WithStrategies(StrategyGecos), WithStripDomain(strip))
}

// The case this exists for: an ePPN is scoped, a GECOS is not.
func TestScopedSubjectMatchesAnUnscopedGecos(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n", true)

	got, err := r.Resolve(context.Background(), "bockelman@wisc.edu")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "bbockelm" {
		t.Errorf("Resolve = %q, want bbockelm", got)
	}
}

// The flag strips WHATEVER domain the token carried, so two providers'
// "bockelman" reach the same account. That is the property the deployment
// must constrain elsewhere -- by restricting which providers may log in --
// and asserting it here keeps it from being mistaken for per-domain
// filtering that this option does not do.
func TestAnyDomainIsStripped(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n", true)

	for _, subject := range []string{"bockelman@wisc.edu", "bockelman@anywhere.example"} {
		got, err := r.Resolve(context.Background(), subject)
		if err != nil || got != "bbockelm" {
			t.Errorf("Resolve(%q) = %q, %v; the flag strips any domain", subject, got, err)
		}
	}
}

// Without the option configured at all, nothing changes.
func TestScopedSubjectDoesNotMatchWhenStrippingIsOff(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n", false)
	if _, err := r.Resolve(context.Background(), "bockelman@wisc.edu"); !errors.Is(err, ErrNoMatch) {
		t.Errorf("err = %v, want ErrNoMatch when stripping is not configured", err)
	}
}

// The full subject is tried first, so an account whose GECOS really is
// the scoped form still wins and stripping can only add a fallback.
func TestTheFullSubjectWinsOverTheStrippedOne(t *testing.T) {
	body := "" +
		"scoped:x:20015:20015:bockelman@wisc.edu:/home/scoped:/bin/sh\n" +
		"bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n"
	r := stripResolver(t, body, true)

	got, err := r.Resolve(context.Background(), "bockelman@wisc.edu")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "scoped" {
		t.Errorf("Resolve = %q, want scoped: an exact GECOS match must beat the stripped fallback", got)
	}
}

// The local part is passed through exactly as asserted; only the domain
// is discarded. Matching of the local part itself is the resolver's
// ordinary, case-sensitive comparison.
func TestOnlyTheDomainIsDiscarded(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n", true)

	if got, err := r.Resolve(context.Background(), "bockelman@WISC.EDU"); err != nil || got != "bbockelm" {
		t.Errorf("Resolve = %q, %v; the domain's case must not matter", got, err)
	}
	if _, err := r.Resolve(context.Background(), "BOCKELMAN@wisc.edu"); err == nil {
		t.Error("a differently-cased local part matched; only the domain is discarded")
	}
}

// Degenerate scoped forms must not produce an empty local part, which
// would be a subject nobody asserted.
func TestDegenerateScopedSubjects(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014::/home/bbockelm:/bin/bash\n", true)
	for _, subject := range []string{"@wisc.edu", "bockelman@", "@"} {
		if _, err := r.Resolve(context.Background(), subject); err == nil {
			t.Errorf("Resolve(%q) succeeded; a degenerate subject must not match the empty GECOS", subject)
		}
	}
}
