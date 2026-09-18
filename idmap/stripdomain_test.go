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
func stripResolver(t *testing.T, body string, domains ...string) *Resolver {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := []Option{WithStrategies(StrategyGecos)}
	if len(domains) > 0 {
		opts = append(opts, WithStripDomains(domains...))
	}
	return New(&SystemAccounts{Path: path}, FileGecos{Path: path}, opts...)
}

// The case this exists for: an ePPN is scoped, a GECOS is not.
func TestScopedSubjectMatchesAnUnscopedGecos(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n", "wisc.edu")

	got, err := r.Resolve(context.Background(), "bockelman@wisc.edu")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "bbockelm" {
		t.Errorf("Resolve = %q, want bbockelm", got)
	}
}

// A domain that was not listed is left whole, so it simply does not
// match. Stripping blindly would let bockelman@anywhere.example claim
// this account.
func TestAnUnlistedDomainIsNotStripped(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n", "wisc.edu")

	if _, err := r.Resolve(context.Background(), "bockelman@elsewhere.example"); !errors.Is(err, ErrNoMatch) {
		t.Errorf("err = %v, want ErrNoMatch: an unlisted domain must not be stripped", err)
	}
}

func TestStripDomainsWildcard(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n", "*")
	got, err := r.Resolve(context.Background(), "bockelman@anywhere.example")
	if err != nil || got != "bbockelm" {
		t.Errorf("Resolve = %q, %v; \"*\" should strip any domain", got, err)
	}
}

// Without the option configured at all, nothing changes.
func TestScopedSubjectDoesNotMatchWhenStrippingIsOff(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n")
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
	r := stripResolver(t, body, "wisc.edu")

	got, err := r.Resolve(context.Background(), "bockelman@wisc.edu")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "scoped" {
		t.Errorf("Resolve = %q, want scoped: an exact GECOS match must beat the stripped fallback", got)
	}
}

// Domain comparison is case-insensitive, as DNS is.
func TestStripDomainIsCaseInsensitive(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/bash\n", "WISC.edu")
	if got, err := r.Resolve(context.Background(), "bockelman@wisc.EDU"); err != nil || got != "bbockelm" {
		t.Errorf("Resolve = %q, %v; domain matching should ignore case", got, err)
	}
}

// Degenerate scoped forms must not produce an empty local part, which
// would be a subject nobody asserted.
func TestDegenerateScopedSubjects(t *testing.T) {
	r := stripResolver(t, "bbockelm:x:20014:20014::/home/bbockelm:/bin/bash\n", "*")
	for _, subject := range []string{"@wisc.edu", "bockelman@", "@"} {
		if _, err := r.Resolve(context.Background(), subject); err == nil {
			t.Errorf("Resolve(%q) succeeded; a degenerate subject must not match the empty GECOS", subject)
		}
	}
}
