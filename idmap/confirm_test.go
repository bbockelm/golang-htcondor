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
	"testing"
)

// The asymmetry the whole hint rests on: an account can be confirmed by
// name even when the account database cannot be enumerated at all. That is
// what makes a returning user resolvable in the window where SSSD answers
// getpwnam but not getpwent.
func TestConfirmAnswersWhenEnumerationCannot(t *testing.T) {
	enum := &fakeEnum{err: unreachableDirectory()}
	r := New(enum, &fakeVerifier{gecos: map[string]string{"bbockelm": "bockelman"}})

	if !r.Confirm(context.Background(), "bockelman", "bbockelm") {
		t.Error("a known account could not be confirmed while enumeration was failing")
	}
	if enum.calls != 0 {
		t.Errorf("the enumerator was called %d times; confirming must not need it", enum.calls)
	}
}

// A proposal for the wrong account is refused. This is what makes a forged
// hint useless: naming somebody else's account only works if that account
// already carries the attacker's own subject as its GECOS.
func TestConfirmRefusesAnAccountThatDoesNotCarryTheSubject(t *testing.T) {
	r := New(&fakeEnum{}, &fakeVerifier{gecos: map[string]string{
		"bbockelm": "bockelman",
		"tannenba": "tatannen",
	}})

	if r.Confirm(context.Background(), "bockelman", "tannenba") {
		t.Error("confirmed an account whose GECOS is somebody else's subject")
	}
	if r.Confirm(context.Background(), "bockelman", "nosuchaccount") {
		t.Error("confirmed an account the database does not know")
	}
}

// Confirmation must accept exactly what Resolve would, or a hint could be
// accepted where a full resolution refuses -- or refused where it succeeds,
// which would silently make the hint useless for scoped subjects.
func TestConfirmAppliesTheSameDomainStripping(t *testing.T) {
	verifier := &fakeVerifier{gecos: map[string]string{"bbockelm": "bockelman"}}

	off := New(&fakeEnum{}, verifier)
	if off.Confirm(context.Background(), "bockelman@wisc.edu", "bbockelm") {
		t.Error("stripped the domain without being configured to")
	}

	on := New(&fakeEnum{}, verifier, WithStripDomain(true))
	if !on.Confirm(context.Background(), "bockelman@wisc.edu", "bbockelm") {
		t.Error("did not strip the domain, so a scoped subject could never use a hint")
	}
}

// With no verifier there is nothing to confirm against, and a proposal
// must not be taken on trust.
func TestConfirmRefusesWithoutAVerifier(t *testing.T) {
	r := New(&fakeEnum{}, nil)
	if r.Confirm(context.Background(), "bockelman", "bbockelm") {
		t.Error("a proposal was accepted with nothing to check it against")
	}
}
