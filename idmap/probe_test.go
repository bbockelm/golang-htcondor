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
	"testing"
)

// The reported incident, reproduced exactly.
//
//	clock:*:24144:24144:clock:/home/clock:/bin/bash
//
// The subject is "clock@wisc.edu", stripping is on, the GECOS is "clock",
// and the account resolves perfectly by name. It was refused because the
// enumeration that built the index had not listed it -- and the error told
// the user their GECOS was the problem.
func TestASubjectMissingFromTheIndexStillResolvesByName(t *testing.T) {
	// What the cold enumeration returned: a few container accounts, and
	// not the user's.
	cold := []Account{{Username: "root", Gecos: "root"}, {Username: "daemon", Gecos: ""}}
	// What getpwnam answers, which is everything.
	live := &fakeVerifier{gecos: map[string]string{
		"root": "root", "daemon": "", "clock": "clock", "bbockelm": "bockelman",
	}}
	r := New(&fakeEnum{accounts: cold}, live, WithStripDomain(true))

	got, err := r.Resolve(context.Background(), "clock@wisc.edu")
	if err != nil {
		t.Fatalf("Resolve(clock@wisc.edu): %v -- the account exists and its GECOS matches", err)
	}
	if got != "clock" {
		t.Errorf("Resolve = %q, want clock", got)
	}

	// Unscoped subjects too, for a deployment that does not strip.
	plain := New(&fakeEnum{accounts: cold}, live)
	if got, err := plain.Resolve(context.Background(), "clock"); err != nil || got != "clock" {
		t.Errorf("Resolve(clock) = %q, %v; want clock", got, err)
	}
}

// The probe is a guess CHECKED against the live database, not a guess
// accepted. An account whose GECOS is somebody else's identity -- or
// nobody's -- must still be refused, or the GECOS strategy would have
// quietly become "the subject is the username".
func TestTheProbeRefusesASubjectWhoseGecosDoesNotMatch(t *testing.T) {
	live := &fakeVerifier{gecos: map[string]string{
		// Exists, but its GECOS names somebody else.
		"mallory": "someone.else",
		// Exists with no GECOS at all: it maps to no subject.
		"blank": "",
		// Exists and matches, so the test is not simply refusing
		// everything.
		"clock": "clock",
	}}
	r := New(&fakeEnum{accounts: []Account{{Username: "root", Gecos: "root"}}}, live)

	for _, subject := range []string{"mallory", "blank", "ghost"} {
		got, err := r.Resolve(context.Background(), subject)
		if !errors.Is(err, ErrNoMatch) {
			t.Errorf("Resolve(%q) = %q, %v; want ErrNoMatch", subject, got, err)
		}
	}
	if got, err := r.Resolve(context.Background(), "clock"); err != nil || got != "clock" {
		t.Fatalf("Resolve(clock) = %q, %v; the probe rejects everything", got, err)
	}
}

// A GECOS is free text. Passing one to a by-name lookup as if it were a
// login name is how a "Full Name, Room, Phone" string, or worse, reaches
// a subprocess argument.
func TestTheProbeNeverLooksUpSomethingThatIsNotALoginName(t *testing.T) {
	// Says yes to any account, so the ONLY thing that can refuse these is
	// the syntax screen in front of the lookup.
	ver := &acceptAnything{}
	r := New(&fakeEnum{accounts: []Account{{Username: "root", Gecos: "root"}}}, ver)

	for _, bad := range []string{"../etc/shadow", "a:b", "Full Name", "two\nlines", "tab\there"} {
		if got, err := r.Resolve(context.Background(), bad); err == nil {
			t.Errorf("Resolve(%q) = %q; a malformed subject was probed as a login name", bad, got)
		}
	}
	if len(ver.asked) != 0 {
		t.Errorf("malformed subjects reached the verifier: %v", ver.asked)
	}
}

// The window the probe exists for is the one where the index does not
// exist yet at all: enumeration is failing, and every login would
// otherwise be refused.
func TestTheProbeAnswersWhenNoIndexCanBeBuilt(t *testing.T) {
	enum := &fakeEnum{err: errors.New("sssd is not answering")}
	r := New(enum, &fakeVerifier{gecos: map[string]string{"clock": "clock"}})

	got, err := r.Resolve(context.Background(), "clock")
	if err != nil || got != "clock" {
		t.Errorf("Resolve = %q, %v; the probe needs no index and this is where it matters most", got, err)
	}
	// And it does not turn an unreadable database into a free pass.
	if got, err := r.Resolve(context.Background(), "stranger"); err == nil {
		t.Errorf("Resolve(stranger) = %q while the database was unreadable", got)
	}
}

// Ambiguity the index CAN see still wins. The probe is a fallback for
// subjects the index knows nothing about, not an override -- a duplicate
// GECOS the index holds must keep refusing, because that refusal is the
// package's whole answer to two accounts claiming one identity.
func TestTheProbeDoesNotOverrideAVisibleAmbiguity(t *testing.T) {
	both := []Account{
		{Username: "clock", Gecos: "clock"},
		{Username: "clock-2", Gecos: "clock"},
	}
	r := New(&fakeEnum{accounts: both}, gecosOfAll(both))

	got, err := r.Resolve(context.Background(), "clock")
	if !errors.Is(err, ErrAmbiguous) {
		t.Errorf("Resolve = %q, %v; the probe resolved a GECOS the index knows is contested", got, err)
	}
}

// A stale index entry pointing at the wrong account must not block the
// right one. With entries retained for longer, this is the shape a
// renamed account leaves behind.
func TestAStaleIndexHitDoesNotBlockTheProbe(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{{Username: "old-clock", Gecos: "clock"}}}
	live := &fakeVerifier{gecos: map[string]string{
		// old-clock no longer carries the subject; the real account does.
		"old-clock": "retired",
		"clock":     "clock",
	}}
	r := New(enum, live)

	got, err := r.Resolve(context.Background(), "clock")
	if err != nil || got != "clock" {
		t.Errorf("Resolve = %q, %v; a stale index entry shadowed the account that actually matches", got, err)
	}
}

// Without a verifier there is nothing to check a guess against, so there
// is no probe. This is the configuration where the index IS the database.
func TestThereIsNoProbeWithoutAVerifier(t *testing.T) {
	r := New(&fakeEnum{accounts: []Account{{Username: "root", Gecos: "root"}}}, nil)

	if got, err := r.Resolve(context.Background(), "clock"); err == nil {
		t.Errorf("Resolve = %q with nothing to confirm it against", got)
	}
}
