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

package sshgateway

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/interactive"
)

func TestParseTargetJobIDs(t *testing.T) {
	for _, tc := range []struct {
		in            string
		cluster, proc int
	}{
		{"12345.0", 12345, 0},
		{"12345.7", 12345, 7},
		{"12345", 12345, 0},
		{"0.0", 0, 0},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTarget(tc.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !got.IsJob() {
				t.Fatalf("%q parsed as %v, want a job", tc.in, got)
			}
			if got.Cluster != tc.cluster || got.Proc != tc.proc {
				t.Errorf("= %d.%d, want %d.%d", got.Cluster, got.Proc, tc.cluster, tc.proc)
			}
		})
	}
}

func TestParseTargetSessionNames(t *testing.T) {
	for _, in := range []string{"work", "build-2", "my.session", "a_b"} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseTarget(in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.IsJob() {
				t.Fatalf("%q parsed as a job", in)
			}
			if got.Name != in {
				t.Errorf("name = %q, want %q", got.Name, in)
			}
		})
	}
}

// Atoi accepts things a job id never contains. A signed or padded
// number must not become a cluster, because it would silently reach a
// different job than the one the text names.
func TestParseTargetRejectsNumbersThatAreNotJobIDs(t *testing.T) {
	for _, in := range []string{"+5", "-5", "5 ", " 5", "5.+0", "5.-1", "0x10"} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseTarget(in)
			if err == nil && got.IsJob() {
				t.Fatalf("%q parsed as job %d.%d", in, got.Cluster, got.Proc)
			}
		})
	}
}

// Every username a client can send has to produce a session, because
// a bare `ssh gateway` sends whatever the local login happens to be
// and the person cannot act on "that is not a valid session name".
//
// The derived name must satisfy the interactive package's own
// validator: it is spliced into a submit file and a batch name, so a
// name that only this package considers usable would fail later, at
// submit, with a worse message.
func TestAnyUsernameProducesAUsableSession(t *testing.T) {
	for _, in := range []string{
		"work",
		"_appstore",              // a real macOS system login
		"bob@wisc.edu",           // an eppn as a username
		"Brian Bockelman",        // a space
		"-leading",               // cannot start a session name
		"...",                    // nothing but separators
		"@@@",                    // nothing usable at all
		"ünïcodé",                // outside the pattern entirely
		strings.Repeat("x", 200), // longer than the limit
		"5 ",                     // padded, so not a job id
		"+5",
	} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseTarget(in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.IsJob() {
				t.Fatalf("%q parsed as a job", in)
			}
			if err := interactive.ValidateSessionName(got.Name); err != nil {
				t.Errorf("derived name %q is not usable: %v", got.Name, err)
			}
			if got.Raw != in {
				t.Errorf("Raw = %q, want the username verbatim", got.Raw)
			}
		})
	}
}

// A name that is already usable must survive untouched: `ssh
// work@gateway` has to reach the session called "work" and nothing
// else.
func TestUsableNamesAreNotRewritten(t *testing.T) {
	for _, in := range []string{"work", "build-2", "my.session", "a_b", "W0rk"} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseTarget(in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.Name != in {
				t.Errorf("name = %q, want it unchanged", got.Name)
			}
		})
	}
}

// Deterministic, so the same laptop reaches the same session every
// time; distinct, so two unrelated logins do not land in one.
func TestDerivedNamesAreStableAndDistinct(t *testing.T) {
	first, _ := ParseTarget("@@@")
	again, _ := ParseTarget("@@@")
	other, _ := ParseTarget("###")

	if first.Name != again.Name {
		t.Errorf("the same username produced %q then %q", first.Name, again.Name)
	}
	if first.Name == other.Name {
		t.Errorf("two different usernames both produced %q", first.Name)
	}
}

// Only a username that is not there at all is refused, and an SSH
// client always sends one.
func TestEmptyTargetIsRefused(t *testing.T) {
	if _, err := ParseTarget(""); err == nil {
		t.Fatal("an empty username was accepted")
	}
}

// The truncation length has to be the validator's, or a name this
// package considers fine fails at submit instead.
func TestDerivedNameLengthMatchesTheValidator(t *testing.T) {
	name := sessionNameFor(strings.Repeat("a", sessionNameMaxLen+50))
	if len(name) != sessionNameMaxLen {
		t.Fatalf("truncated to %d, want %d", len(name), sessionNameMaxLen)
	}
	if err := interactive.ValidateSessionName(name); err != nil {
		t.Errorf("a name of exactly the limit is refused: %v", err)
	}
	if err := interactive.ValidateSessionName(name + "a"); err == nil {
		t.Error("the validator accepts one more than the limit, so the constant is wrong")
	}
}
