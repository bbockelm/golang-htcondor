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

// Every username a client can send has to produce a target, because a
// bare `ssh gateway` sends whatever the local login happens to be and
// the person cannot act on "that is not a valid session name".
//
// Unprefixed now means the DEFAULT session, whatever the login looks
// like -- which is the point: the same command reaches the same
// session from a laptop, a login node and a container.
func TestUnprefixedUsernamesReachTheDefaultSession(t *testing.T) {
	for _, in := range []string{
		"bbockelm",
		"brian",
		"root",
		"_appstore",       // a real macOS system login
		"bob@wisc.edu",    // an eppn as a username
		"Brian Bockelman", // a space
		"-leading",
		"session-manager", // the account a word-prefix would have broken
		"ünïcodé",
		strings.Repeat("x", 200),
	} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseTarget(in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.IsJob() {
				t.Fatalf("%q parsed as a job", in)
			}
			if got.Name != DefaultSessionName {
				t.Errorf("name = %q, want the default session", got.Name)
			}
			if got.Explicit {
				t.Error("an unprefixed username was recorded as an explicit request")
			}
			if got.Raw != in {
				t.Errorf("Raw = %q, want the username verbatim", got.Raw)
			}
		})
	}
}

// A POSIX username cannot contain "+", so no local login can be
// mistaken for an explicit session request. That is why the prefix is
// a sigil and not a word: "session-manager" is a plausible account, and
// a word prefix would have needed an escape hatch for it.
func TestTheSessionPrefixCannotBeALocalUsername(t *testing.T) {
	// The portable POSIX set, which is what a login may contain.
	const portable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
	if strings.ContainsAny(SessionPrefix, portable) {
		t.Fatalf("SessionPrefix %q is made of characters a username may contain, so a login could be "+
			"mistaken for an explicit request", SessionPrefix)
	}
}

// The prefix names a session, and a name that is already usable
// survives untouched.
func TestPrefixedUsernamesNameASession(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"+work", "work"},
		{"+build-2", "build-2"},
		{"+my.session", "my.session"},
		{"+a_b", "a_b"},
		{"+W0rk", "W0rk"},
		{"+has space", "has-space"},
		{"+@@@", ""}, // derived; asserted below rather than here
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTarget(tc.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.IsJob() {
				t.Fatalf("%q parsed as a job", tc.in)
			}
			if !got.Explicit {
				t.Error("a prefixed username was not recorded as explicit")
			}
			if tc.want != "" && got.Name != tc.want {
				t.Errorf("name = %q, want %q", got.Name, tc.want)
			}
			if err := interactive.ValidateSessionName(got.Name); err != nil {
				t.Errorf("derived name %q is not usable: %v", got.Name, err)
			}
		})
	}
}

// The prefix is also the escape hatch for the other collision: a
// session legitimately named like a job id is unreachable bare,
// because job ids are tried first.
func TestPrefixReachesASessionNamedLikeAJobID(t *testing.T) {
	bare, err := ParseTarget("12345.0")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bare.IsJob() {
		t.Fatal("a bare job id did not parse as a job")
	}

	got, err := ParseTarget("+12345.0")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.IsJob() {
		t.Fatal("a prefixed job-id-shaped name still parsed as a job")
	}
	if got.Name != "12345.0" {
		t.Errorf("name = %q, want the literal session name", got.Name)
	}
}

// "+" with nothing after it asked for a session and named none.
func TestBarePrefixIsTheDefaultSession(t *testing.T) {
	got, err := ParseTarget("+")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Name != DefaultSessionName {
		t.Errorf("name = %q, want the default session", got.Name)
	}
}

// Deterministic, so the same request reaches the same session; and
// distinct, so two unrelated ones do not land in one.
func TestDerivedNamesAreStableAndDistinct(t *testing.T) {
	first, _ := ParseTarget("+@@@")
	again, _ := ParseTarget("+@@@")
	other, _ := ParseTarget("+###")

	if first.Name != again.Name {
		t.Errorf("the same request produced %q then %q", first.Name, again.Name)
	}
	if first.Name == other.Name {
		t.Errorf("two different requests both produced %q", first.Name)
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
