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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Target is what the SSH username asked to connect to.
//
// The username carries no identity here -- the OAuth2 grant does -- so
// the field is free to mean something useful instead. It names either a
// job already in the queue or an interactive session by name:
//
//	ssh 12345.0@gateway    the job with that cluster and proc
//	ssh 12345@gateway      proc 0 of that cluster
//	ssh work@gateway       the interactive session called "work"
//	ssh gateway            a session named after your local login
//
// A bare `ssh gateway` sends whatever the local account is called, so
// it lands in the session-name case and gives that user a session named
// after their laptop login. That is predictable rather than clever, and
// it is worth knowing that two machines with different local usernames
// therefore reach two different sessions.
type Target struct {
	// Raw is the username exactly as the client sent it.
	Raw string

	// Cluster and Proc are set when Raw named a job.
	Cluster, Proc int
	// Name is set when Raw named an interactive session.
	Name string
}

// IsJob reports whether the target named a job id rather than a session.
func (t Target) IsJob() bool { return t.Name == "" }

func (t Target) String() string {
	if t.IsJob() {
		return fmt.Sprintf("job %d.%d", t.Cluster, t.Proc)
	}
	return fmt.Sprintf("session %q", t.Name)
}

// ParseTarget reads an SSH username.
//
// A job id is tried first, so "12345.0" reaches that job. An
// interactive session may legally be named "12345.0" as well, since
// session names allow digits and dots; such a session is unreachable
// by name here. Naming a session after a job id is pathological enough
// to leave alone rather than to grow a prefix syntax for.
//
// Anything else becomes a session name, and ANY username produces one.
// A login is not chosen with this in mind -- `_appstore`, `bob@wisc.edu`
// and names with spaces are all real -- and refusing them would mean a
// bare `ssh gateway` failing for reasons the person cannot act on. The
// name is derived instead; see sessionNameFor.
//
// Whitespace is not trimmed. Padding is not something a client sends
// by accident, and quietly turning " 5" into job 5 reaches a different
// job than the text names -- which is the same hazard allDigits guards
// against for signs. A padded name is derived like any other.
func ParseTarget(user string) (Target, error) {
	if user == "" {
		return Target{}, fmt.Errorf("no target: connect as a job id (12345.0) or a session name")
	}
	t := Target{Raw: user}

	if cluster, proc, ok := parseJobID(user); ok {
		t.Cluster, t.Proc = cluster, proc
		return t, nil
	}

	t.Name = sessionNameFor(user)
	return t, nil
}

// sessionNameFor derives a usable session name from a username.
//
// Session names are narrow on purpose -- they are spliced into a
// submit file and a batch name -- so this maps anything outside
// [A-Za-z0-9._-] to a dash, drops leading characters that cannot start
// one, and truncates to the 64 the validator allows.
//
// A username that survives unchanged is the overwhelmingly common
// case, and it is the one this must not disturb: `ssh work@gateway`
// has to reach the session called "work" and nothing else.
//
// When nothing usable is left -- a login of "@@@", or one written in a
// script the pattern does not admit -- the name falls back to a short
// digest of the original. Deterministic, so the same laptop reaches
// the same session every time, and distinct, so two unrelated logins
// do not collide into one.
func sessionNameFor(user string) string {
	var b strings.Builder
	for _, r := range user {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.TrimLeft(b.String(), "._-")

	if len(name) > sessionNameMaxLen {
		name = name[:sessionNameMaxLen]
	}
	if name == "" {
		sum := sha256.Sum256([]byte(user))
		return "session-" + hex.EncodeToString(sum[:4])
	}
	return name
}

// sessionNameMaxLen mirrors interactive.ValidateSessionName's limit.
// Kept as a constant rather than read from there because truncating to
// a length the validator does not enforce would be a silent mismatch
// either way; a test asserts the two agree.
const sessionNameMaxLen = 64

// parseJobID accepts "N" and "N.M" with no sign and no spare parts.
func parseJobID(s string) (cluster, proc int, ok bool) {
	clusterPart, procPart, hasProc := strings.Cut(s, ".")

	cluster, err := strconv.Atoi(clusterPart)
	if err != nil || cluster < 0 || !allDigits(clusterPart) {
		return 0, 0, false
	}
	if !hasProc {
		return cluster, 0, true
	}
	proc, err = strconv.Atoi(procPart)
	if err != nil || proc < 0 || !allDigits(procPart) {
		return 0, 0, false
	}
	return cluster, proc, true
}

// allDigits rejects what Atoi accepts but a job id never has: a sign,
// or surrounding space. "+5" and " 5" must not become cluster 5.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
