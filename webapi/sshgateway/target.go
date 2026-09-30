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
// The username carries no identity here -- the OAuth2 grant or the
// certificate does -- so the field is free to mean something useful
// instead. It is also the ONLY thing SSH offers before authentication:
// no path, no Host header, no SNI. That matters beyond shells, because
// a port forward and an scp carry no command, so the username is the
// only place they can say which job they mean.
//
//	ssh 12345.0@gateway    the job with that cluster and proc
//	ssh 12345@gateway      proc 0 of that cluster
//	ssh +work@gateway      the interactive session called "work"
//	ssh gateway            your default session
//
// The leading "+" is required to name a session, and that is the point.
// A bare `ssh gateway` sends whatever the local machine calls you, and
// your laptop login has nothing to do with your HTCondor session: an
// earlier version read it as a session name, so the same command gave
// you "bbockelm" from a laptop, "brian" from a login node and "root"
// from a container -- three sessions for somebody who asked for none of
// them. Everything unprefixed now means the same session from every
// machine you own.
//
// "+" is chosen because a POSIX username cannot contain it, so no local
// login can be mistaken for an explicit request. A word like "session-"
// would have needed an escape hatch for the account actually called
// "session-manager"; this needs none.
//
// It doubles as the escape hatch for the other collision: a session
// legitimately named "12345.0" is unreachable bare, because job ids are
// tried first, but "+12345.0" names it unambiguously.
type Target struct {
	// Raw is the username exactly as the client sent it.
	Raw string

	// Cluster and Proc are set when Raw named a job.
	Cluster, Proc int
	// Name is set when Raw named an interactive session, explicitly or
	// by default.
	Name string
	// Explicit records that the session was asked for by name rather
	// than being the default. Only useful for logs -- it is the
	// difference between "they wanted this one" and "they did not
	// say".
	Explicit bool
}

// IsJob reports whether the target named a job id rather than a session.
func (t Target) IsJob() bool { return t.Name == "" }

func (t Target) String() string {
	if t.IsJob() {
		return fmt.Sprintf("job %d.%d", t.Cluster, t.Proc)
	}
	return fmt.Sprintf("session %q", t.Name)
}

// SessionPrefix marks a username as naming an interactive session.
const SessionPrefix = "+"

// DefaultSessionName is what an unprefixed username reaches.
//
// A fixed name rather than a derived one, so `ssh gateway` means the
// same session from every machine.
const DefaultSessionName = "default"

// ParseTarget reads an SSH username.
//
// A job id is tried first, so "12345.0" reaches that job.
func ParseTarget(user string) (Target, error) {
	if user == "" {
		return Target{}, fmt.Errorf("no target: connect as a job id (12345.0), +<session>, or bare for your default session")
	}
	t := Target{Raw: user}

	if cluster, proc, ok := parseJobID(user); ok {
		t.Cluster, t.Proc = cluster, proc
		return t, nil
	}

	if rest, ok := strings.CutPrefix(user, SessionPrefix); ok {
		if strings.TrimSpace(rest) == "" {
			// "+" alone asked for a session and named none, which is
			// the default by any reading.
			t.Name = DefaultSessionName
			return t, nil
		}
		t.Name = sessionNameFor(rest)
		t.Explicit = true
		return t, nil
	}

	t.Name = DefaultSessionName
	return t, nil
}

// sessionNameFor derives a usable session name from what followed the
// prefix.
//
// Session names are narrow on purpose -- they are spliced into a submit
// file and a batch name -- so this maps anything outside
// [A-Za-z0-9._-] to a dash, drops leading characters that cannot start
// one, and truncates to the 64 the validator allows. A name that is
// already usable survives untouched, which is the case that matters.
//
// When nothing usable is left, the name falls back to a short digest of
// the original: deterministic, so the same request reaches the same
// session every time, and distinct, so two unrelated ones do not
// collide.
func sessionNameFor(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.TrimLeft(b.String(), "._-")

	if len(out) > sessionNameMaxLen {
		out = out[:sessionNameMaxLen]
	}
	if out == "" {
		sum := sha256.Sum256([]byte(name))
		return "session-" + hex.EncodeToString(sum[:4])
	}
	return out
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
