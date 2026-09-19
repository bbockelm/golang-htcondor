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

	"github.com/bbockelm/golang-htcondor/droppriv"
)

func unreachableDirectory() error {
	return &droppriv.DirectoryError{Source: "sssd", Err: errors.New("not connected")}
}

// A directory that cannot be read must not take the whole index with it.
// The local accounts are still worth indexing -- and on a container's
// first seconds they may be ALL there is, because the SSSD sidecar has not
// started answering yet.
func TestBuildServesAPartialIndexWhenTheDirectoryIsUnreachable(t *testing.T) {
	enum := &fakeEnum{
		accounts: []Account{{Username: "root", Gecos: "root"}},
		err:      unreachableDirectory(),
	}
	r := New(enum, &fakeVerifier{gecos: map[string]string{"root": "root"}})

	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("a degraded enumeration refused to build any index: %v", err)
	}
	got, err := r.Resolve(context.Background(), "root")
	if err != nil || got != "root" {
		t.Fatalf("Resolve = %q, %v; the accounts that WERE readable must still resolve", got, err)
	}
	if r.Degraded() == nil {
		t.Error("the index is incomplete and nothing records why; that is how this goes unnoticed")
	}
}

// Fail-closed at the other end: if nothing at all was readable there is no
// index to serve, and pretending otherwise would refuse every login with a
// misleading "no account matches".
func TestBuildFailsWhenDegradedAndNothingWasReadable(t *testing.T) {
	enum := &fakeEnum{accounts: nil, err: unreachableDirectory()}
	r := New(enum, &fakeVerifier{})

	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("an enumeration that produced nothing at all was treated as a successful build")
	}
}

// The state must clear, or one transient outage marks the index degraded
// for the life of the process and the warning stops meaning anything.
func TestDegradedClearsWhenTheDirectoryComesBack(t *testing.T) {
	enum := &fakeEnum{
		accounts: []Account{{Username: "root", Gecos: "root"}},
		err:      unreachableDirectory(),
	}
	r := New(enum, &fakeVerifier{gecos: map[string]string{"root": "root"}})

	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if r.Degraded() == nil {
		t.Fatal("precondition: the first build should be degraded")
	}

	enum.err = nil
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if r.Degraded() != nil {
		t.Errorf("Degraded = %v after a clean rebuild; the directory came back", r.Degraded())
	}
}

// An ordinary enumeration failure -- an unreadable passwd file, not a
// directory outage -- still fails the build even though accounts came
// back, because it is not the case this tolerance was added for.
func TestBuildStillFailsOnANonDirectoryError(t *testing.T) {
	enum := &fakeEnum{
		accounts: []Account{{Username: "root", Gecos: "root"}},
		err:      errors.New("permission denied"),
	}
	r := New(enum, &fakeVerifier{})

	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("a plain enumeration error was silently tolerated")
	}
}
