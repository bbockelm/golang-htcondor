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

//go:build linux

package droppriv

import (
	"errors"
	"testing"

	"github.com/bbockelm/gosssd"
)

// SSSD running and naming nobody is not the same as SSSD being absent.
// It means either the domain lacks "enumerate = true" or SSSD has not
// finished its first pass over the directory -- and in both cases this
// process does not know the directory's accounts, so the index it builds
// must not be mistaken for complete.
func TestAnEmptyDirectoryAnswerIsNotCompleteKnowledge(t *testing.T) {
	accounts, err := accountsFromSSSDUsers(nil)

	if !errors.Is(err, ErrDirectoryEmpty) {
		t.Fatalf("err = %v, want ErrDirectoryEmpty", err)
	}
	if len(accounts) != 0 {
		t.Errorf("accounts = %+v, want none", accounts)
	}
}

// Entries SSSD cannot describe are skipped, and if that leaves nothing
// the answer is still "no knowledge" rather than "no accounts".
func TestAnAnswerOfOnlyUnusableEntriesIsAlsoEmpty(t *testing.T) {
	_, err := accountsFromSSSDUsers([]*gosssd.User{nil, {Name: ""}})
	if !errors.Is(err, ErrDirectoryEmpty) {
		t.Fatalf("err = %v, want ErrDirectoryEmpty", err)
	}
}

// A directory that answers with accounts is complete knowledge, and the
// GECOS is truncated the same way os/user truncates it.
func TestAPopulatedDirectoryAnswerIsComplete(t *testing.T) {
	accounts, err := accountsFromSSSDUsers([]*gosssd.User{
		{Name: "bbockelm", UID: 20014, GID: 20014, Gecos: "bockelman,room,work,home"},
	})
	if err != nil {
		t.Fatalf("a populated answer was reported as a failure: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("accounts = %+v, want one", accounts)
	}
	if accounts[0].Gecos != "bockelman" {
		t.Errorf("Gecos = %q, want the part before the first comma", accounts[0].Gecos)
	}
}
