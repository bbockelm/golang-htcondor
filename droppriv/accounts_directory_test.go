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

package droppriv

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// withDirectory stubs the SSSD-backed seam.
func withDirectory(t *testing.T, accounts []Account, gecos map[string]string) {
	t.Helper()
	withDirectoryErr(t, accounts, gecos, nil)
}

// withDirectoryErr stubs the seam with a directory that fails.
func withDirectoryErr(t *testing.T, accounts []Account, gecos map[string]string, err error) {
	t.Helper()
	oldA, oldG := directoryAccounts, directoryGecos
	t.Cleanup(func() { directoryAccounts, directoryGecos = oldA, oldG })

	directoryAccounts = func() ([]Account, error) { return accounts, err }
	directoryGecos = func(name string) (string, bool) {
		g, ok := gecos[name]
		return g, ok
	}
}

func writePasswdFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The point of enumerating the directory: a container's /etc/passwd knows
// only its own accounts, so without this the GECOS index is empty and every
// login is refused as corresponding to no local account.
func TestEnumerateMergesDirectoryAccounts(t *testing.T) {
	withDirectory(t, []Account{
		{Username: "bbockelm", UID: 20014, Gecos: "bockelman"},
		{Username: "tannenba", UID: 20013, Gecos: "tatannen"},
	}, nil)

	// Default path: the merge applies. The fixture stands in for a
	// container's own passwd file.
	old := defaultPasswdFileForTest
	defaultPasswdFileForTest = writePasswdFile(t, "root:x:0:0:root:/root:/bin/sh\n")
	t.Cleanup(func() { defaultPasswdFileForTest = old })

	got, err := EnumerateAccounts(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, a := range got {
		names[a.Username] = a.Gecos
	}
	for _, want := range []string{"root", "bbockelm", "tannenba"} {
		if _, ok := names[want]; !ok {
			t.Errorf("%q missing from the merged index: %v", want, names)
		}
	}
	if names["bbockelm"] != "bockelman" {
		t.Errorf("directory GECOS not carried through: %q", names["bbockelm"])
	}
}

// A named file is the operator's statement of which database to use. The
// verifier reads that same file, so quietly adding the directory would let
// the index hold entries the verifier then contradicts.
func TestAnExplicitPasswdFileIsNotMerged(t *testing.T) {
	withDirectory(t, []Account{{Username: "bbockelm", UID: 20014, Gecos: "bockelman"}}, nil)

	path := writePasswdFile(t, "tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/bash\n")
	got, err := EnumerateAccounts(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Username != "tannenba" {
		t.Errorf("explicit file was merged with the directory: %+v", got)
	}
}

// A local entry is what os/user resolves, so it must win: letting the
// directory shadow it would index a GECOS the verifier contradicts.
func TestTheLocalFileWinsACollision(t *testing.T) {
	withDirectory(t, []Account{{Username: "tannenba", UID: 999, Gecos: "from-directory"}}, nil)

	old := defaultPasswdFileForTest
	defaultPasswdFileForTest = writePasswdFile(t, "tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/bash\n")
	t.Cleanup(func() { defaultPasswdFileForTest = old })

	got, err := EnumerateAccounts(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want the local one only: %+v", len(got), got)
	}
	if got[0].Gecos != "tatannen" || got[0].UID != 20013 {
		t.Errorf("the directory shadowed the local entry: %+v", got[0])
	}
}

// Verification has to reach the directory too. An index built by
// enumerating it would otherwise verify none of its own entries: os/user
// reads /etc/passwd alone without cgo, and under musl has no NSS at all.
func TestGecosOfFallsBackToTheDirectory(t *testing.T) {
	// A name that cannot exist locally: if os/user can answer, the fallback
	// never runs and the test would pass without exercising anything.
	const onlyInDirectory = "directory-only-acct-zx9"
	if _, err := user.Lookup(onlyInDirectory); err == nil {
		t.Skipf("%q unexpectedly exists locally", onlyInDirectory)
	}
	withDirectory(t, nil, map[string]string{onlyInDirectory: "bockelman"})

	got, err := GecosOf(context.Background(), onlyInDirectory)
	if err != nil {
		t.Fatalf("GecosOf: %v", err)
	}
	if got != "bockelman" {
		t.Errorf("GecosOf = %q, want the directory's answer", got)
	}
}

// An account nobody knows is still ErrUnknownUser, not a directory error:
// the caller distinguishes "no such account" from "the lookup broke".
func TestGecosOfStillReportsUnknownAccounts(t *testing.T) {
	withDirectory(t, nil, nil)

	_, err := GecosOf(context.Background(), "definitely-not-a-real-account-xyz")
	if !errors.Is(err, ErrUnknownUser) {
		t.Errorf("err = %v, want ErrUnknownUser", err)
	}
}

func TestMergeDirectoryAccountsWithNothingToMerge(t *testing.T) {
	file := []Account{{Username: "root"}}
	if got := mergeDirectoryAccounts(file, nil); len(got) != 1 {
		t.Errorf("merging nothing changed the result: %+v", got)
	}
}
