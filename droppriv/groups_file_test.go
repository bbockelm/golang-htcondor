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
	"path/filepath"
	"testing"
	"time"
)

func writeGroupFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "groups")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The format is /etc/group's on purpose: an administrator maintaining
// memberships the directory does not carry should be able to paste
// `getent group <name>` output in unchanged.
func TestFileGroupsReadsGetentOutput(t *testing.T) {
	path := writeGroupFile(t, "chtc_staff:*:40388:ckoch5,aowen4,bbockelm\n"+
		"ap2001-login:*:40428:bbockelm,qwang377\n")
	f := NewFileGroups(path)

	got, err := f.LookupGroups(context.Background(), "bbockelm")
	if err != nil {
		t.Fatalf("LookupGroups: %v", err)
	}
	want := []string{"ap2001-login", "chtc_staff"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("groups = %v, want %v", got, want)
	}
}

// An account the file does not mention contributes nothing, which is the
// ordinary case: most accounts are not in a hand-maintained overlay.
func TestFileGroupsReportsAnAbsentAccountAsUnknown(t *testing.T) {
	f := NewFileGroups(writeGroupFile(t, "chtc_staff:*:40388:ckoch5\n"))

	_, err := f.LookupGroups(context.Background(), "nobody")
	if !errors.Is(err, ErrUnknownUser) {
		t.Errorf("err = %v, want ErrUnknownUser", err)
	}
}

// A file that cannot be read is NOT "nobody is in any group". An operator
// configured this source meaning it to be consulted; treating a missing
// file as an empty answer would quietly revoke access.
func TestFileGroupsReportsAnUnreadableFile(t *testing.T) {
	f := NewFileGroups(filepath.Join(t.TempDir(), "not-there"))

	_, err := f.LookupGroups(context.Background(), "bbockelm")
	if err == nil {
		t.Fatal("a missing group file produced no error")
	}
	if errors.Is(err, ErrUnknownUser) {
		t.Error("a missing file was reported as an unknown account, which reads as 'belongs to nothing'")
	}
}

// The file is edited by hand, so an edit has to take effect without
// restarting the daemon.
func TestFileGroupsPicksUpAnEdit(t *testing.T) {
	path := writeGroupFile(t, "chtc_staff:*:40388:ckoch5\n")
	f := NewFileGroups(path)
	f.reloadEvery = time.Millisecond

	if _, err := f.LookupGroups(context.Background(), "bbockelm"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("precondition: err = %v, want ErrUnknownUser", err)
	}

	if err := os.WriteFile(path, []byte("chtc_staff:*:40388:ckoch5,bbockelm\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The reload is gated on mtime AND size; both change here, and the
	// interval is a millisecond.
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, err := f.LookupGroups(context.Background(), "bbockelm")
		if err == nil && len(got) == 1 && got[0] == "chtc_staff" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the edit was never picked up: %v, %v", got, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Malformed lines are skipped rather than failing the whole file: one bad
// line in a hand-edited file must not revoke everybody else's groups.
func TestFileGroupsSkipsUnusableLines(t *testing.T) {
	f := NewFileGroups(writeGroupFile(t,
		"# a comment\n\nnot-a-group-line\n:*:1:orphan\nchtc_staff:*:40388:bbockelm\n"))

	got, err := f.LookupGroups(context.Background(), "bbockelm")
	if err != nil || len(got) != 1 || got[0] != "chtc_staff" {
		t.Errorf("groups = %v, err = %v; want just chtc_staff", got, err)
	}
}

// Several sources are a UNION, the way glibc merges NSS services. This is
// the whole reason for allowing more than one: a site carries directory
// groups and hand-maintained ones at the same time.
func TestGroupChainUnionsItsSources(t *testing.T) {
	a := NewFileGroups(writeGroupFile(t, "from_ldap:*:1:bbockelm\n"))
	b := NewFileGroups(writeGroupFile(t, "chtc_staff:*:2:bbockelm\n"))

	chain := NewGroupChain(a, b)
	got, err := chain.LookupGroups(context.Background(), "bbockelm")
	if err != nil {
		t.Fatalf("LookupGroups: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("groups = %v, want both sources' answers", got)
	}
}

// One unavailable source must not hide the other's answer, but it must be
// reported: a short group list is an authorization decision.
func TestGroupChainMarksAMissingFileDegraded(t *testing.T) {
	good := NewFileGroups(writeGroupFile(t, "chtc_staff:*:2:bbockelm\n"))
	missing := NewFileGroups(filepath.Join(t.TempDir(), "gone"))

	got, err := NewGroupChain(good, missing).LookupGroups(context.Background(), "bbockelm")
	if len(got) != 1 || got[0] != "chtc_staff" {
		t.Errorf("groups = %v; the working source's answer was lost", got)
	}
	var degraded *DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("err = %v, want a DegradedError naming the unavailable source", err)
	}
}

// A single source is not wrapped, so logs say what was consulted rather
// than "chain(x)".
func TestASingleSourceIsNotWrappedInAChain(t *testing.T) {
	only := NewFileGroups(writeGroupFile(t, "g:*:1:u\n"))
	if got := NewGroupChain(only).Name(); got != only.Name() {
		t.Errorf("Name = %q, want %q", got, only.Name())
	}
	if NewGroupChain() != nil {
		t.Error("an empty chain should be nil, meaning no local source")
	}
}
