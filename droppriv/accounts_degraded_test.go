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
	"testing"
)

// The bug this guards against cost a live debugging session: a directory
// that could not be read reported "no directory accounts", which is what a
// working directory with nothing to add also reports. The index came out
// holding only the container's own accounts, every directory login was
// refused as corresponding to no local account, and nothing anywhere said
// SSSD had failed.
func TestEnumerateReportsAnUnreachableDirectory(t *testing.T) {
	withDirectoryErr(t, nil, nil, errors.New("not connected"))

	old := defaultPasswdFileForTest
	defaultPasswdFileForTest = writePasswdFile(t, "root:x:0:0:root:/root:/bin/sh\n")
	t.Cleanup(func() { defaultPasswdFileForTest = old })

	accounts, err := EnumerateAccounts(context.Background(), "")

	// The readable half is still returned: a caller may prefer a partial
	// index to refusing every login.
	if len(accounts) != 1 || accounts[0].Username != "root" {
		t.Errorf("accounts = %+v, want the passwd file's entries", accounts)
	}
	var derr *DirectoryError
	if !errors.As(err, &derr) {
		t.Fatalf("err = %v, want a *DirectoryError naming the failure", err)
	}
	if derr.Source == "" {
		t.Error("a degraded read must name the source that failed")
	}
	if !errors.Is(err, derr.Err) {
		t.Error("the underlying cause must remain reachable through errors.Is")
	}
}

// The complement, so the test above cannot pass by the seam always
// failing: a directory that answers produces no error at all.
func TestEnumerateReportsNoErrorWhenTheDirectoryAnswers(t *testing.T) {
	withDirectory(t, []Account{{Username: "bbockelm", UID: 20014, Gecos: "bockelman"}}, nil)

	old := defaultPasswdFileForTest
	defaultPasswdFileForTest = writePasswdFile(t, "root:x:0:0:root:/root:/bin/sh\n")
	t.Cleanup(func() { defaultPasswdFileForTest = old })

	accounts, err := EnumerateAccounts(context.Background(), "")
	if err != nil {
		t.Fatalf("a directory that answered was reported as degraded: %v", err)
	}
	if len(accounts) != 2 {
		t.Errorf("accounts = %+v, want the file's entry and the directory's", accounts)
	}
}

// An operator who named a passwd file gets that file and nothing else, so
// a broken directory is not their problem and must not be reported as
// theirs.
func TestExplicitPasswdFileNeverConsultsTheDirectory(t *testing.T) {
	consulted := false
	oldA := directoryAccounts
	t.Cleanup(func() { directoryAccounts = oldA })
	directoryAccounts = func() ([]Account, error) {
		consulted = true
		return nil, errors.New("not connected")
	}

	path := writePasswdFile(t, "root:x:0:0:root:/root:/bin/sh\n")
	accounts, err := EnumerateAccounts(context.Background(), path)
	if err != nil {
		t.Fatalf("an explicit file was reported degraded because of the directory: %v", err)
	}
	if consulted {
		t.Error("the directory was consulted for an explicitly configured passwd file")
	}
	if len(accounts) != 1 {
		t.Errorf("accounts = %+v", accounts)
	}
}
