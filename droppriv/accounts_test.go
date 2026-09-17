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
	"strings"
	"testing"
)

// A real line from the site this was built for: the GECOS is not the
// login name, which is the whole reason a reverse index exists.
// conventional shadow placeholder, not a credential.
//
//nolint:gosec // G101: a passwd(5) line from a fixture; the "x" is the
const realPasswdLine = "tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/bash"

func TestEnumerateAccountsParsesTheRealLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	body := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"# a comment",
		"",
		realPasswdLine,
		"malformed-line-without-enough-fields",
		"nouid:x:notanumber:0:x:/:/bin/sh",
		"colons:x:20015:20015:has:colons?no:/home/g:/bin/sh",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	accounts, err := EnumerateAccounts(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Account{}
	for _, a := range accounts {
		byName[a.Username] = a
	}
	if len(accounts) != 3 {
		t.Errorf("parsed %d accounts (%v), want 3 with the bad lines skipped", len(accounts), byName)
	}
	// A non-numeric uid makes the line malformed, and it is dropped rather
	// than recorded with a defaulted uid -- a silent 0 there would be root's.
	if _, ok := byName["nouid"]; ok {
		t.Error("kept an entry whose uid did not parse")
	}
	if got := byName["tannenba"]; got.Gecos != "tatannen" || got.UID != 20013 {
		t.Errorf("parsed %+v, want GECOS tatannen uid 20013", got)
	}
	// passwd(5) is colon-separated, so the field stops at the next colon.
	if g := byName["colons"].Gecos; g != "has" {
		t.Errorf("GECOS field = %q, want it to stop at the colon", g)
	}
}

// The GECOS field is truncated at the first comma, deliberately, because
// that is what os/user does on BOTH its cgo and pure-Go paths. If this
// file disagreed with GecosOf, an index entry and its verification would
// compare different strings and every such login would be refused.
func TestEnumerateAccountsTruncatesGecosLikeOsUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	body := "tannenba:x:20013:20013:Tannenbaum, Todd,,:/home/tannenba:/bin/bash\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	accounts, err := EnumerateAccounts(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Fatalf("got %d accounts, want 1", len(accounts))
	}
	if got := accounts[0].Gecos; got != "Tannenbaum" {
		t.Errorf("Gecos = %q, want %q -- os/user keeps only the first comma-separated item, and this must match it",
			got, "Tannenbaum")
	}
}

func TestGecosInFileDistinguishesMissingFromEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	body := realPasswdLine + "\nblank:x:20016:20016::/home/blank:/bin/sh\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	gecos, err := GecosInFile(context.Background(), path, "tannenba")
	if err != nil || gecos != "tatannen" {
		t.Errorf("GecosInFile(tannenba) = %q, %v", gecos, err)
	}

	// An account with no GECOS is present with an empty one...
	if gecos, err := GecosInFile(context.Background(), path, "blank"); err != nil || gecos != "" {
		t.Errorf("GecosInFile(blank) = %q, %v; want an empty GECOS and no error", gecos, err)
	}
	// ...which must not look like an account that does not exist.
	if _, err := GecosInFile(context.Background(), path, "ghost"); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("a missing account gave %v, want ErrUnknownUser", err)
	}
}

func TestEnumerateAccountsReportsAnUnreadableFile(t *testing.T) {
	if _, err := EnumerateAccounts(context.Background(), filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("a missing passwd file must be an error, not an empty account list")
	}
}
