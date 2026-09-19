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

	"github.com/bbockelm/golang-htcondor/droppriv"
)

// This package maps a token subject to a local account. It deliberately
// contains no account or group READING of its own: every passwd, group
// and NSS question goes to droppriv, which already owns the per-platform
// strategy selection, the nsswitch.conf ordering and the cgo/non-cgo
// split. What lives here is only the mapping policy -- which field to
// match, in what order, and what to do when two accounts claim the same
// identity.

// SystemAccounts enumerates the account database through droppriv.
type SystemAccounts struct {
	// Path overrides the passwd file. Empty means the system default.
	Path string
}

// Name identifies the source in logs.
func (s *SystemAccounts) Name() string {
	if s.Path == "" {
		return "passwd:" + droppriv.DefaultPasswdFile
	}
	return "passwd:" + s.Path
}

// Enumerate lists the accounts available to build an index from.
func (s *SystemAccounts) Enumerate(ctx context.Context) ([]Account, error) {
	// A degraded read returns BOTH the accounts it managed to list and the
	// reason the rest are missing, so convert first and hand the error back
	// alongside the result. Discarding the accounts here would leave the
	// resolver unable to tell a partial answer from no answer.
	found, err := droppriv.EnumerateAccounts(ctx, s.Path)
	accounts := make([]Account, 0, len(found))
	for _, a := range found {
		accounts = append(accounts, Account{Username: a.Username, Gecos: a.Gecos, UID: a.UID})
	}
	return accounts, err
}

// SystemGecos re-checks a candidate account through droppriv.
//
// This is the half that reaches further than enumeration can: with cgo it
// is getpwnam_r, so a directory account answers here even though nothing
// could have listed it. That asymmetry is what makes a mapping derived
// from an index of local accounts safe to act on.
type SystemGecos struct{}

// GecosOf returns the account's current GECOS name.
func (SystemGecos) GecosOf(ctx context.Context, username string) (string, error) {
	return droppriv.GecosOf(ctx, username)
}

// FileGecos re-checks a candidate against a specific passwd file.
//
// It pairs with a SystemAccounts that names the same file. Verifying
// against the system when the index came from somewhere else would refuse
// every account that file describes and the system does not know.
type FileGecos struct{ Path string }

// GecosOf returns the account's GECOS name from the configured file.
func (f FileGecos) GecosOf(ctx context.Context, username string) (string, error) {
	return droppriv.GecosInFile(ctx, f.Path, username)
}
