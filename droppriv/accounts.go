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
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// DefaultPasswdFile is the account file read when none is configured.
const DefaultPasswdFile = "/etc/passwd"

// Account is one entry from the account database.
type Account struct {
	Username string
	UID      uint32
	GID      uint32

	// Gecos is the account's GECOS "full name" -- the field up to the
	// first comma, NOT the raw field. See GecosOf for why.
	Gecos string
}

// GecosOf returns an account's GECOS name, asking the system.
//
// This is os/user.Lookup, which means that with cgo it runs getpwnam_r
// and therefore consults every service in nsswitch.conf -- so a directory
// account resolves here even though nothing can enumerate one.
//
// The value is the GECOS field up to the first comma, because that is what
// os/user returns: both its cgo and pure-Go paths do
// "u.Name, _, _ = strings.Cut(u.Name, \",\")", treating the field as the
// comma-separated list that passwd(5) describes and keeping the first item.
// EnumerateAccounts truncates identically, so an index built there and a
// verification made here compare the same string.
func GecosOf(_ context.Context, username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("no username to look up")
	}
	u, err := user.Lookup(username)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return "", fmt.Errorf("%w: %q", ErrUnknownUser, username)
		}
		return "", fmt.Errorf("looking up %q: %w", username, err)
	}
	return u.Name, nil
}

// GecosInFile returns an account's GECOS name from a specific passwd file.
//
// This is the verification counterpart to enumerating a NON-default file.
// An operator who points the index at their own passwd file must have it
// re-checked against that same file: verifying against the system instead
// would refuse every account the file describes and the system does not.
func GecosInFile(ctx context.Context, path, username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("no username to look up")
	}
	accounts, err := EnumerateAccounts(ctx, path)
	if err != nil {
		return "", err
	}
	for _, a := range accounts {
		if a.Username == username {
			return a.Gecos, nil
		}
	}
	return "", fmt.Errorf("%w: no account %q in %s", ErrUnknownUser, username, path)
}

// EnumerateAccounts lists accounts from a passwd file.
//
// This is the one operation with no stdlib equivalent -- os/user can look
// an account up but cannot list them -- and no NSS equivalent either: the
// SSSD client protocol has no enumeration call, and SSSD answers an
// enumeration only under "enumerate = true", which is off by default. So a
// reverse index over GECOS can only cover accounts present in this file.
// Every hit it produces is re-checked with GecosOf, which does reach the
// directory, so an incomplete index cannot promote anybody.
func EnumerateAccounts(_ context.Context, path string) ([]Account, error) {
	if path == "" {
		path = DefaultPasswdFile
	}
	f, err := os.Open(path) //nolint:gosec // the path is operator configuration
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var accounts []Account
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 5 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			// A non-numeric uid drops the line rather than defaulting to 0,
			// which would silently make it root.
			continue
		}
		gid, err := strconv.ParseUint(fields[3], 10, 32)
		if err != nil {
			continue
		}
		gecos, _, _ := strings.Cut(fields[4], ",")
		accounts = append(accounts, Account{
			Username: fields[0],
			UID:      uint32(uid),
			GID:      uint32(gid),
			Gecos:    gecos,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return accounts, nil
}
