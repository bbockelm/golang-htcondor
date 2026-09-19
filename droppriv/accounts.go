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

// The directory seam. These are the SSSD-backed implementations, held in
// variables so a test can exercise the merge and the verification fallback
// without standing up an SSSD.
var (
	directoryAccounts = enumerateSSSDAccounts
	directoryGecos    = gecosFromSSSD
)

// DefaultPasswdFile is the account file read when none is configured.
const DefaultPasswdFile = "/etc/passwd"

// defaultPasswdFileForTest is the path actually read for the default. A
// variable so a test can supply a fixture in place of the real one.
var defaultPasswdFileForTest = DefaultPasswdFile

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
	if err == nil {
		return u.Name, nil
	}

	var unknown user.UnknownUserError
	if !errors.As(err, &unknown) {
		return "", fmt.Errorf("looking up %q: %w", username, err)
	}

	// Not in the local database. Ask the directory before concluding the
	// account does not exist: os/user reads /etc/passwd alone without cgo,
	// and under musl there is no NSS for it to consult at all, so a
	// directory account is invisible to it. Without this, an index built by
	// enumerating the directory would verify none of its own entries.
	if gecos, ok := directoryGecos(username); ok {
		return gecos, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownUser, username)
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
// os/user has no equivalent: it can look an account up but not list them.
//
// Nor does anything else here, today. The SSSD protocol DOES define
// enumeration -- SSS_NSS_SETPWENT/GETPWENT/ENDPWENT, what getpwent(3)
// drives through the NSS module -- but the client library this package
// uses does not implement it yet, so a passwd file is currently the only
// thing that can be listed. When it does, a directory-backed deployment
// can build the index without materialising accounts locally, and SSSD
// will still only answer under "enumerate = true", which is off by
// default and discouraged for large directories.
//
// Until then a reverse index over GECOS covers only the accounts in this
// file. That is safe rather than merely limited: every hit it produces is
// re-checked with GecosOf, which does reach the directory, so an
// incomplete index can fail to find somebody but cannot promote anybody.
func EnumerateAccounts(_ context.Context, path string) ([]Account, error) {
	// An explicitly configured file is the whole answer: the operator named
	// the database, and silently adding the directory to it would make the
	// index disagree with the verifier, which reads that same file.
	explicit := strings.TrimSpace(path) != ""
	if !explicit {
		path = defaultPasswdFileForTest
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

	if !explicit {
		directory, derr := directoryAccounts()
		accounts = mergeDirectoryAccounts(accounts, directory)
		if derr != nil {
			// The file was read, so hand back what it held -- but say that
			// the directory half is missing. "The directory has no extra
			// accounts" and "the directory could not be reached" produce an
			// identical index, and only one of them is somebody's fault.
			return accounts, &DirectoryError{Source: "sssd", Err: derr}
		}
	}
	return accounts, nil
}

// ErrDirectoryEmpty reports that the directory service answered and named
// no accounts at all.
//
// Distinct from a directory that could not be reached, and from one that
// is simply absent: SSSD is running and said "nobody". The index that
// results covers only local accounts, so it cannot map a directory
// identity, and callers must not mistake it for complete knowledge.
var ErrDirectoryEmpty = errors.New("the directory service enumerated no accounts")

// DirectoryError reports that the passwd file was read but the directory
// half of an enumeration was not.
//
// It is returned ALONGSIDE the accounts that were readable, so a caller
// may choose to index those and carry on. That choice belongs to the
// caller: refusing every login because a directory is briefly unreachable
// is usually worse than serving a smaller index, but doing so silently is
// worse than either.
type DirectoryError struct {
	Source string
	Err    error
}

func (e *DirectoryError) Error() string {
	return fmt.Sprintf("account enumeration degraded: %s unavailable: %v", e.Source, e.Err)
}

func (e *DirectoryError) Unwrap() error { return e.Err }

// mergeDirectoryAccounts appends directory accounts the file did not name.
//
// The file wins a collision. A local entry is the one an administrator put
// on this machine deliberately, and it is what os/user resolves, so letting
// the directory shadow it would index a GECOS that the verifier -- which
// asks os/user first -- would then contradict.
func mergeDirectoryAccounts(fromFile, fromDirectory []Account) []Account {
	if len(fromDirectory) == 0 {
		return fromFile
	}
	seen := make(map[string]struct{}, len(fromFile))
	for _, a := range fromFile {
		seen[a.Username] = struct{}{}
	}
	for _, a := range fromDirectory {
		if _, dup := seen[a.Username]; dup {
			continue
		}
		seen[a.Username] = struct{}{}
		fromFile = append(fromFile, a)
	}
	return fromFile
}
