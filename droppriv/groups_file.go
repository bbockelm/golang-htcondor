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
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// FileGroups reads group membership from a file in /etc/group format.
//
// It exists for memberships the directory does not carry. A site whose
// staff and admin groups live somewhere other than LDAP -- or not yet in
// LDAP at all -- has no way to express them through the system sources,
// and the alternative is hard-coding names in configuration where they
// cannot be audited or shared.
//
// The format is passwd(5)'s group file, deliberately, so an administrator
// can paste `getent group <name>` output into it unchanged:
//
//	chtc_staff:*:40388:ckoch5,aowen4,xalim
//
// Only the name and the member list are used. The gid is parsed but not
// required to be meaningful, and the password field is ignored -- this
// file grants no login, only membership.
//
// Like /etc/group itself, it lists SUPPLEMENTARY members only: there is no
// primary-group notion here, because there is no passwd entry to carry
// one.
type FileGroups struct {
	// Path is the file to read.
	Path string

	// reloadEvery bounds how often the file is re-read. Zero means the
	// default; a test may shorten it.
	reloadEvery time.Duration

	mu       sync.Mutex
	byUser   map[string][]string
	loadedAt time.Time
	modTime  time.Time
	size     int64
	loadErr  error
}

// NewFileGroups returns a group source reading path.
func NewFileGroups(path string) *FileGroups {
	return &FileGroups{Path: path}
}

// Name identifies the source in logs, including the path: a deployment may
// configure more than one file, and "file" alone would not say which.
func (f *FileGroups) Name() string { return "file:" + f.Path }

const fileGroupsReloadInterval = 30 * time.Second

func (f *FileGroups) interval() time.Duration {
	if f.reloadEvery > 0 {
		return f.reloadEvery
	}
	return fileGroupsReloadInterval
}

// LookupGroups returns the groups this file records for username.
//
// An account the file does not mention is ErrUnknownUser, which
// contributes nothing to a chain and is the ordinary case: most accounts
// are not in a hand-maintained overlay.
//
// A file that cannot be read is an error rather than an empty answer. An
// operator who configured this source meant it to be consulted, and
// silently treating a missing file as "nobody is in any group" would
// revoke access with no signal anywhere.
func (f *FileGroups) LookupGroups(_ context.Context, username string) ([]string, error) {
	if username == "" {
		return nil, fmt.Errorf("%w: empty username", ErrUnknownUser)
	}

	byUser, err := f.snapshot()
	if err != nil {
		return nil, err
	}
	groups, ok := byUser[username]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not named in %s", ErrUnknownUser, username, f.Path)
	}
	return NormalizeGroups(groups), nil
}

// snapshot returns the parsed file, re-reading it when it has changed.
//
// Re-reading matters: this file is edited by hand, and an administrator
// who adds somebody to a group expects that to take effect without
// restarting the daemon. The stat is cheap and bounded by interval().
func (f *FileGroups) snapshot() (map[string][]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	fresh := f.byUser != nil || f.loadErr != nil
	if fresh && now.Sub(f.loadedAt) < f.interval() {
		return f.byUser, f.loadErr
	}

	info, statErr := os.Stat(f.Path)
	if statErr == nil && fresh &&
		info.ModTime().Equal(f.modTime) && info.Size() == f.size {
		// Unchanged on disk; keep what we have and defer the next stat.
		f.loadedAt = now
		return f.byUser, f.loadErr
	}

	byUser, err := parseGroupFile(f.Path)
	f.loadedAt = now
	f.byUser, f.loadErr = byUser, err
	if statErr == nil {
		f.modTime, f.size = info.ModTime(), info.Size()
	}
	return f.byUser, f.loadErr
}

// parseGroupFile reads an /etc/group-format file into user -> groups.
func parseGroupFile(path string) (map[string][]string, error) {
	fh, err := os.Open(path) //nolint:gosec // the path is operator configuration
	if err != nil {
		return nil, fmt.Errorf("opening the group file %s: %w", path, err)
	}
	defer func() { _ = fh.Close() }()

	byUser := make(map[string][]string)
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:gid:members
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		group := strings.TrimSpace(fields[0])
		if group == "" {
			continue
		}
		for _, member := range strings.Split(fields[3], ",") {
			member = strings.TrimSpace(member)
			if member == "" {
				continue
			}
			byUser[member] = append(byUser[member], group)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading the group file %s: %w", path, err)
	}
	return byUser, nil
}
