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
	"os"
	"strings"
	"sync"
)

// One nsswitch.conf location, shared by every lookup in this package.
//
// It lives in an untagged file on purpose. The passwd chain needs it only
// without cgo, the group chain needs it on every platform without cgo, and
// tests need to point all of them at a fixture. Declaring it per build tag
// meant the same path existed under some builds and not others.
var (
	nssSwitchPathMu sync.RWMutex
	//nolint:unused // Read via nsswitchPath in the nocgo build
	nssSwitchPath = "/etc/nsswitch.conf"
)

// SetNSSSwitchPath sets the path to nsswitch.conf. Intended for testing.
//
// It also resets the memoised group lookup, since that is chosen from this
// file on first use and would otherwise keep answering from the old one.
func SetNSSSwitchPath(path string) {
	nssSwitchPathMu.Lock()
	nssSwitchPath = path
	nssSwitchPathMu.Unlock()
	resetDefaultGroupLookup()
}

// nsswitchPath returns the configured nsswitch.conf location.
//
//nolint:unused // Used in the nocgo build; with cgo, glibc reads this file itself
func nsswitchPath() string {
	nssSwitchPathMu.RLock()
	defer nssSwitchPathMu.RUnlock()
	return nssSwitchPath
}

// countDeclaredMethods counts every method on a database's line,
// including the ones ParseNSSwitchDB drops because this package cannot
// speak them. The difference between this and what came back is exactly
// "what the administrator configured that we cannot consult".
//
//nolint:unused // Used in the nocgo build
func countDeclaredMethods(path, database string) int {
	f, err := os.Open(path) //nolint:gosec // operator configuration
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		name, rest, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != database {
			continue
		}
		n := 0
		for _, f := range strings.Fields(rest) {
			// Skip action specifiers like [NOTFOUND=return].
			if strings.HasPrefix(f, "[") {
				continue
			}
			n++
		}
		return n
	}
	return 0
}
