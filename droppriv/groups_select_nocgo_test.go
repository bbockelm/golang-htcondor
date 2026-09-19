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

//go:build !cgo

package droppriv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireSSSDClient skips where the SSSD client is not compiled in.
//
// It is linux-only (see groups_gosssd_stub.go), so without this the tests
// below fail on a developer's macOS checkout while passing in CI -- the
// failure mode that makes people stop trusting a suite.
func requireSSSDClient(t *testing.T) {
	t.Helper()
	if sssdGroupLookup() == nil {
		t.Skip("the SSSD client is only built on linux")
	}
}

// withSocket points the SSSD probe at a file the test controls.
func withSocket(t *testing.T, present bool) {
	t.Helper()
	old := sssdSocketPath
	t.Cleanup(func() { sssdSocketPath = old })

	path := filepath.Join(t.TempDir(), "nss")
	if present {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sssdSocketPath = path
}

func withNSSwitch(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nsswitch.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := nsswitchPath()
	SetNSSSwitchPath(path)
	t.Cleanup(func() { SetNSSSwitchPath(old) })
}

// The deployment case this exists for: an Alpine/musl container, whose
// nsswitch.conf carries only a `hosts:` line because musl does not
// implement NSS, with an SSSD socket mounted in from a sidecar.
//
// Honouring the "files" default literally would ignore that socket and
// leave every directory user a member of nothing -- not an error, just an
// empty list, which reads downstream as "no permissions".
func TestMuslContainerConsultsAMountedSSSDSocket(t *testing.T) {
	requireSSSDClient(t)
	withNSSwitch(t, "# musl does not support NSS\nhosts: files dns\n")
	withSocket(t, true)

	name := selectBestGroupLookup().Name()
	if !strings.Contains(name, "sssd") {
		t.Errorf("chain = %q; a mounted SSSD socket was ignored", name)
	}
	// And it must not be marked degraded: files + sss is the whole of
	// what this container can consult, so the answer is complete.
	if strings.Contains(name, "unsupported") {
		t.Errorf("chain = %q, want a complete read", name)
	}
}

// Without the socket there is nothing to consult, and nothing to claim.
func TestNoGroupLineAndNoSocketStaysFiles(t *testing.T) {
	withNSSwitch(t, "hosts: files dns\n")
	withSocket(t, false)

	name := selectBestGroupLookup().Name()
	if strings.Contains(name, "sssd") {
		t.Errorf("chain = %q; there is no socket to consult", name)
	}
}

// An administrator who wrote `group: files` made a statement, and a
// socket happening to exist must not override it.
func TestAnExplicitFilesLineIsNotOverridden(t *testing.T) {
	requireSSSDClient(t)
	withNSSwitch(t, "group: files\nhosts: files dns\n")
	withSocket(t, true)

	name := selectBestGroupLookup().Name()
	if strings.Contains(name, "sssd") {
		t.Errorf("chain = %q; `group: files` is an explicit choice", name)
	}
}

// And an explicit `group: files sss` still works the way it always did.
func TestAnExplicitSSSLineIsHonoured(t *testing.T) {
	requireSSSDClient(t)
	withNSSwitch(t, "group: files sss\n")
	withSocket(t, false) // presence is irrelevant once the line says sss

	name := selectBestGroupLookup().Name()
	if !strings.Contains(name, "sssd") {
		t.Errorf("chain = %q, want sssd from the explicit line", name)
	}
}
