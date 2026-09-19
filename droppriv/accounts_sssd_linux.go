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

//go:build linux

package droppriv

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/bbockelm/gosssd"
)

// This file speaks the SSSD client socket directly rather than going
// through libc.
//
// Reconnecting is gosssd's job as of v0.0.4: it dials on demand and
// retries a request whose connection has died, so a restarted SSSD or a
// socket that appears late no longer disables lookups for the life of the
// process. This package used to carry that retry itself.

var sssdAccountsPath = gosssd.DefaultNSSSocketPath

var (
	sssdAccountsMu     sync.Mutex
	sssdAccountsClient *gosssd.Client
)

// sssdAvailable reports whether an SSSD socket exists at all.
//
// A host with no SSSD is the ordinary case, not a fault: the directory
// half of the enumeration is simply empty and the caller proceeds with
// the passwd file. It is checked per call rather than once, because in a
// container the socket routinely appears AFTER this process starts.
func sssdAvailable() bool {
	_, err := os.Stat(sssdAccountsPath)
	return err == nil
}

func sssdAccountClient() (*gosssd.Client, error) {
	sssdAccountsMu.Lock()
	defer sssdAccountsMu.Unlock()
	if sssdAccountsClient != nil {
		return sssdAccountsClient, nil
	}

	opts := []gosssd.ClientOption{}
	if sssdAccountsPath != gosssd.DefaultNSSSocketPath {
		opts = append(opts, gosssd.WithSocketPath(sssdAccountsPath))
	}
	// No eager Connect: gosssd dials on demand, so a client built before
	// SSSD is listening is not stillborn, and it redials a connection the
	// daemon has since dropped. Both used to be this package's problem.
	client := gosssd.NewClient(opts...)
	sssdAccountsClient = client
	return client, nil
}

// enumerateSSSDAccounts lists the accounts SSSD knows about.
//
// A nil error with no accounts means SSSD has nothing to add -- either it
// is not running here, or the domain is not configured with
// "enumerate = true". A non-nil error means the directory could not be
// read, which is a different situation entirely and must not be reported
// as an empty directory: an index silently missing every directory
// account refuses logins that ought to work.
func enumerateSSSDAccounts() ([]Account, error) {
	if !sssdAvailable() {
		return nil, nil
	}
	client, err := sssdAccountClient()
	if err != nil {
		return nil, err
	}
	users, err := client.EnumerateUsers()
	if err != nil {
		return nil, fmt.Errorf("enumerating accounts from SSSD at %s: %w", sssdAccountsPath, err)
	}

	return accountsFromSSSDUsers(users)
}

// accountsFromSSSDUsers converts an enumeration result, and decides what
// an empty one means. Split out so the decision can be tested without
// standing up a directory that answers but has nothing in it.
func accountsFromSSSDUsers(users []*gosssd.User) ([]Account, error) {
	accounts := make([]Account, 0, len(users))
	for _, u := range users {
		if u == nil || u.Name == "" {
			continue
		}
		gecos, _, _ := strings.Cut(u.Gecos, ",")
		accounts = append(accounts, Account{
			Username: u.Name,
			UID:      u.UID,
			GID:      u.GID,
			Gecos:    gecos,
		})
	}
	if len(accounts) == 0 {
		// SSSD is here and told us about nobody. That is a fact, not a
		// guess, and it has exactly two causes: the domain does not set
		// "enumerate = true", or SSSD has not finished its first pass over
		// the directory -- which on a real directory takes minutes, and in
		// a container overlaps every start.
		//
		// Either way this process does not know the directory's accounts,
		// so the resulting index must not be treated as authoritative:
		// not persisted, and not allowed to replace one that is.
		return nil, ErrDirectoryEmpty
	}
	return accounts, nil
}

func gecosFromSSSD(username string) (string, bool) {
	if username == "" || !sssdAvailable() {
		return "", false
	}
	client, err := sssdAccountClient()
	if err != nil {
		return "", false
	}
	u, err := client.GetUserByName(username)
	if err != nil || u == nil || u.Name != username {
		return "", false
	}
	gecos, _, _ := strings.Cut(u.Gecos, ",")
	return gecos, true
}
