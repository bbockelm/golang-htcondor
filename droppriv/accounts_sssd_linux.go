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

// Account enumeration and GECOS lookup through SSSD.
//
// Deliberately NOT gated on cgo, unlike the group lookup beside it. That
// one is !cgo-only because getgrouplist(3) already walks every NSS service
// when cgo is available, so asking SSSD as well would duplicate it. There
// is no equivalent here: os/user has no enumeration call in EITHER build
// mode -- it can look an account up and cannot list them -- so a
// directory-backed deployment needs this however the binary was built.
//
// SSSD answers enumeration only when the domain sets "enumerate = true".
// That is off by default and discouraged for large directories, so an
// empty result is the normal case, not a failure, and is reported as such.

// sssdAccountsPath is the socket probed before dialling. A variable so a
// test can point it at one it is allowed to create.
var sssdAccountsPath = gosssd.DefaultNSSSocketPath

var (
	sssdAccountsMu     sync.Mutex
	sssdAccountsClient *gosssd.Client
)

// sssdAvailable reports whether an SSSD client socket is present.
//
// Its presence is a deliberate act -- sssd is running, or somebody mounted
// the pipe directory into a container -- and dialling a socket that is not
// there costs a connection attempt on every index rebuild.
func sssdAvailable() bool {
	_, err := os.Stat(sssdAccountsPath)
	return err == nil
}

// sssdAccountClient returns a connected client, dialling on first use.
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
	client := gosssd.NewClient(opts...)
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("SSSD not available: %w", err)
	}
	sssdAccountsClient = client
	return client, nil
}

// enumerateSSSDAccounts lists the accounts SSSD is willing to enumerate.
//
// Returns nothing, without error, when SSSD is not reachable or the domain
// does not enumerate: a caller merging this with a passwd file wants the
// file's accounts either way, and neither case means the directory is
// broken.
func enumerateSSSDAccounts() []Account {
	if !sssdAvailable() {
		return nil
	}
	client, err := sssdAccountClient()
	if err != nil {
		return nil
	}
	users, err := client.EnumerateUsers()
	if err != nil {
		return nil
	}

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
	return accounts
}

// gecosFromSSSD returns an account's GECOS name from the directory.
//
// The counterpart to enumeration: an index entry that cannot be verified is
// refused, so enumerating the directory without being able to look one of
// its accounts up again would map nobody.
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
