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
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/bbockelm/gosssd"
)

// This file speaks the SSSD client socket directly rather than going
// through libc, which means it also owns the housekeeping an NSS module
// would otherwise do for it -- in particular noticing that the daemon on
// the other end of a cached connection has gone away.

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
	client := gosssd.NewClient(opts...)
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("SSSD not available: %w", err)
	}
	sssdAccountsClient = client
	return client, nil
}

// dropSSSDClient discards a connection that has stopped working so the
// next call dials a fresh one.
//
// It drops the shared client only if it is still the one that failed:
// a concurrent caller may already have replaced it, and closing that
// replacement would turn one dead connection into a stream of them.
func dropSSSDClient(stale *gosssd.Client) {
	sssdAccountsMu.Lock()
	defer sssdAccountsMu.Unlock()
	if sssdAccountsClient != stale {
		return
	}
	sssdAccountsClient = nil
	_ = stale.Close()
}

// onSSSD runs fn against the shared connection and, if it fails, re-dials
// and runs it once more.
//
// The connection is cached for the life of the process; SSSD is not. A
// config reload, a crash or a supervisor restart leaves the cached socket
// dead, and gosssd does not reconnect on its own -- sendRequest fails with
// "not connected" and keeps doing so. Without this retry a single SSSD
// restart disables every directory lookup until the daemon using this
// package is itself restarted.
//
// Retrying on ANY error, rather than trying to recognise a connection
// error, is deliberate: these operations are idempotent reads, so the
// cost of a needless second attempt is one round trip, whereas the cost
// of failing to recognise a dead socket is a silently degraded process.
func onSSSD[T any](fn func(*gosssd.Client) (T, error)) (T, error) {
	var zero T
	client, err := sssdAccountClient()
	if err != nil {
		return zero, err
	}
	result, err := fn(client)
	if err == nil {
		return result, nil
	}

	dropSSSDClient(client)
	fresh, dialErr := sssdAccountClient()
	if dialErr != nil {
		// Report both: the first error says what broke, the second says
		// that reconnecting did not help either.
		return zero, errors.Join(err, dialErr)
	}
	return fn(fresh)
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
	users, err := onSSSD(func(c *gosssd.Client) ([]*gosssd.User, error) {
		return c.EnumerateUsers()
	})
	if err != nil {
		return nil, fmt.Errorf("enumerating accounts from SSSD at %s: %w", sssdAccountsPath, err)
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
	return accounts, nil
}

func gecosFromSSSD(username string) (string, bool) {
	if username == "" || !sssdAvailable() {
		return "", false
	}
	u, err := onSSSD(func(c *gosssd.Client) (*gosssd.User, error) {
		return c.GetUserByName(username)
	})
	if err != nil || u == nil || u.Name != username {
		return "", false
	}
	gecos, _, _ := strings.Cut(u.Gecos, ",")
	return gecos, true
}
