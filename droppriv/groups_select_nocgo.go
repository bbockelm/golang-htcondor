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
	"fmt"
	"time"
)

// selectBestGroupLookup chooses the best available group lookup.
//
// Without cgo, os/user's GroupIds() reads /etc/group directly instead of
// calling getgrouplist(3). That covers "files" and nothing else: a
// directory-backed account comes back a member of only its primary group,
// which reads as "no permissions" rather than as the gap it is. The
// missing services are added back here, in the order nsswitch.conf gives,
// so this agrees with the rest of the machine rather than preferring a
// source of its own.
func selectBestGroupLookup() GroupLookup {
	methods, err := ParseNSSwitchDB(nsswitchPath(), "group")
	if err != nil {
		// Unreadable, so where membership comes from is genuinely unknown.
		// Read what we can and mark it degraded rather than guessing.
		return &groupChain{sources: []GroupLookup{
			NewStdlibGroups(time.Minute),
			&unsupportedMethod{
				method: "unknown",
				reason: fmt.Sprintf("%s could not be read: %v", nsswitchPath(), err),
			},
		}}
	}

	declared := countDeclaredMethods(nsswitchPath(), "group")

	var sources []GroupLookup
	for _, m := range methods {
		switch m {
		case NSSSwitchMethodFiles:
			sources = append(sources, NewStdlibGroups(time.Minute))
		case NSSSwitchMethodSSS:
			if s := sssdGroupLookup(); s != nil {
				sources = append(sources, s)
			}
		}
	}
	if len(sources) == 0 {
		sources = append(sources, NewStdlibGroups(time.Minute))
	}

	// The line named methods this package cannot speak. Record that rather
	// than quietly answering from the subset it can.
	if declared > len(methods) {
		sources = append(sources, &unsupportedMethod{
			method: "an NSS method this build cannot speak (ldap, winbind, or nis)",
			reason: fmt.Sprintf("%s declares %d group sources, %d of which are supported without cgo",
				nsswitchPath(), declared, len(methods)),
		})
	}
	return &groupChain{sources: sources}
}
