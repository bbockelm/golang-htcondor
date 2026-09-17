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

//go:build cgo

package droppriv

import "time"

// selectBestGroupLookup chooses the best available group lookup.
//
// With cgo there is nothing to choose. os/user's GroupIds() calls
// getgrouplist(3), so glibc walks nsswitch.conf itself -- files, sss,
// ldap, winbind, nis, in the administrator's order, honouring every
// service this package could not speak on its own. Consulting SSSD
// separately here would at best duplicate what libc already returned,
// and at worst disagree with the rest of the machine.
func selectBestGroupLookup() GroupLookup {
	return NewStdlibGroups(time.Minute)
}
