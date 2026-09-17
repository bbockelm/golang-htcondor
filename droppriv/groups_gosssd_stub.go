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

//go:build !linux || cgo

package droppriv

// sssdGroupLookup is not used on non-Linux systems or when CGO is enabled.
//
// With cgo, getgrouplist(3) consults sss itself as part of walking
// nsswitch.conf, so there is nothing for a separate SSSD client to add.
//
//nolint:unused // Used in the linux && !cgo build
func sssdGroupLookup() GroupLookup { return nil }
