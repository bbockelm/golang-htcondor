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

package httpserver

import (
	"fmt"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/droppriv"
)

// Group source specs, as they appear in HTTP_API_GROUP_SOURCE.
const (
	groupSourceToken  = "token"
	groupSourceSystem = "system"
	groupSourceFile   = "file:"
)

// ParseGroupSources splits the comma-separated HTTP_API_GROUP_SOURCE.
//
// Whitespace around each entry is trimmed, so "system, file:/etc/x" reads
// the way an administrator would write it.
//
// Mixing "token" with a local source is refused rather than merged. The
// two are different trust bases -- one is what the identity provider
// asserted, the other is what this machine's account database says -- and
// unioning them would mean a provider could add a caller to any group the
// local policy checks. Choosing between them has to be deliberate.
func ParseGroupSources(raw string) ([]string, error) {
	var (
		specs    []string
		hasToken bool
		hasLocal bool
	)
	for _, part := range strings.Split(raw, ",") {
		spec := strings.TrimSpace(part)
		if spec == "" {
			continue
		}
		lower := strings.ToLower(spec)
		switch {
		case lower == groupSourceToken || lower == "oidc":
			hasToken = true
			continue // token contributes no local source
		case lower == groupSourceSystem || lower == "unix":
			hasLocal = true
			specs = append(specs, groupSourceSystem)
		case strings.HasPrefix(lower, groupSourceFile):
			path := strings.TrimSpace(spec[len(groupSourceFile):])
			if path == "" {
				return nil, fmt.Errorf("group source %q names no file", spec)
			}
			hasLocal = true
			specs = append(specs, groupSourceFile+path)
		default:
			return nil, fmt.Errorf("unknown group source %q "+
				"(want \"token\", \"system\", or \"file:<path>\")", spec)
		}
	}

	if hasToken && hasLocal {
		return nil, fmt.Errorf("group sources mix %q with a local source; "+
			"groups come either from the token or from this machine, not both", groupSourceToken)
	}
	return specs, nil
}

// buildGroupSources turns parsed specs into a single lookup, or nil when
// membership comes from the token.
func buildGroupSources(specs []string, ttl time.Duration) droppriv.GroupLookup {
	sources := make([]droppriv.GroupLookup, 0, len(specs))
	for _, spec := range specs {
		switch {
		case spec == groupSourceSystem:
			// Ordered from nsswitch.conf, so this agrees with the rest of
			// the machine rather than preferring a source of its own.
			sources = append(sources, droppriv.NewSystemGroupLookup(ttl))
		case strings.HasPrefix(spec, groupSourceFile):
			// Not cached here: the file re-reads itself when it changes,
			// so an edit takes effect without a restart, and wrapping it
			// in a TTL cache would only delay that.
			sources = append(sources, droppriv.NewFileGroups(spec[len(groupSourceFile):]))
		}
	}
	return droppriv.NewGroupChain(sources...)
}
