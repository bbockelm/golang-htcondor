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
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseGroupSources(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"the default, groups from the token", "token", nil},
		{"one local source", "system", []string{"system"}},
		{"a file the directory cannot provide", "file:/etc/htcondor-api/groups",
			[]string{"file:/etc/htcondor-api/groups"}},
		{"both, which is the point of a list", "system, file:/etc/extra-groups",
			[]string{"system", "file:/etc/extra-groups"}},
		{"whitespace is the administrator's, not ours", "  system ,  file:/x  ",
			[]string{"system", "file:/x"}},
		{"legacy spellings still parse", "unix", []string{"system"}},
		{"empty entries are ignored", "system,,", []string{"system"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseGroupSources(tc.in)
			if err != nil {
				t.Fatalf("ParseGroupSources(%q): %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// Token groups and local groups are different trust bases: one is what
// the identity provider asserted, the other is what this machine says.
// Unioning them would let a provider add a caller to any group the local
// policy checks, so the combination is refused rather than quietly
// resolved one way.
func TestMixingTokenAndLocalGroupSourcesIsRefused(t *testing.T) {
	for _, in := range []string{"token, system", "system, token", "token,file:/x"} {
		if _, err := ParseGroupSources(in); err == nil {
			t.Errorf("ParseGroupSources(%q) was accepted; it mixes trust bases", in)
		}
	}
}

func TestUnusableGroupSourcesAreRefused(t *testing.T) {
	for _, in := range []string{"ldap", "file:", "file:  ", "system, nonsense"} {
		_, err := ParseGroupSources(in)
		if err == nil {
			t.Errorf("ParseGroupSources(%q) was accepted", in)
			continue
		}
		// The message has to name the offender, or an operator is left
		// bisecting their own config string.
		if !strings.Contains(err.Error(), "group source") && !strings.Contains(err.Error(), "mix") {
			t.Errorf("ParseGroupSources(%q) error does not say what was wrong: %v", in, err)
		}
	}
}

func TestBuildGroupSources(t *testing.T) {
	if got := buildGroupSources(nil, time.Minute); got != nil {
		t.Errorf("got %v; no sources means the token's claim is kept", got)
	}

	one := buildGroupSources([]string{"file:/tmp/x"}, time.Minute)
	if one == nil || one.Name() != "file:/tmp/x" {
		t.Errorf("single source Name = %v", one)
	}

	both := buildGroupSources([]string{"system", "file:/tmp/x"}, time.Minute)
	if both == nil {
		t.Fatal("no lookup was built")
	}
	// Both must appear, or one of the administrator's sources is silently
	// not being consulted.
	name := both.Name()
	if !strings.Contains(name, "file:/tmp/x") {
		t.Errorf("Name = %q; the file source is missing", name)
	}
	if !strings.Contains(name, "sssd") && !strings.Contains(name, "stdlib") && !strings.Contains(name, "getgrouplist") {
		t.Errorf("Name = %q; the system source is missing", name)
	}
}
