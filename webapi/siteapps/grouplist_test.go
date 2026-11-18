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

package siteapps

import (
	"reflect"
	"testing"
)

// The name that motivated the JSON form: a COmanage group, spaces and
// colons and all.
const cmsConnect = "CO:COU:CMS Connect COU:members:active"

func TestParseGroupListJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		// The comma rule is untouched.
		{"comma list", "smith_lab, jones_lab", []string{"smith_lab", "jones_lab"}},
		// A space inside a name always worked under the comma rule, and
		// still has to: nobody should have to rewrite a working list.
		{"space under the comma rule", cmsConnect, []string{cmsConnect}},

		{"json one name", `["` + cmsConnect + `"]`, []string{cmsConnect}},
		{"json several", `["a", "b"]`, []string{"a", "b"}},
		// What the comma rule cannot spell at all.
		{"json name with a comma", `["Lab, Smith", "wheel"]`, []string{"Lab, Smith", "wheel"}},
		// Verbatim inside the array: a name spelled with a space on the
		// end is spelled that way on purpose.
		{"json keeps edge space", `[" padded "]`, []string{" padded "}},
		{"json whitespace around the array", "  [\"a\"]\n", []string{"a"}},
		{"json drops empty names", `["a", "", "b"]`, []string{"a", "b"}},
		// An empty array says what an empty value says.
		{"json empty array", `[]`, nil},

		// Malformed JSON falls back to the comma rule rather than to
		// nothing: an empty list opens the gates that read one.
		{"unterminated array", `["a", "b"`, []string{`["a"`, `"b"`}},
		{"not an array of strings", `[1, 2]`, []string{"[1", "2]"}},
		{"nested", `[["a"]]`, []string{`[["a"]]`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseGroupList(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseGroupList(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

// A malformed JSON list must never read as "no group required", which is
// how the access gates read an empty list.
func TestParseGroupListMalformedJSONIsNotEmpty(t *testing.T) {
	for _, in := range []string{`["a"`, `[1]`, `[`, `[{"name": "a"}]`} {
		if got := ParseGroupList(in); len(got) == 0 {
			t.Errorf("ParseGroupList(%q) = %#v; a malformed list must not read as no requirement", in, got)
		}
	}
}

func TestParseJSONGroupList(t *testing.T) {
	if _, ok := parseJSONGroupList("a, b"); ok {
		t.Error("a comma list reported as JSON")
	}
	if got, ok := parseJSONGroupList(`["a b"]`); !ok || !reflect.DeepEqual(got, []string{"a b"}) {
		t.Errorf("parseJSONGroupList = %#v, %v", got, ok)
	}
	// An array that does not parse is not a JSON list, so ParseGroupList
	// applies the comma rule to it rather than seeing an empty one.
	if got, ok := parseJSONGroupList(`["a"`); ok {
		t.Errorf("malformed array reported as JSON: %#v", got)
	}
}

// What is stored has to read back as what was stored.
func TestFormatGroupListRoundTrip(t *testing.T) {
	cases := [][]string{
		nil,
		{"smith_lab"},
		{"smith_lab", "jones_lab"},
		{cmsConnect},
		{"Lab, Smith", "wheel"},
		{" padded "},
		{`["literal"]`},
		{"*"},
	}
	for _, groups := range cases {
		stored := FormatGroupList(groups)
		got := ParseGroupList(stored)
		if len(groups) == 0 && len(got) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, groups) {
			t.Errorf("FormatGroupList(%#v) = %q, read back as %#v", groups, stored, got)
		}
	}
}

// The plain case keeps the spelling rows already in the database have.
func TestFormatGroupListPrefersCommas(t *testing.T) {
	if got := FormatGroupList([]string{"smith_lab", "jones_lab"}); got != "smith_lab,jones_lab" {
		t.Errorf("FormatGroupList = %q, want the comma form", got)
	}
	if got := FormatGroupList([]string{"Lab, Smith"}); got != `["Lab, Smith"]` {
		t.Errorf("FormatGroupList = %q, want JSON for a name holding a comma", got)
	}
}
