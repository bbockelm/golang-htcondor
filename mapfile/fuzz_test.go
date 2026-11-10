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

package mapfile

import (
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
)

func regexpMust(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// FuzzParse checks that no input panics Parse or Map, and that every
// entry Parse keeps can be looked up. @include is refused so the fuzzer
// cannot read files.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		cppHashCanon,
		cppRegexCanon,
		"FS a b\n",
		`GSI "a \"b\\" c` + "\n",
		"FS /^(a)|(b)$/iU [\\1][\\2]\\\n",
		"FS /a\\/b/ x\r\n# c\n\n",
		`FS "unterminated`,
		"FS a \"unterminated\\\n",
		"FS /(?=x)/ y\n",
		"@include /dev/null\n",
		"OIDC /^OSG100012[0-9]$/ *.hpc.example.edu\n",
	} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, text string, regexKeys bool) {
		opts := Options{RegexKeys: regexKeys, NoInclude: true, Logger: slog.New(slog.DiscardHandler)}
		mf, err := opts.Parse(strings.NewReader(text), "fuzz")
		if errors.Is(err, ErrUnsupportedRegex) {
			return
		}
		if err != nil {
			t.Fatalf("Parse with the default error handling failed: %v", err)
		}
		for _, method := range mf.Methods() {
			for _, e := range mf.Entries(method) {
				if e.Method == "" || e.Principal == "" || e.Canonicalization == "" {
					t.Fatalf("empty field in %+v", e)
				}
				mf.Map(method, e.Principal)
				mf.Map(method, e.Canonicalization)
			}
		}
		_, _ = Options{RegexKeys: regexKeys, NoInclude: true, OnError: fatal}.Parse(strings.NewReader(text), "fuzz")
	})
}
