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
	"fmt"
	"regexp"
	"strings"
)

// compileRegex compiles a principal's regular expression with the i and U
// flags (PCRE2_CASELESS, PCRE2_UNGREEDY).
func compileRegex(src string, ignoreCase, ungreedy bool) (*regexp.Regexp, error) {
	if err := checkPCREOnly(src); err != nil {
		return nil, err
	}
	flags := ""
	if ignoreCase {
		flags += "i"
	}
	if ungreedy {
		flags += "U"
	}
	if flags != "" {
		src = "(?" + flags + ")" + src
	}
	return regexp.Compile(src)
}

// pcreGroups are group openers PCRE2 accepts and RE2 does not.
var pcreGroups = []struct{ prefix, name string }{
	{"(?=", "lookahead"},
	{"(?!", "negative lookahead"},
	{"(?<=", "lookbehind"},
	{"(?<!", "negative lookbehind"},
	{"(?>", "atomic group"},
}

// checkPCREOnly refuses PCRE2 constructs that Go's regexp either rejects
// with a less helpful message or reads differently: a backslash and digit
// 1-9 outside a character class is a backreference to PCRE2 but an octal
// escape (or an error) to Go. Anything else Go cannot compile is left to
// regexp.Compile to report.
func checkPCREOnly(src string) error {
	inClass := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\\':
			if i+1 >= len(src) {
				return nil
			}
			n := src[i+1]
			if n == 'Q' {
				end := strings.Index(src[i+2:], `\E`)
				if end < 0 {
					return nil
				}
				i += 2 + end + 1
				continue
			}
			if !inClass && ((n >= '1' && n <= '9') || n == 'g' || n == 'k') {
				return fmt.Errorf("backreference \\%c is not supported by Go regular expressions", n)
			}
			i++
		case inClass:
			switch c {
			case '[':
				i = skipPOSIXClass(src, i)
			case ']':
				inClass = false
			}
		case c == '[':
			inClass = true
			if i+1 < len(src) && src[i+1] == '^' {
				i++
			}
			if i+1 < len(src) && src[i+1] == ']' {
				i++
			}
		case c == '(':
			for _, g := range pcreGroups {
				if strings.HasPrefix(src[i:], g.prefix) {
					return fmt.Errorf("%s %s is not supported by Go regular expressions", g.name, g.prefix)
				}
			}
		}
	}
	return nil
}

// skipPOSIXClass returns the index of the closing "]" of a [:name:] or
// [:^name:] starting at src[i], or i if there is none.
func skipPOSIXClass(src string, i int) int {
	j := i + 1
	if j >= len(src) || src[j] != ':' {
		return i
	}
	j++
	if j < len(src) && src[j] == '^' {
		j++
	}
	for j < len(src) && ((src[j] >= 'a' && src[j] <= 'z') || (src[j] >= 'A' && src[j] <= 'Z')) {
		j++
	}
	if j+1 < len(src) && src[j] == ':' && src[j+1] == ']' {
		return j + 1
	}
	return i
}
