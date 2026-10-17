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
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
)

// ErrUnsupportedRegex marks a regular expression that HTCondor's PCRE2
// would use but Go's regexp cannot evaluate. A line with one stops the
// load whatever Options.OnError does: skipping it would let a later line
// map principals that HTCondor maps by this one.
var ErrUnsupportedRegex = errors.New("not supported by Go regular expressions")

// compileRegex compiles a principal's regular expression with the i and U
// flags (PCRE2_CASELESS, PCRE2_UNGREEDY). The error wraps
// ErrUnsupportedRegex unless PCRE2 would refuse src too.
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
	re, err := regexp.Compile(src)
	if err != nil && !pcreRejects(err) {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedRegex, err)
	}
	return re, err
}

// pcreRejectedEscapes are the letters PCRE2 refuses after a backslash.
// Go refuses them too, along with many PCRE2 accepts (\h, \K, \R, \G...).
const pcreRejectedEscapes = "FIJLMOTUYijlmquy"

// pcreRejects reports whether PCRE2 also refuses a pattern Go's regexp
// refused with err. It is true only for errors known to be errors in both;
// anything else is taken to be a construct only PCRE2 supports.
func pcreRejects(err error) bool {
	var se *syntax.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code {
	case syntax.ErrMissingParen, syntax.ErrUnexpectedParen, syntax.ErrMissingBracket,
		syntax.ErrTrailingBackslash, syntax.ErrMissingRepeatArgument:
		return true
	case syntax.ErrInvalidCharRange:
		// A reversed range or an unknown POSIX class, but not a Unicode
		// property Go lacks (\p{Xan}) or PCRE2's [[:<:]] and [[:>:]].
		return !strings.HasPrefix(se.Expr, `\p`) && !strings.HasPrefix(se.Expr, `\P`) &&
			se.Expr != "[:<:]" && se.Expr != "[:>:]"
	case syntax.ErrInvalidEscape:
		return len(se.Expr) == 2 && strings.IndexByte(pcreRejectedEscapes, se.Expr[1]) >= 0
	case syntax.ErrInvalidRepeatOp:
		// ** or {2}{3}; a trailing + is a possessive quantifier.
		return !strings.HasSuffix(se.Expr, "+")
	case syntax.ErrInvalidRepeatSize:
		// {2,1} or a count over 65535; Go's limit of 1000 is lower.
		return badPCRERepeat(se.Expr)
	}
	return false
}

// badPCRERepeat reports whether a {n}, {n,} or {n,m} repeat is out of
// order or over PCRE2's limit of 65535.
func badPCRERepeat(expr string) bool {
	i := strings.LastIndexByte(expr, '{')
	if i < 0 || !strings.HasSuffix(expr, "}") {
		return false
	}
	lo, hi, _ := strings.Cut(expr[i+1:len(expr)-1], ",")
	n, err := strconv.Atoi(lo)
	if err != nil || n > 65535 {
		return err == nil
	}
	if hi == "" {
		return false
	}
	m, err := strconv.Atoi(hi)
	return err == nil && (m > 65535 || m < n)
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
// with a less helpful or misleading error, or reads differently: a
// backslash and digit 1-9 outside a character class is a backreference to
// PCRE2 but an octal escape (or an error) to Go, and (*VERB) is an error
// Go shares with a bare (*). Anything else Go cannot compile is left to
// regexp.Compile to report. The error wraps ErrUnsupportedRegex.
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
				return fmt.Errorf("%w: backreference \\%c", ErrUnsupportedRegex, n)
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
					return fmt.Errorf("%w: %s %s", ErrUnsupportedRegex, g.name, g.prefix)
				}
			}
			if i+2 < len(src) && src[i+1] == '*' && (src[i+2] == ':' || isASCIILetter(src[i+2])) {
				return fmt.Errorf("%w: verb or option (*", ErrUnsupportedRegex)
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
	for j < len(src) && isASCIILetter(src[j]) {
		j++
	}
	if j+1 < len(src) && src[j] == ':' && src[j+1] == ']' {
		return j + 1
	}
	return i
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
