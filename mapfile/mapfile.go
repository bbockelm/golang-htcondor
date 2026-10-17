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

// Package mapfile reads HTCondor map files: the format of
// CERTIFICATE_MAPFILE and CLASSAD_USER_MAPFILE_<name>, implemented in C++
// by MapFile (src/condor_utils/MapFile.cpp).
//
// Each line is
//
//	<method> <principal> <canonicalization>
//
// separated by spaces or tabs. Anything after the third field is ignored.
// A line whose first field is empty or starts with # is skipped.
//
// Fields are read as MapFile::ParseField reads them. A field that starts
// with a double quote runs to the next unescaped double quote and may
// contain spaces; inside it \" is a quote, \\ is one backslash, and any
// other backslash is kept along with the character after it. A closing
// quote need not be followed by white space: the next field starts right
// after it. A quoted field with no closing quote runs to the end of the
// line, including the newline: `FS alice "bob` maps alice to "bob\n",
// and an unclosed method or principal leaves the line without a
// canonicalization.
//
// # Principals
//
// By default (CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true, and always for
// CLASSAD_USER_MAPFILE) a principal is a literal, compared byte for byte,
// unless it is written /like this/, in which case it is a regular
// expression. A regular expression is quoted the way a double-quoted field
// is, with / in place of the quote, and may be followed directly by the
// flags i (case-insensitive) and U (ungreedy). It is searched for, not
// anchored. With Options.RegexKeys (CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS =
// false, HTCondor's default for CERTIFICATE_MAPFILE) every principal is a
// regular expression, slashes are ordinary characters, and no flags are
// recognised.
//
// Regular expressions use Go's regexp (RE2) syntax, not PCRE2. An
// expression that uses backreferences, lookaround, atomic groups,
// possessive quantifiers, verbs, or another construct PCRE2 accepts and
// Go does not makes loading fail with ErrUnsupportedRegex (see Errors).
// Some differences cannot be detected and are accepted: $ matches only at the very end of the
// principal (PCRE2 also matches before a final newline); patterns match
// UTF-8 characters rather than bytes; and the i flag folds non-ASCII
// letters, which HTCondor's PCRE2 does not (/é/i matches É here but not
// in HTCondor).
//
// # Lookup
//
// Methods are compared without regard to ASCII case; "*" has no special
// meaning. Within a method, the first line in file order whose principal
// matches wins, whether that line is a literal or a regular expression.
// (C++ groups consecutive literal lines into one hash table, which is a
// performance detail with the same result.)
//
// The canonicalization is returned with \0 through \9 replaced: for a
// regular expression, \0 is the whole match and \n the n-th group (empty
// if the group did not take part in the match, left as written if no
// group at or beyond n took part); for a literal, \0 is the principal and
// \1 through \9 are left as written. No other backslash sequence is
// interpreted, and \\ is not an escape: \\1 is copied as written.
//
// # @include
//
// A line whose first field is @include reads the file or directory named
// by its second field; a relative path is relative to the directory of
// the file being read. A directory's entries other than subdirectories
// are read in byte order of their names, skipping names that match
// Options.IncludeExclude
// (LOCAL_CONFIG_DIR_EXCLUDE_REGEXP, by default DefaultIncludeExclude). An
// included file may not itself use @include.
//
// # Errors
//
// As in HTCondor, a line that cannot be used is logged and skipped, and
// loading continues. Bad lines are those missing a principal or
// canonicalization, those whose regular expression PCRE2 would refuse
// too, and an @include that names nothing, names a file or directory that
// cannot be read, appears in an included file, or is refused by
// Options.NoInclude. The log record (slog at level Warn, on
// Options.Logger) names the file and line. Set Options.OnError to collect
// bad lines as *ParseError values or to make them fatal. Failing to open
// or read the top-level file is always an error.
//
// A regular expression that Go cannot compile but HTCondor would use is
// not a bad line: HTCondor maps principals by it, so skipping it could
// let a later line map them differently. Loading stops with a *ParseError
// wrapping ErrUnsupportedRegex, whatever Options.OnError does. A Go
// compile error is taken to be such a construct unless it is one PCRE2
// is known to share (an unbalanced parenthesis or bracket, a trailing
// backslash, a quantifier with nothing to repeat or nested in another,
// a reversed range or count, an unknown POSIX class, or an escape PCRE2
// does not define); when in doubt, loading fails.
//
// # Differences from HTCondor
//
//   - A line ending in "\r\n" is read as ending in "\n"; HTCondor keeps
//     the "\r" in the last field it reads.
//   - A backslash ending a canonicalization is dropped; HTCondor appends
//     a NUL, which ends the name wherever it is used as a C string.
//   - A NUL byte is an ordinary character. HTCondor drops the rest of
//     the line after it and joins the next line on.
//   - A failed read of an included file is a bad line and skips the rest
//     of that file, including the part of the line read before the
//     error; HTCondor retries the read, forever if it keeps failing.
//   - MapFile's prefix mode (is_prefix, used for URL maps) and the
//     two-field user map read by GetUser are not implemented.
package mapfile

import (
	"regexp"
	"strings"
)

// Entry is one mapping line.
type Entry struct {
	// Method is the method as written.
	Method string
	// Principal is the literal principal, or the regular expression's
	// source without its slashes and flags.
	Principal string
	// Regex reports whether Principal is a regular expression.
	Regex bool
	// IgnoreCase and Ungreedy are the i and U flags of a regular
	// expression.
	IgnoreCase bool
	Ungreedy   bool
	// Canonicalization is the third field, before any \N substitution.
	Canonicalization string
	// File and Line locate the entry.
	File string
	Line int
}

// rule is an Entry ready for matching.
type rule struct {
	entry Entry
	re    *regexp.Regexp
}

// table is the entries of one method, in file order.
type table struct {
	rules []rule
	// regexes is the index in rules of each regular expression line.
	regexes []int
	// literals maps a literal principal to the index in rules of the
	// first literal line with that principal.
	literals map[string]int
}

func (t *table) add(r rule) {
	idx := len(t.rules)
	t.rules = append(t.rules, r)
	if r.re != nil {
		t.regexes = append(t.regexes, idx)
		return
	}
	if t.literals == nil {
		t.literals = make(map[string]int)
	}
	if _, dup := t.literals[r.entry.Principal]; !dup {
		t.literals[r.entry.Principal] = idx
	}
}

// MapFile is a parsed map file. It is safe for concurrent use once
// loaded.
type MapFile struct {
	// methods is keyed by the ASCII-lowercased method.
	methods map[string]*table
	// order is the methods' keys in order of first appearance.
	order []string
}

// lowerASCII lowercases ASCII letters only, as strcasecmp compares.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func (m *MapFile) add(r rule) {
	key := lowerASCII(r.entry.Method)
	t := m.methods[key]
	if t == nil {
		if m.methods == nil {
			m.methods = make(map[string]*table)
		}
		t = &table{}
		m.methods[key] = t
		m.order = append(m.order, key)
	}
	t.add(r)
}

// Map returns the canonicalization of principal under method, with \N
// substituted, and whether any line matched.
func (m *MapFile) Map(method, principal string) (string, bool) {
	if m == nil {
		return "", false
	}
	t := m.methods[lowerASCII(method)]
	if t == nil {
		return "", false
	}
	lit, haveLit := t.literals[principal]
	for _, i := range t.regexes {
		if haveLit && i > lit {
			break
		}
		if groups, ok := regexGroups(t.rules[i].re, principal); ok {
			return substitute(t.rules[i].entry.Canonicalization, groups), true
		}
	}
	if haveLit {
		return substitute(t.rules[lit].entry.Canonicalization, []string{principal}), true
	}
	return "", false
}

// Entries returns every line for method (compared without regard to ASCII
// case) in file order, including lines that can never match because an
// earlier line always wins.
func (m *MapFile) Entries(method string) []Entry {
	if m == nil {
		return nil
	}
	t := m.methods[lowerASCII(method)]
	if t == nil {
		return nil
	}
	out := make([]Entry, len(t.rules))
	for i := range t.rules {
		out[i] = t.rules[i].entry
	}
	return out
}

// Methods returns each method that has at least one line, as first
// written, in order of first appearance.
func (m *MapFile) Methods() []string {
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(m.order))
	for _, key := range m.order {
		out = append(out, m.methods[key].rules[0].entry.Method)
	}
	return out
}

// Len returns the number of mapping lines.
func (m *MapFile) Len() int {
	if m == nil {
		return 0
	}
	n := 0
	for _, t := range m.methods {
		n += len(t.rules)
	}
	return n
}

// regexGroups searches principal with re and returns the groups as
// pcre2_match reports them: entries up to the highest group that took
// part in the match, with groups that did not take part empty.
func regexGroups(re *regexp.Regexp, principal string) ([]string, bool) {
	loc := re.FindStringSubmatchIndex(principal)
	if loc == nil {
		return nil, false
	}
	n := len(loc) / 2
	for n > 1 && loc[2*(n-1)] < 0 {
		n--
	}
	groups := make([]string, n)
	for i := 0; i < n; i++ {
		if loc[2*i] >= 0 {
			groups[i] = principal[loc[2*i]:loc[2*i+1]]
		}
	}
	return groups, true
}

// substitute is MapFile::PerformSubstitution: \N for a digit N with a
// group is replaced by that group; every other backslash is copied along
// with the character after it.
func substitute(pattern string, groups []string) string {
	if strings.IndexByte(pattern, '\\') < 0 {
		return pattern
	}
	var b strings.Builder
	b.Grow(len(pattern))
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i == len(pattern) {
			// C++ appends a NUL here (and reads past the end of the
			// pattern), which ends the name wherever it is used as a C
			// string: drop the backslash.
			break
		}
		if d := int(pattern[i]) - '0'; d >= 0 && d <= 9 && d < len(groups) {
			b.WriteString(groups[d])
			continue
		}
		b.WriteByte('\\')
		b.WriteByte(pattern[i])
	}
	return b.String()
}
