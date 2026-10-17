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
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

// fatal makes every bad line stop the load.
func fatal(e *ParseError) error { return e }

// logRecord is a log record reduced to what the tests check.
type logRecord struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

// captureHandler is a slog.Handler that keeps every record.
type captureHandler struct {
	mu      sync.Mutex
	records []logRecord
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *captureHandler) WithGroup(string) slog.Handler            { return h }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := logRecord{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, rec)
	return nil
}

func (h *captureHandler) get() []logRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]logRecord(nil), h.records...)
}

// checkLogged checks that recs are Warn records naming file and each of
// lines, in order.
func checkLogged(t *testing.T, recs []logRecord, file string, lines ...string) {
	t.Helper()
	if len(recs) != len(lines) {
		t.Fatalf("logged %d records, want %d: %+v", len(recs), len(lines), recs)
	}
	for i, line := range lines {
		r := recs[i]
		if r.level != slog.LevelWarn || r.attrs["file"] != file || r.attrs["line"] != line || r.attrs["error"] == "" {
			t.Errorf("record %d = %+v, want Warn at %s:%s with an error", i, r, file, line)
		}
	}
}

func mustParse(t *testing.T, o Options, text string) *MapFile {
	t.Helper()
	mf, err := o.Parse(strings.NewReader(text), "test.map")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return mf
}

type lookup struct {
	method, principal string
	want              string // "" means no match
}

func checkLookups(t *testing.T, mf *MapFile, lookups []lookup) {
	t.Helper()
	for _, l := range lookups {
		got, ok := mf.Map(l.method, l.principal)
		if l.want == "" {
			if ok {
				t.Errorf("Map(%q, %q) = %q, want no match", l.method, l.principal, got)
			}
			continue
		}
		if !ok || got != l.want {
			t.Errorf("Map(%q, %q) = %q, %v; want %q", l.method, l.principal, got, ok, l.want)
		}
	}
}

// The data and lookups of src/condor_utils/test_user_mapping.cpp.
const cppRegexCanon = "FS (.*) \\1\n" +
	"KERBEROS (.*) \\1\n" +
	"CLAIMTOBE john john\n" +
	"CLAIMTOBE billg billg\n" +
	"CLAIMTOBE pjfry pjfry\n" +
	"CLAIMTOBE smiller.* smiller\n" +
	"CLAIMTOBE swinger swinger\n" +
	"CLAIMTOBE j.*r jackmiller\n" +
	"CLAIMTOBE (.*) some_\\1\n" +
	"GSI /C=US/ST=Wisconsin/L=Madison/O=CHTC/O=TEST/CN=CA jmiller\n" +
	"GSI /C=US/ST=Wisconsin/L=Madison/O=CHTC/O=TEST/CN=CERT jmiller\n" +
	"GSI \"/DC=com/DC=DigiCert-Grid/O=Open Science Grid/OU=People/CN=Jack Miller\" jmiller\n"

const cppHashCanon = "FS /(.*)/ \\1\n" +
	"KERBEROS /.*/ \\0\n" +
	"CLAIMTOBE john john\n" +
	"CLAIMTOBE billg billg\n" +
	"CLAIMTOBE pjfry pjfry\n" +
	"CLAIMTOBE swinger swinger\n" +
	"CLAIMTOBE /smiller.*/ smiller\n" +
	"CLAIMTOBE /j.*r/ jackmiller\n" +
	"CLAIMTOBE /.*/ some_\\0\n" +
	"GSI \"/C=US/ST=Wisconsin/L=Madison/O=CHTC/O=TEST/CN=CA\" jmiller\n" +
	"GSI \"/C=US/ST=Wisconsin/L=Madison/O=CHTC/O=TEST/CN=CERT\" jmiller\n" +
	"GSI \"/DC=com/DC=DigiCert-Grid/O=Open Science Grid/OU=People/CN=Jack Miller\" jmiller\n"

var cppLookups = []lookup{
	{"FS", "Alice", "Alice"},
	{"FS", "Bob", "Bob"},
	{"FS", "john", "john"},
	{"FS", "billg", "billg"},
	{"FS", "pjfry", "pjfry"},
	{"FS", "uncle", "uncle"},
	{"FS", "swinger", "swinger"},
	{"FS", "jmiller", "jmiller"},
	{"KERBEROS", "Alice", "Alice"},
	{"KERBEROS", "Bob", "Bob"},
	{"KERBEROS", "john", "john"},
	{"KERBEROS", "uncle", "uncle"},
	{"KERBEROS", "jmiller", "jmiller"},
	{"CLAIMTOBE", "Alice", "some_Alice"},
	{"CLAIMTOBE", "Bob", "some_Bob"},
	{"CLAIMTOBE", "john", "john"},
	{"CLAIMTOBE", "billg", "billg"},
	{"CLAIMTOBE", "pjfry", "pjfry"},
	{"CLAIMTOBE", "uncle", "some_uncle"},
	{"CLAIMTOBE", "swinger", "swinger"},
	{"CLAIMTOBE", "jmiller", "jackmiller"},
	{"GSI", "/C=US/ST=Wisconsin/L=Madison/O=CHTC/O=TEST/CN=CA", "jmiller"},
	{"GSI", "/C=US/ST=Wisconsin/L=Madison/O=CHTC/O=TEST/CN=CERT", "jmiller"},
	{"GSI", "/DC=com/DC=DigiCert-Grid/O=Open Science Grid/OU=People/CN=Jack Miller", "jmiller"},
	{"GSI", "/DC=com/DC=DigiCert-Grid/O=Open Science Grid/OU=People/CN=John Miller", ""},
}

func TestCppUnitTestRegexMode(t *testing.T) {
	mf := mustParse(t, Options{RegexKeys: true}, cppRegexCanon)
	checkLookups(t, mf, cppLookups)
}

func TestCppUnitTestHashMode(t *testing.T) {
	mf := mustParse(t, Options{}, cppHashCanon)
	checkLookups(t, mf, cppLookups)
}

func TestFields(t *testing.T) {
	tests := []struct {
		name  string
		opts  Options
		line  string
		entry Entry // File and Line are not compared
	}{
		{"plain", Options{}, "FS alice bob", Entry{Method: "FS", Principal: "alice", Canonicalization: "bob"}},
		{"tabs and leading space", Options{}, " \tFS\talice\t\tbob", Entry{Method: "FS", Principal: "alice", Canonicalization: "bob"}},
		{"trailing fields ignored", Options{}, "FS alice bob carol # c", Entry{Method: "FS", Principal: "alice", Canonicalization: "bob"}},
		{"quoted principal is literal", Options{}, `GSI "a b.c" bob`, Entry{Method: "GSI", Principal: "a b.c", Canonicalization: "bob"}},
		{"escaped quote", Options{}, `GSI "a \"b\"" bob`, Entry{Method: "GSI", Principal: `a "b"`, Canonicalization: "bob"}},
		{"escaped backslash", Options{}, `GSI "a\\b" bob`, Entry{Method: "GSI", Principal: `a\b`, Canonicalization: "bob"}},
		{"other escape kept", Options{}, `GSI "a\nb" bob`, Entry{Method: "GSI", Principal: `a\nb`, Canonicalization: "bob"}},
		{"unquoted backslashes verbatim", Options{}, `FS a\\b c\\d`, Entry{Method: "FS", Principal: `a\\b`, Canonicalization: `c\\d`}},
		{"quoted method", Options{}, `"F S" a b`, Entry{Method: "F S", Principal: "a", Canonicalization: "b"}},
		{"quoted canonicalization", Options{}, `FS a "b \"c\\d"`, Entry{Method: "FS", Principal: "a", Canonicalization: `b "c\d`}},
		{"slash canonicalization is literal", Options{}, `FS a /b/`, Entry{Method: "FS", Principal: "a", Canonicalization: "/b/"}},
		{"regex", Options{}, `FS /^a b$/ c`, Entry{Method: "FS", Principal: "^a b$", Regex: true, Canonicalization: "c"}},
		{"regex escaped slash", Options{}, `FS /a\/b/ c`, Entry{Method: "FS", Principal: "a/b", Regex: true, Canonicalization: "c"}},
		{"regex escaped backslash halves", Options{}, `FS /a\\d/ c`, Entry{Method: "FS", Principal: `a\d`, Regex: true, Canonicalization: "c"}},
		{"regex other escape kept", Options{}, `FS /a\d/ c`, Entry{Method: "FS", Principal: `a\d`, Regex: true, Canonicalization: "c"}},
		{"regex flag i", Options{}, `FS /a/i c`, Entry{Method: "FS", Principal: "a", Regex: true, IgnoreCase: true, Canonicalization: "c"}},
		{"regex flags iU", Options{}, `FS /a/Ui c`, Entry{Method: "FS", Principal: "a", Regex: true, IgnoreCase: true, Ungreedy: true, Canonicalization: "c"}},
		// ParseField stops at the first character that is not a flag and
		// the next field starts there.
		{"regex then non-flag", Options{}, `FS /a/ix c`, Entry{Method: "FS", Principal: "a", Regex: true, IgnoreCase: true, Canonicalization: "x"}},
		{"quote then text", Options{}, `FS "a"b c`, Entry{Method: "FS", Principal: "a", Canonicalization: "b"}},
		// An unclosed quote runs to the end of the line, newline included.
		{"unterminated canonicalization", Options{}, `FS a "b c`, Entry{Method: "FS", Principal: "a", Canonicalization: "b c\n"}},
		{"unterminated canonicalization ending in backslash", Options{}, `FS a "b\`, Entry{Method: "FS", Principal: "a", Canonicalization: "b\\\n"}},
		{"regex keys: slashes literal", Options{RegexKeys: true}, `GSI /C=US/CN=x/i c`, Entry{Method: "GSI", Principal: "/C=US/CN=x/i", Regex: true, Canonicalization: "c"}},
		{"regex keys: quoted", Options{RegexKeys: true}, `GSI "a b" c`, Entry{Method: "GSI", Principal: "a b", Regex: true, Canonicalization: "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mf := mustParse(t, tt.opts, tt.line+"\n")
			got := mf.Entries(tt.entry.Method)
			if len(got) != 1 {
				t.Fatalf("Entries(%q) = %+v, want one entry", tt.entry.Method, got)
			}
			want := tt.entry
			want.File, want.Line = "test.map", 1
			if got[0] != want {
				t.Errorf("entry = %+v\n          want %+v", got[0], want)
			}
		})
	}
}

func TestSkippedLines(t *testing.T) {
	mf := mustParse(t, Options{}, strings.Join([]string{
		"",
		"   ",
		"\t",
		"# comment FS a b",
		"   # indented comment",
		"#FS a b",
		`"#quoted" a b`,
		`"# unterminated comment`,
		`""`,
		"FS a b",
	}, "\n"))
	if n := mf.Len(); n != 1 {
		t.Fatalf("Len = %d, want 1: %+v", n, mf.Entries("FS"))
	}
	if e := mf.Entries("FS")[0]; e.Line != 10 {
		t.Errorf("Line = %d, want 10", e.Line)
	}
}

func TestLineEndings(t *testing.T) {
	mf := mustParse(t, Options{}, "FS a b\r\nFS c d\r\nFS e f")
	checkLookups(t, mf, []lookup{{"FS", "a", "b"}, {"FS", "c", "d"}, {"FS", "e", "f"}})
}

// An unclosed quote runs to the end of the line: the newline when there
// is one ("\r\n" read as "\n"), else the end of the file.
func TestUnterminatedCanonicalization(t *testing.T) {
	for _, tt := range []struct{ text, want string }{
		{"FS a \"b c\n", "b c\n"},
		{"FS a \"b c\r\n", "b c\n"},
		{"FS a \"b c", "b c"},
		{"FS a \"b\\", "b"},
		{"FS /^(a)$/ \"<\\1>\n", "<a>\n"},
	} {
		h := &captureHandler{}
		mf, err := Options{Logger: slog.New(h)}.Parse(strings.NewReader(tt.text), "m")
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.text, err)
		}
		if got, ok := mf.Map("FS", "a"); !ok || got != tt.want {
			t.Errorf("Parse(%q): Map = %q, %v; want %q", tt.text, got, ok, tt.want)
		}
		if recs := h.get(); len(recs) != 0 {
			t.Errorf("Parse(%q) logged %+v", tt.text, recs)
		}
	}
}

func TestMatching(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		text    string
		lookups []lookup
	}{
		{"method case-insensitive", Options{}, "oidc a b\n", []lookup{
			{"OIDC", "a", "b"}, {"Oidc", "a", "b"}, {"oidc", "a", "b"},
		}},
		{"literal case-sensitive", Options{}, "FS Alice x\n", []lookup{
			{"FS", "Alice", "x"}, {"FS", "alice", ""}, {"FS", "Alice ", ""},
		}},
		{"literal exact not substring", Options{}, "FS abc x\n", []lookup{
			{"FS", "abcd", ""}, {"FS", "zabc", ""},
		}},
		{"star is not a wildcard method", Options{}, "* /.*/ any\n", []lookup{
			{"*", "a", "any"}, {"FS", "a", ""},
		}},
		{"unknown method", Options{}, "FS a b\n", []lookup{{"SSL", "a", ""}}},
		{"regex unanchored", Options{}, "FS /b/ x\n", []lookup{{"FS", "abc", "x"}, {"FS", "ac", ""}}},
		{"regex anchored", Options{}, "FS /^b$/ x\n", []lookup{{"FS", "abc", ""}, {"FS", "b", "x"}}},
		{"regex case flag", Options{}, "FS /^abc$/i x\n", []lookup{{"FS", "ABC", "x"}}},
		{"regex no case flag", Options{}, "FS /^abc$/ x\n", []lookup{{"FS", "ABC", ""}}},
		{"regex empty match allowed", Options{}, "FS /x*/ y\n", []lookup{{"FS", "abc", "y"}}},
		{"regex ungreedy", Options{}, "FS /^(a+)/U [\\1]\nFS2 /^(a+)/ [\\1]\n", []lookup{
			{"FS", "aaa", "[a]"}, {"FS2", "aaa", "[aaa]"},
		}},
		{"quoted principal not regex", Options{}, `FS "a.c" x` + "\n", []lookup{{"FS", "abc", ""}, {"FS", "a.c", "x"}}},
		{"regex keys: every principal is a regex", Options{RegexKeys: true}, "FS a.c x\n", []lookup{{"FS", "abc", "x"}, {"FS", "zzabczz", "x"}}},
		{"regex keys: slashes are part of the pattern", Options{RegexKeys: true}, "FS /^a$/ x\n", []lookup{{"FS", "a", ""}, {"FS", "/^a$/", ""}}},
		{"registrationd lines", Options{}, "OIDC  https://cilogon.org,http://cilogon.org/serverE/users/12345   ce1.example.edu,ce2.example.edu\n" +
			"OIDC  /^OSG100012[0-9]$/                                          *.hpc.example.edu\n", []lookup{
			{"OIDC", "https://cilogon.org,http://cilogon.org/serverE/users/12345", "ce1.example.edu,ce2.example.edu"},
			{"OIDC", "OSG1000123", "*.hpc.example.edu"},
			{"OIDC", "OSG10001234", ""},
			{"oidc", "https://cilogon.org", ""},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkLookups(t, mustParse(t, tt.opts, tt.text), tt.lookups)
		})
	}
}

// The first matching line in file order wins, whether literal or regex.
func TestPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		lookups []lookup
	}{
		{"regex before literal", "FS /^a/ regex\nFS abc literal\n", []lookup{{"FS", "abc", "regex"}}},
		{"literal before regex", "FS abc literal\nFS /^a/ regex\n", []lookup{{"FS", "abc", "literal"}, {"FS", "abd", "regex"}}},
		{"duplicate literal in one run", "FS a first\nFS a second\n", []lookup{{"FS", "a", "first"}}},
		{"duplicate literal across a regex", "FS a first\nFS /^z/ z\nFS a second\n", []lookup{{"FS", "a", "first"}}},
		{"literal between regexes", "FS /^x/ x1\nFS abc lit\nFS /c$/ c\n", []lookup{
			{"FS", "abc", "lit"}, {"FS", "xbc", "x1"}, {"FS", "zzc", "c"},
		}},
		{"first regex wins", "FS /a/ one\nFS /ab/ two\n", []lookup{{"FS", "ab", "one"}}},
		{"methods are separate lists", "FS /.*/ fs\nSSL a ssl\n", []lookup{{"SSL", "a", "ssl"}, {"FS", "a", "fs"}}},
		{"same method different case shares a list", "fs /^a/ lower\nFS abc upper\n", []lookup{{"FS", "abc", "lower"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkLookups(t, mustParse(t, Options{}, tt.text), tt.lookups)
		})
	}
}

func TestSubstitution(t *testing.T) {
	tests := []struct {
		name, line, principal, want string
	}{
		{"literal \\0 is the principal", `FS alice u_\0`, "alice", "u_alice"},
		{"literal \\1 is kept", `FS alice u_\1`, "alice", `u_\1`},
		{"regex groups", `FS /^(\w+)@(\w+)$/ \2.\1`, "bob@site", "site.bob"},
		{"regex \\0 is the whole match", `FS /b+/ [\0]`, "abbbc", "[bbb]"},
		{"unset group below the highest set group is empty", `FS /^(a)?(b)$/ [\1][\2]`, "b", "[][b]"},
		{"group past the highest set group is kept", `FS /^(a)|(b)$/ [\1][\2]`, "a", `[a][\2]`},
		{"group past the pattern's groups is kept", `FS /^(a)$/ \9`, "a", `\9`},
		{"other escapes kept", `FS /^a$/ x\ny\\z`, "a", `x\ny\\z`},
		{"double backslash is not an escape", `FS /^(a)$/ \\1`, "a", `\\1`},
		{"trailing backslash dropped", `FS /^a$/ x\`, "a", "x"},
		{"quoted canonicalization unescaped first", `FS /^(a)$/ "\\1"`, "a", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mf := mustParse(t, Options{}, tt.line+"\n")
			got, ok := mf.Map("FS", tt.principal)
			if !ok || got != tt.want {
				t.Errorf("Map = %q, %v; want %q", got, ok, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name, text string
		line       int
		contains   string
	}{
		{"missing canonicalization", "FS a b\nFS a\n", 2, "expected <method> <principal> <canonicalization>"},
		{"missing principal", "FS\n", 1, "expected"},
		{"empty regex", "FS // x\n", 1, "expected"},
		{"empty quoted principal", `FS "" x` + "\n", 1, "expected"},
		// An unclosed method or principal takes the rest of the line.
		{"unterminated principal", `FS "a b` + "\n", 1, "expected"},
		{"unterminated regex", "FS /a b\n", 1, "expected"},
		{"unterminated method", `"FS a b` + "\n", 1, "expected"},
		{"unterminated @include method", `"@include` + "\n", 1, "expected"},
		{"trailing backslash in principal", `FS "a\`, 1, "expected"},
		// Regular expressions PCRE2 refuses as well.
		{"bad regex", "\n\nFS /a(/ x\n", 3, "missing closing )"},
		{"unexpected paren", "FS /a)/ x\n", 1, "unexpected )"},
		{"missing bracket", "FS /[]/ x\n", 1, "missing closing ]"},
		{"nothing to repeat", "FS /*a/ x\n", 1, "missing argument"},
		{"empty verb", "FS /(*)/ x\n", 1, "missing argument"},
		{"nested repeat", "FS /a**/ x\n", 1, "invalid nested repetition"},
		{"repeat out of order", "FS /a{2,1}/ x\n", 1, "invalid repeat count"},
		{"repeat over PCRE2 limit", "FS /a{65536}/ x\n", 1, "invalid repeat count"},
		{"reversed range", "FS /[z-a]/ x\n", 1, "invalid character class range"},
		{"unknown POSIX class", "FS /[[:foo:]]/ x\n", 1, "invalid character class range"},
		{"unknown escape", `FS /a\y/ x` + "\n", 1, "invalid escape"},
		{"case-changing escape", `FS /\U/ x` + "\n", 1, "invalid escape"},
		{"regex keys bad regex", "FS a( x", 1, "missing closing )"},
		{"regex keys trailing backslash", `FS a\ x` + "\n", 1, "trailing backslash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regexKeys := strings.HasPrefix(tt.name, "regex keys")

			// By default the line is logged and skipped, and the
			// lines around it are kept.
			h := &captureHandler{}
			text := "M before x\n" + tt.text
			want := []lookup{{"M", "before", "x"}}
			if strings.HasSuffix(tt.text, "\n") {
				text += "M after y\n"
				want = append(want, lookup{"M", "after", "y"})
			}
			mf, err := Options{RegexKeys: regexKeys, Logger: slog.New(h)}.Parse(strings.NewReader(text), "test.map")
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			checkLookups(t, mf, want)
			recs := h.get()
			checkLogged(t, recs, "test.map", strconv.Itoa(tt.line+1))
			if !strings.Contains(recs[0].attrs["error"], tt.contains) {
				t.Errorf("logged error %q, want it to contain %q", recs[0].attrs["error"], tt.contains)
			}

			_, err = Options{RegexKeys: regexKeys, OnError: fatal}.Parse(strings.NewReader(tt.text), "test.map")
			var perr *ParseError
			if !errors.As(err, &perr) {
				t.Fatalf("err = %v, want *ParseError", err)
			}
			if perr.File != "test.map" || perr.Line != tt.line {
				t.Errorf("at %s:%d, want test.map:%d", perr.File, perr.Line, tt.line)
			}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("err = %q, want it to contain %q", err, tt.contains)
			}
			if prefix := "test.map:"; !strings.HasPrefix(err.Error(), prefix) {
				t.Errorf("err = %q, want prefix %q", err, prefix)
			}
		})
	}
}

// A regular expression PCRE2 accepts but Go cannot evaluate stops the
// load whatever OnError says: HTCondor would use the line, and skipping it
// lets later lines map principals it maps.
func TestUnsupportedRegexIsFatal(t *testing.T) {
	tests := []struct {
		name, principal, contains string
	}{
		{"backreference", `/(a)\1/`, "backreference"},
		{"named backreference", `/(?P<n>a)\k<n>/`, "backreference"},
		{"backreference after class", `/(a)[[:x]\1/`, "backreference"},
		{"lookahead", "/a(?=b)/", "lookahead"},
		{"negative lookahead", `/^CN=(?!admin)(\w+)$/`, "negative lookahead"},
		{"negative lookbehind", "/(?<!a)b/", "negative lookbehind"},
		{"atomic group", "/(?>a)/", "atomic group"},
		{"verb", "/(*UTF)a/", "verb"},
		{"possessive", "/a*+/", "invalid nested repetition"},
		{"possessive count", "/a{2}+/", "invalid nested repetition"},
		{"horizontal space", `/a\hb/`, "invalid escape"},
		{"keep out", `/a\Kb/`, "invalid escape"},
		{"branch reset", "/(?|a)/", "invalid or unsupported Perl syntax"},
		{"comment", "/a(?#c)/", "invalid or unsupported Perl syntax"},
		{"word start", "/[[:<:]]a/", "invalid character class range"},
		{"PCRE2 property", `/\p{Xan}/`, "invalid character class range"},
		{"repeat over Go limit", "/a{1001}/", "invalid repeat count"},
		{"non-UTF-8 byte", "/a\xffb/", "invalid UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := "FS before x\nFS " + tt.principal + " y\nFS after z\n"
			skip := func(*ParseError) error { return nil }
			for _, o := range []Options{{}, {OnError: skip}, {OnError: fatal}} {
				h := &captureHandler{}
				o.Logger = slog.New(h)
				mf, err := o.Parse(strings.NewReader(text), "test.map")
				if mf != nil {
					t.Errorf("Parse returned a map file")
				}
				var perr *ParseError
				if !errors.As(err, &perr) || perr.File != "test.map" || perr.Line != 2 {
					t.Fatalf("err = %v, want *ParseError at test.map:2", err)
				}
				if !errors.Is(err, ErrUnsupportedRegex) || !strings.Contains(err.Error(), tt.contains) {
					t.Errorf("err = %v, want ErrUnsupportedRegex containing %q", err, tt.contains)
				}
				if recs := h.get(); len(recs) != 0 {
					t.Errorf("logged %+v", recs)
				}
			}
		})
	}

	// With regex keys every principal is a regular expression.
	_, err := Options{RegexKeys: true}.Parse(strings.NewReader("FS a(?=b) x\n"), "test.map")
	if !errors.Is(err, ErrUnsupportedRegex) {
		t.Errorf("regex keys: err = %v, want ErrUnsupportedRegex", err)
	}

	// Skipping the first line would map CN=bob to admin_bob, where
	// HTCondor maps it to bob.
	_, err = Parse(strings.NewReader("SSL /^CN=(?!admin)(\\w+)$/ \\1\nSSL /^CN=(.*)$/ admin_\\1\n"), "test.map")
	if !errors.Is(err, ErrUnsupportedRegex) {
		t.Errorf("err = %v, want ErrUnsupportedRegex", err)
	}
}

// Character classes and \Q...\E do not trip the PCRE-only checks (Go may
// still refuse what they contain).
func TestRegexAccepted(t *testing.T) {
	for _, re := range []string{`[\1]`, `[]\1]`, `[^]\1]`, `[[:alpha:]\1]`, `[[:^digit:]]`, `[[:\1]`, `\Qa\1(?=\E`} {
		if err := checkPCREOnly(re); err != nil {
			t.Errorf("checkPCREOnly(%q): %v", re, err)
		}
	}
	for _, re := range []string{`[[:alpha:]]+`, `\Qa\1(?=\E`, `\0`, `(?i)a`, `(?P<n>a)`, `(?<n>a)`, `(?:a)`, `[]a]`} {
		if _, err := compileRegex(re, false, false); err != nil {
			t.Errorf("compileRegex(%q): %v", re, err)
		}
	}
}

func TestOnError(t *testing.T) {
	text := "FS a b\nFS bad\nFS /(/ x\nFS c d\n"

	// OnError replaces logging; returning nil skips the line.
	var seen []string
	h := &captureHandler{}
	mf, err := Options{Logger: slog.New(h), OnError: func(e *ParseError) error {
		seen = append(seen, e.Error())
		return nil
	}}.Parse(strings.NewReader(text), "m")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(seen) != 2 || !strings.HasPrefix(seen[0], "m:2: ") || !strings.HasPrefix(seen[1], "m:3: ") {
		t.Errorf("errors = %q", seen)
	}
	if recs := h.get(); len(recs) != 0 {
		t.Errorf("logged %+v with OnError set", recs)
	}
	checkLookups(t, mf, []lookup{{"FS", "a", "b"}, {"FS", "c", "d"}})

	// Returning the *ParseError makes the first bad line fatal.
	_, err = Options{OnError: fatal}.Parse(strings.NewReader(text), "m")
	var perr *ParseError
	if !errors.As(err, &perr) || perr.File != "m" || perr.Line != 2 {
		t.Errorf("err = %v, want *ParseError at m:2", err)
	}

	stop := errors.New("stop")
	_, err = Options{OnError: func(*ParseError) error { return stop }}.Parse(strings.NewReader(text), "m")
	if !errors.Is(err, stop) {
		t.Errorf("err = %v, want stop", err)
	}
}

// The zero Options logs bad lines to slog.Default() and keeps the rest.
// Not parallel: it replaces the default logger.
func TestZeroOptionsLogsToDefault(t *testing.T) {
	h := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	mf, err := Parse(strings.NewReader("FS a b\nFS bad\nFS /x**/ y\n@include\nFS c d\n"), "m")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	checkLookups(t, mf, []lookup{{"FS", "a", "b"}, {"FS", "c", "d"}, {"FS", "x", ""}})
	if mf.Len() != 2 {
		t.Errorf("Len = %d, want 2", mf.Len())
	}
	recs := h.get()
	checkLogged(t, recs, "m", "2", "3", "4")
	for _, r := range recs {
		if r.msg != "mapfile: skipping line" {
			t.Errorf("message = %q", r.msg)
		}
	}
}

func TestReadError(t *testing.T) {
	boom := errors.New("boom")
	_, err := Parse(iotest.ErrReader(boom), "m")
	if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "m: ") {
		t.Errorf("err = %v, want m: boom", err)
	}
	_, err = Parse(io.MultiReader(strings.NewReader("FS a b\nFS alice alicia_"), iotest.ErrReader(boom)), "m")
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want boom", err)
	}
}

// A read error in an included file skips the rest of it, including the
// partial line read before the error, and is reported at that line.
func TestIncludeReadErrorDropsPartialLine(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main")
	inc := filepath.Join(dir, "inc")
	writeFile(t, main, "@include inc\nFS m m\n")
	writeFile(t, inc, "")
	boom := errors.New("boom")
	prev := openInclude
	t.Cleanup(func() { openInclude = prev })
	openInclude = func(path string) (io.ReadCloser, error) {
		if path != inc {
			return prev(path)
		}
		// The read fails partway through "FS alice alicia_smith".
		r := io.MultiReader(strings.NewReader("FS a b\nFS alice alicia_"), iotest.ErrReader(boom))
		return io.NopCloser(r), nil
	}

	h := &captureHandler{}
	mf, err := Options{Logger: slog.New(h)}.Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checkLookups(t, mf, []lookup{{"FS", "a", "b"}, {"FS", "alice", ""}, {"FS", "m", "m"}})
	recs := h.get()
	checkLogged(t, recs, inc, "2")
	if !strings.Contains(recs[0].attrs["error"], "boom") {
		t.Errorf("logged %+v", recs)
	}
}

func TestParseErrorNoName(t *testing.T) {
	_, err := Options{OnError: fatal}.Parse(strings.NewReader("FS a\n"), "")
	if err == nil || err.Error() != "line 1: expected <method> <principal> <canonicalization>" {
		t.Errorf("err = %v", err)
	}
}

func TestEntriesAndMethods(t *testing.T) {
	mf := mustParse(t, Options{}, "OIDC a x\nFS /b/ y\noidc /c/ z\nOIDC a dup\n")
	if got, want := mf.Methods(), []string{"OIDC", "FS"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Methods = %q, want %q", got, want)
	}
	var canons []string
	for _, e := range mf.Entries("Oidc") {
		canons = append(canons, e.Canonicalization)
	}
	if want := []string{"x", "z", "dup"}; !reflect.DeepEqual(canons, want) {
		t.Errorf("canonicalizations = %q, want %q", canons, want)
	}
	if e := mf.Entries("OIDC")[1]; !e.Regex || e.Principal != "c" || e.Line != 3 || e.Method != "oidc" {
		t.Errorf("entry = %+v", e)
	}
	if mf.Entries("SSL") != nil {
		t.Error("Entries(SSL) not nil")
	}
	if mf.Len() != 4 {
		t.Errorf("Len = %d", mf.Len())
	}
	// Entries is a copy.
	mf.Entries("FS")[0].Canonicalization = "changed"
	checkLookups(t, mf, []lookup{{"FS", "b", "y"}})

	var nilMF *MapFile
	if _, ok := nilMF.Map("FS", "a"); ok || nilMF.Len() != 0 || nilMF.Entries("FS") != nil || nilMF.Methods() != nil {
		t.Error("nil MapFile not empty")
	}
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "map")
	writeFile(t, path, "FS a b\nFS c\nFS d e\n")
	h := &captureHandler{}
	mf, err := Options{Logger: slog.New(h)}.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checkLookups(t, mf, []lookup{{"FS", "a", "b"}, {"FS", "d", "e"}, {"FS", "c", ""}})
	checkLogged(t, h.get(), path, "2")

	_, err = Options{OnError: fatal}.Load(path)
	var perr *ParseError
	if !errors.As(err, &perr) || perr.File != path || perr.Line != 2 {
		t.Fatalf("err = %v", err)
	}
	if _, err := Load(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: err = %v", err)
	}
}

func TestIncludeFileAndDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main"), strings.Join([]string{
		"FS /^first$/ main-before",
		"@include extra",
		"@include " + filepath.Join(dir, "d.d"),
		"FS /.*/ main-after",
	}, "\n"))
	writeFile(t, filepath.Join(dir, "extra"), "FS e extra\nFS first extra-shadowed\n")
	d := filepath.Join(dir, "d.d")
	writeFile(t, filepath.Join(d, "20-b"), "FS b 20\nFS x 20\n")
	writeFile(t, filepath.Join(d, "10-a"), "FS a 10\nFS x 10\n")
	writeFile(t, filepath.Join(d, "30-skip.rpmsave"), "FS s skipped\n")
	writeFile(t, filepath.Join(d, ".hidden"), "FS s skipped\n")
	writeFile(t, filepath.Join(d, "skip~"), "FS s skipped\n")
	writeFile(t, filepath.Join(d, "skip.sh"), "FS s skipped\n")
	writeFile(t, filepath.Join(d, "#skip"), "FS s skipped\n")
	writeFile(t, filepath.Join(d, "sub", "inner"), "FS s skipped\n")

	mf, err := Load(filepath.Join(dir, "main"))
	if err != nil {
		t.Fatal(err)
	}
	checkLookups(t, mf, []lookup{
		{"FS", "first", "main-before"},
		{"FS", "e", "extra"},
		{"FS", "a", "10"},
		{"FS", "b", "20"},
		{"FS", "x", "10"},
		{"FS", "s", "main-after"},
	})
	var files []string
	for _, e := range mf.Entries("FS") {
		files = append(files, filepath.Base(e.File)+":"+e.Canonicalization)
	}
	want := []string{"main:main-before", "extra:extra", "extra:extra-shadowed", "10-a:10", "10-a:10", "20-b:20", "20-b:20", "main:main-after"}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("entries = %q\n     want %q", files, want)
	}
}

func TestIncludeExcludeOption(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main"), "@include d\n")
	writeFile(t, filepath.Join(dir, "d", "a.conf"), "FS a a\n")
	writeFile(t, filepath.Join(dir, "d", "b.skip"), "FS b b\n")
	writeFile(t, filepath.Join(dir, "d", ".c"), "FS c c\n")
	mf, err := Options{IncludeExclude: regexpMust(`\.skip$`)}.Load(filepath.Join(dir, "main"))
	if err != nil {
		t.Fatal(err)
	}
	checkLookups(t, mf, []lookup{{"FS", "a", "a"}, {"FS", "b", ""}, {"FS", "c", "c"}})
}

func TestIncludeErrors(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main")
	writeFile(t, filepath.Join(dir, "nested"), "FS n n\n@include other\n")
	writeFile(t, filepath.Join(dir, "self"), "@include self\nFS s s\n")

	tests := []struct {
		name, text string
		opts       Options
		file       string
		line       int
		contains   string
	}{
		{"missing file", "FS a b\n@include nope\n", Options{}, main, 2, "no such file"},
		{"empty path", "@include\n", Options{}, main, 1, "@include needs a file or directory"},
		// The path takes the newline, as in C++.
		{"unterminated path", `@include "inc` + "\n", Options{}, main, 1, "inc\n: no such file"},
		{"unterminated method at end of file", `"@include`, Options{}, main, 1, "@include needs a file or directory"},
		{"nested include", "@include nested\n", Options{}, filepath.Join(dir, "nested"), 2, "not allowed in an included file"},
		{"no include", "@include nested\n", Options{NoInclude: true}, main, 1, "@include is not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeFile(t, main, tt.text)

			h := &captureHandler{}
			opts := tt.opts
			opts.Logger = slog.New(h)
			if _, err := opts.Load(main); err != nil {
				t.Fatalf("Load: %v", err)
			}
			checkLogged(t, h.get(), tt.file, strconv.Itoa(tt.line))

			opts.OnError = fatal
			_, err := opts.Load(main)
			var perr *ParseError
			if !errors.As(err, &perr) {
				t.Fatalf("err = %v, want *ParseError", err)
			}
			if perr.File != tt.file || perr.Line != tt.line || !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("err = %v; want %s:%d containing %q", err, tt.file, tt.line, tt.contains)
			}
		})
	}

	// As in HTCondor, the nested @include is ignored and the rest of
	// both files is read; a self-include reads the file a second time
	// without recursing.
	writeFile(t, filepath.Join(dir, "inc"), "FS i i\n")
	writeFile(t, main, "@include nested\n@include self\n@include \"inc\nFS m m\n")
	h := &captureHandler{}
	mf, err := Options{Logger: slog.New(h)}.Load(main)
	if err != nil {
		t.Fatal(err)
	}
	recs := h.get()
	if len(recs) != 3 || recs[0].attrs["file"] != filepath.Join(dir, "nested") ||
		recs[1].attrs["file"] != filepath.Join(dir, "self") || recs[2].attrs["file"] != main {
		t.Errorf("logged %+v", recs)
	}
	checkLookups(t, mf, []lookup{{"FS", "i", ""}})
	checkLookups(t, mf, []lookup{{"FS", "n", "n"}, {"FS", "s", "s"}, {"FS", "m", "m"}})
}

func TestIncludeRelativeToParseName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "inc"), "FS a b\n")
	mf, err := Parse(strings.NewReader("@include inc\n"), filepath.Join(dir, "virtual"))
	if err != nil {
		t.Fatal(err)
	}
	checkLookups(t, mf, []lookup{{"FS", "a", "b"}})
}
