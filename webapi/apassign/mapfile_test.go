package apassign

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseMapfile(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		// want is "METHOD principal schedd alt..." per rule, the
		// principal as /src/ for an expression.
		want []string
		err  string
	}{
		{name: "the design's example", text: `
# match    principal                          schedd
USER       alice@example.org                  ap12.example.org
GROUP      cms                                ap20.example.org
USER       /^(.*)@physics\.example\.org$/      ap30.example.org
SUBJECT    /^https:\/\/idp\.example\.org\//     ap31.example.org
`, want: []string{
			"USER alice@example.org ap12.example.org",
			"GROUP cms ap20.example.org",
			`USER /^(.*)@physics\.example\.org$/ ap30.example.org`,
			`SUBJECT /^https://idp\.example\.org//` + " ap31.example.org",
		}},
		{name: "alternates, tabs, any-match and a trailing comment",
			text: "user\talice@example.org\tap12 ap13\tap14 # alice may also use 13 and 14\n*  /.*/  ap01\n",
			want: []string{"USER alice@example.org ap12 ap13 ap14", "* /.*/ ap01"}},
		{name: "quoted principal with spaces and escapes",
			text: `GROUP "High Energy \"Physics\"" ap7` + "\n" + `SUBJECT "C:\\users\\x" ap8`,
			want: []string{`GROUP High Energy "Physics" ap7`, `SUBJECT C:\users\x ap8`}},
		{name: "regex flags", text: "USER /^ALICE@/iU ap1\n", want: []string{"USER /(?iU)^ALICE@/ ap1"}},
		{name: "an escaped backslash in an expression is one backslash, as in HTCondor",
			text: `USER /a\\.b/ ap1`, want: []string{`USER /a\.b/ ap1`}},
		{name: "blank lines, comments and CRLF", text: "\r\n# only comments\r\n   # indented\r\nUSER a ap1\r\n",
			want: []string{"USER a ap1"}},
		{name: "unknown method", text: "HOST alice ap1", err: "unknown match"},
		{name: "missing schedd", text: "USER alice", err: "needs a match, a principal and a schedd"},
		{name: "unterminated quote", text: `USER "alice ap1`, err: "unterminated quote"},
		{name: "unterminated expression", text: `USER /alice ap1`, err: "unterminated slash"},
		{name: "bad expression", text: `USER /(alice/ ap1`, err: "principal"},
		{name: "backreference is not RE2", text: `USER /(a)\1/ ap1`, err: "principal"},
		{name: "empty expression", text: `USER // ap1`, err: "empty regular expression"},
		{name: "schedd as an expression", text: `USER alice /ap1/`, err: "cannot be a regular expression"},
		{name: "include", text: "@include other.map\n", err: "@include"},
		{name: "junk after a closing quote", text: `USER "alice"x ap1`, err: "after a closing"},
		{name: "error names the line", text: "USER a ap1\n\nGROUP\n", err: "line 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := ParseMapfile(strings.NewReader(tc.text))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error %v, want one containing %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range rules {
				p := r.Principal
				if r.Regexp != nil {
					p = "/" + r.Regexp.String() + "/"
				}
				got = append(got, strings.Join(append([]string{r.Method, p, r.Schedd}, r.Alternates...), " "))
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

func writeMap(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMapfileMatching(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assign.map")
	writeMap(t, path, `
USER     alice@example.org                ap1 ap2
USER     /@physics\.example\.org$/        ap3
GROUP    cms                              ap4
SUBJECT  /^https:\/\/IDP\.example\.org\//i ap5
GROUP    /^atlas-/                        ap6
*        carol                            ap7
# first match wins: alice is never sent here
USER     alice@example.org                ap9
`)
	m, err := NewMapfile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		req  Request
		want string
		alts []string
	}{
		{req: Request{User: "alice@example.org", Groups: []string{"cms"}}, want: "ap1", alts: []string{"ap2"}},
		{req: Request{User: "bob@physics.example.org", Groups: []string{"cms"}}, want: "ap3"},
		{req: Request{User: "dave@example.org", Groups: []string{"users", "cms"}}, want: "ap4"},
		{req: Request{User: "erin@example.org", Subject: "https://idp.example.org/erin"}, want: "ap5"},
		{req: Request{User: "frank@example.org", Groups: []string{"atlas-prod"}}, want: "ap6"},
		{req: Request{User: "carol@example.org", Subject: "carol"}, want: "ap7"},
		{req: Request{User: "x@example.org", Groups: []string{"carol"}}, want: "ap7"},
		// A literal is exact: not a prefix, not case-folded.
		{req: Request{User: "Alice@example.org"}},
		{req: Request{User: "alice@example.org.evil"}},
		{req: Request{User: "gina@example.org", Subject: "https://other.example.org/"}},
	} {
		a, err := m.Assign(context.Background(), tc.req)
		if tc.want == "" {
			if !errors.Is(err, ErrNoAnswer) {
				t.Errorf("%+v: got %+v %v, want no answer", tc.req, a, err)
			}
			continue
		}
		if err != nil || a.Schedd != tc.want || strings.Join(a.Alternates, ",") != strings.Join(tc.alts, ",") {
			t.Errorf("%+v: got %+v %v, want %s %v", tc.req, a, err, tc.want, tc.alts)
		}
		if a.TTL != DefaultMapfileTTL {
			t.Errorf("TTL %v, want %v", a.TTL, DefaultMapfileTTL)
		}
	}
}

// First match in file order, not last: the same principal on two lines
// goes to the first line's schedd.
func TestMapfileFirstMatchWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assign.map")
	writeMap(t, path, "USER /.*/ first\nUSER alice@example.org second\nGROUP g third\n")
	m, err := NewMapfile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Assign(context.Background(), Request{User: "alice@example.org", Groups: []string{"g"}})
	if err != nil || a.Schedd != "first" {
		t.Fatalf("got %+v %v, want first", a, err)
	}
}

func TestNewMapfileRefusesBadFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewMapfile(filepath.Join(dir, "missing.map"), nil); err == nil {
		t.Error("a missing mapfile was accepted")
	}
	bad := filepath.Join(dir, "bad.map")
	writeMap(t, bad, "USER alice ap1\nWHO bob ap2\n")
	if _, err := NewMapfile(bad, nil); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("a mapfile with a bad line: %v", err)
	}
	if _, err := NewMapfile("", nil); err == nil {
		t.Error("no path was accepted")
	}
}

// logRecorder is a Logger that keeps what it is told.
type logRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logRecorder) add(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, level+": "+msg)
}
func (l *logRecorder) Error(msg string, _ ...any) { l.add("error", msg) }
func (l *logRecorder) Warn(msg string, _ ...any)  { l.add("warn", msg) }
func (l *logRecorder) Info(msg string, _ ...any)  { l.add("info", msg) }

func (l *logRecorder) count(level string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, m := range l.msgs {
		if strings.HasPrefix(m, level+":") {
			n++
		}
	}
	return n
}

func TestMapfileReloadsOnChangeAndKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assign.map")
	writeMap(t, path, "USER alice@example.org ap1\n")
	logs := &logRecorder{}
	m, err := NewMapfile(path, logs)
	if err != nil {
		t.Fatal(err)
	}
	clk := newClock()
	m.now = clk.now
	m.checkEvery = time.Second
	m.checkedAt = clk.now()
	ctx := context.Background()
	gen0 := m.Generation()

	// An edit is picked up once the check interval has passed.
	writeMap(t, path, "USER alice@example.org ap2 ap3\n")
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if a, _ := m.Assign(ctx, Request{User: "alice@example.org"}); a.Schedd != "ap1" {
		t.Fatalf("re-read before the check interval: %s", a.Schedd)
	}
	clk.advance(2 * time.Second)
	if a, _ := m.Assign(ctx, Request{User: "alice@example.org"}); a.Schedd != "ap2" {
		t.Fatalf("after an edit: got %s, want ap2", a.Schedd)
	}
	gen1 := m.Generation()
	if gen1 == gen0 {
		t.Error("the generation did not change with the map")
	}

	// A broken edit keeps the last good map, and is logged once.
	writeMap(t, path, "USER alice@example.org ap4\nNOPE x y\n")
	later := future.Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		clk.advance(2 * time.Second)
		if a, _ := m.Assign(ctx, Request{User: "alice@example.org"}); a.Schedd != "ap2" {
			t.Fatalf("after a broken edit: got %s, want the last good ap2", a.Schedd)
		}
	}
	if m.Generation() != gen1 {
		t.Error("a broken edit changed the generation")
	}
	if n := logs.count("error"); n != 1 {
		t.Errorf("%d error logs for one broken edit, want 1", n)
	}
	if err := m.Reload(); err == nil {
		t.Error("Reload of a broken file returned no error")
	}

	// Fixed, and reloaded explicitly (reconfigure).
	writeMap(t, path, "USER alice@example.org ap5\n")
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if a, _ := m.Assign(ctx, Request{User: "alice@example.org"}); a.Schedd != "ap5" {
		t.Fatalf("after Reload: got %s, want ap5", a.Schedd)
	}

	// A file deleted out from under the server keeps the last map too.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	clk.advance(2 * time.Second)
	if a, _ := m.Assign(ctx, Request{User: "alice@example.org"}); a.Schedd != "ap5" {
		t.Fatalf("after the file vanished: got %s, want ap5", a.Schedd)
	}
}

// Through a chain: an edit reaches the next request although the cached
// answer's TTL has not run out.
func TestMapfileEditBypassesChainCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assign.map")
	writeMap(t, path, "USER alice@example.org ap1\n")
	ch, err := Build(Config{Backends: []string{BackendMapfile}, Mapfile: path}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	m := ch.backends[0].Assigner.(*Mapfile)
	m.checkEvery = time.Nanosecond
	if a, _ := ch.Resolve(context.Background(), alice); a.Schedd != "ap1" {
		t.Fatalf("got %s", a.Schedd)
	}
	writeMap(t, path, "USER alice@example.org ap2\n")
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if a, _ := ch.Resolve(context.Background(), alice); a.Schedd != "ap2" {
		t.Fatalf("after an edit: got %s, want ap2", a.Schedd)
	}
}

func FuzzParseMapfile(f *testing.F) {
	for _, seed := range []string{
		"USER alice@example.org ap1 ap2\n",
		`GROUP "a \"b\" c" ap1`,
		`SUBJECT /^https:\/\/x\//iU ap1 # c`,
		"* /.*/ ap\r\n#x\n",
		`USER /a\\.b/ ap1`,
		"@include x\n",
		`USER "unterminated`,
		"\x00\xff /\\",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		rules, err := ParseMapfile(strings.NewReader(text))
		if err != nil {
			return
		}
		for _, r := range rules {
			if r.Schedd == "" {
				t.Fatalf("rule with no schedd from %q", text)
			}
			if r.Regexp == nil && r.Principal == "" {
				t.Fatalf("rule with no principal from %q", text)
			}
			_ = r.Match(Request{User: text, Subject: text, Groups: []string{text}})
		}
	})
}
