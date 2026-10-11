package apassign

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The mapfile backend: HTCondor mapfile syntax, first match in file
// order.
//
//	# match    principal                          schedd            [alternate ...]
//	USER       alice@example.org                  ap12.example.org  ap13.example.org
//	GROUP      cms                                ap20.example.org
//	USER       /^(.*)@physics\.example\.org$/     ap30.example.org
//	SUBJECT    /^https:\/\/idp\.example\.org\//i  ap31.example.org
//	*          /.*/                               ap01.example.org
//
// Fields are separated by spaces or tabs and parsed as HTCondor's
// MapFile::ParseField parses them (src/condor_utils/MapFile.cpp):
//
//   - A principal in double quotes may contain spaces; \" is a quote and
//     \\ a backslash inside it.
//   - A principal in slashes is a regular expression, optionally followed
//     by the flags i (case-insensitive) and U (ungreedy), as HTCondor's
//     hash-mode mapfiles allow; \/ is a slash inside it, and \\ one
//     backslash, exactly as HTCondor reads it. The expression is
//     searched for, not anchored: write ^ and $ to anchor it. Go's RE2
//     syntax applies, which is PCRE's minus backreferences and
//     lookaround.
//   - Anything else is a literal, compared exactly.
//   - A line whose first field starts with # is a comment; so is anything
//     from a field starting with # to the end of a line.
//
// The match field is USER (the HTCondor identity, alice@example.org),
// GROUP (any of the caller's groups), SUBJECT (the authenticated
// principal before mapping), or * (any of the three).
//
// HTCondor mapfiles also accept @include; this one does not, and refuses
// a file that uses it rather than ignoring part of the assignment.

// Mapfile match methods.
const (
	MethodUser    = "USER"
	MethodGroup   = "GROUP"
	MethodSubject = "SUBJECT"
	MethodAny     = "*"
)

// DefaultMapfileTTL is how long a mapfile answer is reused.
const DefaultMapfileTTL = 60 * time.Second

// mapfileCheckInterval bounds how often the file is stat'ed for changes.
const mapfileCheckInterval = 2 * time.Second

// maxMapfileSize refuses a file far larger than any assignment table.
const maxMapfileSize = 16 << 20

// Rule is one line of a mapfile.
type Rule struct {
	Method string
	// Principal is the literal, or the expression's source.
	Principal string
	// Regexp is set for a /regex/ principal.
	Regexp     *regexp.Regexp
	Schedd     string
	Alternates []string
	// Line is the line number, for messages.
	Line int
}

// matches reports whether the rule's principal matches s.
func (r Rule) matches(s string) bool {
	if s == "" {
		return false
	}
	if r.Regexp != nil {
		return r.Regexp.MatchString(s)
	}
	return r.Principal == s
}

// Match reports whether the rule matches req.
func (r Rule) Match(req Request) bool {
	switch r.Method {
	case MethodUser:
		return r.matches(req.User)
	case MethodSubject:
		return r.matches(req.Subject)
	case MethodGroup:
		for _, g := range req.Groups {
			if r.matches(g) {
				return true
			}
		}
		return false
	case MethodAny:
		if r.matches(req.User) || r.matches(req.Subject) {
			return true
		}
		for _, g := range req.Groups {
			if r.matches(g) {
				return true
			}
		}
	}
	return false
}

// ParseError is a mapfile line that cannot be used.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

// ParseMapfile reads a mapfile. Any line it cannot use is an error: an
// assignment table that silently skipped a line would send that line's
// users somewhere the operator did not say.
func ParseMapfile(r io.Reader) ([]Rule, error) {
	var rules []Rule
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimRight(sc.Text(), "\r\n")
		fields, err := splitMapLine(text)
		if err != nil {
			return nil, &ParseError{Line: line, Msg: err.Error()}
		}
		if len(fields) == 0 {
			continue
		}
		method := fields[0].text
		if method == "@include" {
			return nil, &ParseError{Line: line, Msg: "@include is not supported in an access point assignment mapfile"}
		}
		switch strings.ToUpper(method) {
		case MethodUser, MethodGroup, MethodSubject:
			method = strings.ToUpper(method)
		case MethodAny:
		default:
			return nil, &ParseError{Line: line, Msg: fmt.Sprintf("unknown match %q; use USER, GROUP, SUBJECT or *", method)}
		}
		if fields[0].regex || fields[0].quoted {
			return nil, &ParseError{Line: line, Msg: "the match field cannot be quoted or a regular expression"}
		}
		if len(fields) < 3 {
			return nil, &ParseError{Line: line, Msg: "a line needs a match, a principal and a schedd"}
		}
		rule := Rule{Method: method, Principal: fields[1].text, Line: line}
		if fields[1].regex {
			re, err := compileMapRegex(fields[1].text, fields[1].flags)
			if err != nil {
				return nil, &ParseError{Line: line, Msg: fmt.Sprintf("principal /%s/: %v", fields[1].text, err)}
			}
			rule.Regexp = re
		} else if rule.Principal == "" {
			return nil, &ParseError{Line: line, Msg: "empty principal"}
		}
		for i, f := range fields[2:] {
			if f.regex {
				return nil, &ParseError{Line: line, Msg: fmt.Sprintf("schedd %q cannot be a regular expression", f.text)}
			}
			if strings.TrimSpace(f.text) == "" {
				return nil, &ParseError{Line: line, Msg: "empty schedd name"}
			}
			if i == 0 {
				rule.Schedd = f.text
			} else {
				rule.Alternates = append(rule.Alternates, f.text)
			}
		}
		rules = append(rules, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, &ParseError{Line: line + 1, Msg: err.Error()}
	}
	return rules, nil
}

// compileMapRegex compiles a /regex/ principal with HTCondor's flags.
func compileMapRegex(src, flags string) (*regexp.Regexp, error) {
	if src == "" {
		return nil, errors.New("empty regular expression")
	}
	prefix := ""
	if strings.Contains(flags, "i") {
		prefix += "i"
	}
	if strings.Contains(flags, "U") {
		prefix += "U"
	}
	if prefix != "" {
		src = "(?" + prefix + ")" + src
	}
	return regexp.Compile(src)
}

type mapField struct {
	text   string
	quoted bool
	regex  bool
	flags  string
}

// splitMapLine splits a line into fields the way MapFile::ParseField
// does, stopping at a field that starts with #.
func splitMapLine(line string) ([]mapField, error) {
	var out []mapField
	i := 0
	for {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			return out, nil
		}
		if line[i] == '#' {
			return out, nil
		}
		var f mapField
		ch := line[i]
		if ch == '"' || ch == '/' {
			f.quoted, f.regex = ch == '"', ch == '/'
			i++
			var b strings.Builder
			closed := false
			for i < len(line) {
				c := line[i]
				if c == ch {
					i++
					closed = true
					break
				}
				if c == '\\' && i+1 < len(line) {
					// As ParseField: an escaped delimiter is the
					// delimiter, an escaped backslash is one backslash
					// (in an expression too, so /a\\.b/ is a\.b), and
					// any other escape is kept as written.
					next := line[i+1]
					switch next {
					case ch:
						b.WriteByte(next)
					case '\\':
						b.WriteByte('\\')
					default:
						b.WriteByte('\\')
						b.WriteByte(next)
					}
					i += 2
					continue
				}
				b.WriteByte(c)
				i++
			}
			if !closed {
				what := "quote"
				if f.regex {
					what = "slash"
				}
				return nil, fmt.Errorf("unterminated %s in %q", what, line)
			}
			f.text = b.String()
			if f.regex {
				for i < len(line) && (line[i] == 'i' || line[i] == 'U') {
					f.flags += string(line[i])
					i++
				}
			}
			if i < len(line) && line[i] != ' ' && line[i] != '\t' {
				return nil, fmt.Errorf("unexpected %q after a closing %c", line[i], ch)
			}
		} else {
			start := i
			for i < len(line) && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			f.text = line[start:i]
		}
		out = append(out, f)
	}
}

// Mapfile is the mapfile backend. It re-reads the file when it changes
// (checked at most every couple of seconds) and on Reload; a file that
// stops parsing keeps the last good map, and says so in the log.
type Mapfile struct {
	path   string
	ttl    time.Duration
	logger Logger
	// checkEvery overrides mapfileCheckInterval; tests shorten it.
	checkEvery time.Duration
	now        func() time.Time

	mu        sync.Mutex
	rules     []Rule
	gen       uint64
	modTime   time.Time
	size      int64
	checkedAt time.Time
	lastErr   string
}

// NewMapfile reads path. A file that cannot be read or parsed is an
// error: the server refuses to start rather than run with no map.
func NewMapfile(path string, logger Logger) (*Mapfile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("the mapfile access point assignment backend needs HTTP_API_AP_ASSIGNMENT_MAPFILE")
	}
	m := &Mapfile{path: path, ttl: DefaultMapfileTTL, logger: logger, now: time.Now}
	info, rules, err := m.read()
	if err != nil {
		return nil, fmt.Errorf("HTTP_API_AP_ASSIGNMENT_MAPFILE %s: %w", path, err)
	}
	m.install(info, rules)
	return m, nil
}

// Path is the mapfile's path.
func (m *Mapfile) Path() string { return m.path }

// Rules returns the map in force.
func (m *Mapfile) Rules() []Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Rule(nil), m.rules...)
}

func (m *Mapfile) read() (os.FileInfo, []Rule, error) {
	f, err := os.Open(m.path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Size() > maxMapfileSize {
		return nil, nil, fmt.Errorf("the file is %d bytes, over the %d byte limit", info.Size(), maxMapfileSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxMapfileSize+1))
	if err != nil {
		return nil, nil, err
	}
	rules, err := ParseMapfile(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	return info, rules, nil
}

// install replaces the map. m.mu is held, or m is not yet shared.
func (m *Mapfile) install(info os.FileInfo, rules []Rule) {
	m.rules = rules
	m.modTime, m.size = info.ModTime(), info.Size()
	m.gen++
	m.lastErr = ""
}

// refresh re-reads the file when it has changed on disk, or always when
// force is set. m.mu is held.
func (m *Mapfile) refresh(force bool) error {
	m.checkedAt = m.now()
	if !force {
		info, err := os.Stat(m.path)
		if err == nil && info.ModTime().Equal(m.modTime) && info.Size() == m.size {
			return nil
		}
	}
	info, rules, err := m.read()
	if err != nil {
		if msg := err.Error(); msg != m.lastErr {
			m.lastErr = msg
			if m.logger != nil {
				m.logger.Error("Could not reload HTTP_API_AP_ASSIGNMENT_MAPFILE; keeping the last map that parsed",
					"path", m.path, "error", err, "rules_in_force", len(m.rules))
			}
		}
		return err
	}
	m.install(info, rules)
	if m.logger != nil {
		m.logger.Info("Reloaded HTTP_API_AP_ASSIGNMENT_MAPFILE", "path", m.path, "rules", len(rules))
	}
	return nil
}

// maybeRefresh is refresh, at most once per check interval.
func (m *Mapfile) maybeRefresh() {
	every := m.checkEvery
	if every <= 0 {
		every = mapfileCheckInterval
	}
	if m.now().Sub(m.checkedAt) >= every {
		_ = m.refresh(false)
	}
}

// Reload re-reads the file now, changed or not. On a parse error the
// last good map stays in force and the error is returned.
func (m *Mapfile) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refresh(true)
}

// Generation changes whenever a new map is installed. It checks the file
// for changes first, so a cached answer from an edited map is not reused.
func (m *Mapfile) Generation() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maybeRefresh()
	return m.gen
}

// Assign implements Assigner: the first rule in file order that matches.
func (m *Mapfile) Assign(_ context.Context, req Request) (Assignment, error) {
	m.mu.Lock()
	m.maybeRefresh()
	rules := m.rules
	m.mu.Unlock()
	for _, r := range rules {
		if r.Match(req) {
			return Assignment{Schedd: r.Schedd, Alternates: append([]string(nil), r.Alternates...), TTL: m.ttl}, nil
		}
	}
	return Assignment{}, ErrNoAnswer
}
