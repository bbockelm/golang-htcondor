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
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// DefaultIncludeExclude is the default of LOCAL_CONFIG_DIR_EXCLUDE_REGEXP:
// the file names an @include of a directory skips.
const DefaultIncludeExclude = `^((\..*)|(.*\.pl)|(.*\.py)|(.*\.sh)|(.*~)|(#.*)|(.*\.rpmsave)|(.*\.rpmnew)|(.*\.dpkg-old)|(.*\.dpkg-dist)|(.*\.cfsaved))$`

var defaultIncludeExclude = regexp.MustCompile(DefaultIncludeExclude)

// includeDirective is the first field of an @include line.
const includeDirective = "@include"

// Options controls how a map file is read. The zero value reads a file
// the way HTCondor reads CLASSAD_USER_MAPFILE, and CERTIFICATE_MAPFILE
// with CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true, except that a bad line
// is an error.
type Options struct {
	// RegexKeys makes every principal a regular expression, as HTCondor
	// reads CERTIFICATE_MAPFILE when CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS
	// is false (its default). Slashes are then ordinary characters.
	RegexKeys bool
	// NoInclude refuses @include lines.
	NoInclude bool
	// IncludeExclude matches the names of files an @include of a
	// directory skips (LOCAL_CONFIG_DIR_EXCLUDE_REGEXP). Nil means
	// DefaultIncludeExclude.
	IncludeExclude *regexp.Regexp
	// OnError is called with each line that cannot be used. If it
	// returns nil the line is skipped, as HTCondor does; otherwise
	// loading stops with the error it returns. Nil stops at the first
	// bad line with that line's *ParseError.
	OnError func(*ParseError) error
}

// ParseError is a line of a map file that cannot be used.
type ParseError struct {
	File string
	Line int
	Err  error
}

func (e *ParseError) Error() string {
	if e.File == "" {
		return fmt.Sprintf("line %d: %v", e.Line, e.Err)
	}
	return fmt.Sprintf("%s:%d: %v", e.File, e.Line, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// Load reads the map file at path with the zero Options.
func Load(path string) (*MapFile, error) { return Options{}.Load(path) }

// Parse reads a map file from r with the zero Options. name is used in
// errors and as the base of relative @include paths.
func Parse(r io.Reader, name string) (*MapFile, error) { return Options{}.Parse(r, name) }

// Load reads the map file at path.
func (o Options) Load(path string) (*MapFile, error) {
	f, err := os.Open(path) //nolint:gosec // the map file is chosen by the administrator
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	return o.Parse(f, path)
}

// Parse reads a map file from r. name is used in errors and as the base
// of relative @include paths.
func (o Options) Parse(r io.Reader, name string) (*MapFile, error) {
	p := &parser{opts: o, mf: &MapFile{}}
	if p.opts.IncludeExclude == nil {
		p.opts.IncludeExclude = defaultIncludeExclude
	}
	if err := p.parse(r, name, !o.NoInclude); err != nil {
		return nil, err
	}
	return p.mf, nil
}

type parser struct {
	opts Options
	mf   *MapFile
}

// fail reports a bad line and returns non-nil if loading must stop.
func (p *parser) fail(file string, line int, err error) error {
	perr := &ParseError{File: file, Line: line, Err: err}
	if p.opts.OnError == nil {
		return perr
	}
	return p.opts.OnError(perr)
}

// parse reads one file. It returns non-nil only if loading must stop.
func (p *parser) parse(r io.Reader, name string, allowInclude bool) error {
	br := bufio.NewReader(r)
	line := 0
	for {
		text, rerr := br.ReadString('\n')
		if text == "" && rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return fmt.Errorf("%s: %w", name, rerr)
		}
		line++
		// C++ keeps the line ending: "\n" is white space to ParseField
		// but a "\r" ends up in the last field. Drop both.
		text = strings.TrimSuffix(text, "\n")
		text = strings.TrimSuffix(text, "\r")
		if err := p.parseLine(text, name, line, allowInclude); err != nil {
			return err
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return fmt.Errorf("%s: %w", name, rerr)
		}
	}
}

// parseLine is the body of MapFile::ParseCanonicalization's loop.
func (p *parser) parseLine(text, name string, line int, allowInclude bool) error {
	method, off := parseField(text, 0, false)
	if method.text == includeDirective && !method.unterminated {
		return p.include(text, off, name, line, allowInclude)
	}
	if method.text == "" || method.text[0] == '#' {
		return nil
	}
	principal, off := parseField(text, off, !p.opts.RegexKeys)
	canon, _ := parseField(text, off, false)
	for _, f := range []field{method, principal, canon} {
		if f.unterminated {
			return p.fail(name, line, fmt.Errorf("unterminated %s", f.kind()))
		}
	}
	if principal.text == "" || canon.text == "" {
		return p.fail(name, line, errors.New("expected <method> <principal> <canonicalization>"))
	}

	r := rule{entry: Entry{
		Method:           method.text,
		Principal:        principal.text,
		Regex:            p.opts.RegexKeys || principal.regex,
		IgnoreCase:       principal.ignoreCase,
		Ungreedy:         principal.ungreedy,
		Canonicalization: canon.text,
		File:             name,
		Line:             line,
	}}
	if r.entry.Regex {
		re, err := compileRegex(principal.text, principal.ignoreCase, principal.ungreedy)
		if err != nil {
			return p.fail(name, line, fmt.Errorf("principal %q: %w", principal.text, err))
		}
		r.re = re
	}
	p.mf.add(r)
	return nil
}

// include handles an @include line.
func (p *parser) include(text string, off int, name string, line int, allowed bool) error {
	if !allowed {
		if p.opts.NoInclude {
			return p.fail(name, line, errors.New("@include is not allowed"))
		}
		return p.fail(name, line, errors.New("@include is not allowed in an included file"))
	}
	target, _ := parseField(text, off, false)
	if target.unterminated {
		return p.fail(name, line, fmt.Errorf("unterminated %s", target.kind()))
	}
	path := target.text
	if path == "" {
		return p.fail(name, line, errors.New("@include needs a file or directory"))
	}
	if !isAbs(path) {
		// Relative to the including file's directory, joined as
		// condor_basename/dircat do: without cleaning the path.
		if i := lastSeparator(name); i >= 0 {
			path = name[:i+1] + path
		}
	}

	st, err := os.Stat(path)
	if err != nil || !st.IsDir() {
		return p.includeFile(path, name, line)
	}
	ents, err := os.ReadDir(path)
	if err != nil {
		return p.fail(name, line, fmt.Errorf("@include %s: %w", path, err))
	}
	// ReadDir sorts by name, as get_config_dir_file_list sorts.
	for _, ent := range ents {
		if p.opts.IncludeExclude.MatchString(ent.Name()) {
			continue
		}
		full := path + string(os.PathSeparator) + ent.Name()
		if fst, err := os.Stat(full); err == nil && fst.IsDir() {
			continue
		}
		if err := p.includeFile(full, name, line); err != nil {
			return err
		}
	}
	return nil
}

// includeFile reads an included file, which may not itself include.
func (p *parser) includeFile(path, name string, line int) error {
	f, err := os.Open(path) //nolint:gosec // named by the administrator's map file
	if err != nil {
		return p.fail(name, line, fmt.Errorf("@include: %w", err))
	}
	defer f.Close() //nolint:errcheck // read-only
	return p.parse(f, path, false)
}

func isAbs(path string) bool {
	if strings.HasPrefix(path, "/") {
		return true
	}
	return os.PathSeparator != '/' && len(path) > 0 && (path[0] == os.PathSeparator ||
		(len(path) > 2 && path[1] == ':' && os.IsPathSeparator(path[2])))
}

func lastSeparator(name string) int {
	for i := len(name) - 1; i >= 0; i-- {
		if os.IsPathSeparator(name[i]) {
			return i
		}
	}
	return -1
}

// field is one field of a line, as MapFile::ParseField reads it.
type field struct {
	text string
	// regex reports that the field was delimited by slashes.
	regex                bool
	ignoreCase, ungreedy bool
	unterminated         bool
}

func (f field) kind() string {
	if f.regex {
		return "regular expression"
	}
	return "quoted string"
}

func isFieldSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' }

// parseField reads the field starting at or after off and returns it with
// the offset just past it. regexDelim lets a field start with / (the
// popts argument of ParseField).
func parseField(line string, off int, regexDelim bool) (field, int) {
	for off < len(line) && isFieldSpace(line[off]) {
		off++
	}
	var f field
	var end byte
	if off < len(line) {
		switch line[off] {
		case '"':
			end = '"'
		case '/':
			if regexDelim {
				end, f.regex = '/', true
			}
		}
	}
	if end == 0 {
		start := off
		for off < len(line) && !isFieldSpace(line[off]) {
			off++
		}
		f.text = line[start:off]
		return f, off
	}

	off++
	var b strings.Builder
	for off < len(line) {
		c := line[off]
		switch {
		case c == end:
			off++
			if f.regex {
				off = f.regexFlags(line, off)
			}
			f.text = b.String()
			return f, off
		case c == '\\' && off+1 < len(line):
			off++
			switch n := line[off]; n {
			case end, '\\':
				b.WriteByte(n)
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
		case c == '\\':
			// A backslash ending the line: the field cannot be closed.
		default:
			b.WriteByte(c)
		}
		off++
	}
	f.text = b.String()
	f.unterminated = true
	return f, off
}

// regexFlags consumes the i and U flags after a closing slash.
func (f *field) regexFlags(line string, off int) int {
	for ; off < len(line); off++ {
		switch line[off] {
		case 'i':
			f.ignoreCase = true
		case 'U':
			f.ungreedy = true
		default:
			return off
		}
	}
	return off
}
