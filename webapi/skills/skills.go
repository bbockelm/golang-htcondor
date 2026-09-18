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

// Package skills loads a directory of site-authored Markdown skills and
// serves them as a read-only library.
//
// A site keeps its operational knowledge -- how to submit to the local GPU
// partition, which transfer plugin to use, what the queue policy is -- in a
// git repository of Markdown files. Pointing this server at a checkout of
// that repository lets an agent read the site's own guidance instead of
// guessing from generic HTCondor knowledge.
//
// The library is read-only and loaded whole into memory: these are prose
// documents in the tens of kilobytes, not a corpus, and holding them means
// a request never touches the filesystem and cannot be made to walk it.
package skills

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// maxSkillBytes bounds one file. Skills are prose; anything larger is
	// a data file that wandered into the checkout, and reading it would
	// cost far more than it could teach.
	maxSkillBytes = 1 << 20 // 1 MiB

	// maxSkills bounds the library. A site with more than this has pointed
	// the server at the wrong directory -- a home directory, say -- and the
	// honest response is to stop rather than to read it all.
	maxSkills = 2000
)

// Skill is one Markdown document from the library.
type Skill struct {
	// ID addresses the skill. It is the path relative to the library root
	// with the .md extension removed, so it is stable across reloads and
	// means something to a human reading a log line.
	ID string `json:"id"`
	// Name and Description come from the YAML front matter when present.
	Name        string `json:"name"`
	Description string `json:"description"`
	// Path is the location relative to the root, kept so an operator can
	// find the file an agent quoted.
	Path string `json:"path"`
	// Body is the Markdown with the front matter removed.
	Body string `json:"-"`
}

// frontMatter is the subset of the YAML header this package acts on.
//
// Both description and summary are accepted: the first is the convention
// Claude skills use, the second reads more naturally to someone writing
// site documentation, and a file that sets neither still loads.
type frontMatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Summary     string `yaml:"summary"`
	Title       string `yaml:"title"`
}

// Library is an immutable set of loaded skills.
type Library struct {
	root   string
	skills []Skill
	byID   map[string]Skill
}

// Root returns the directory the library was loaded from.
func (l *Library) Root() string {
	if l == nil {
		return ""
	}
	return l.root
}

// Len reports how many skills were loaded.
func (l *Library) Len() int {
	if l == nil {
		return 0
	}
	return len(l.skills)
}

// List returns every skill, ordered by ID.
//
// The bodies are included; callers that only want the catalogue should use
// the Name/Description fields and ignore Body.
func (l *Library) List() []Skill {
	if l == nil {
		return nil
	}
	out := make([]Skill, len(l.skills))
	copy(out, l.skills)
	return out
}

// Get returns one skill by ID.
//
// A name is also accepted, since that is what an agent is most likely to
// have read off the index, and requiring it to know which of the two a
// tool wanted would be a needless failure.
func (l *Library) Get(idOrName string) (Skill, bool) {
	if l == nil {
		return Skill{}, false
	}
	if s, ok := l.byID[idOrName]; ok {
		return s, true
	}
	for _, s := range l.skills {
		if strings.EqualFold(s.Name, idOrName) {
			return s, true
		}
	}
	// Tolerate a leading "./" or a trailing ".md", both of which a caller
	// copying from a path naturally produces.
	trimmed := strings.TrimSuffix(strings.TrimPrefix(idOrName, "./"), ".md")
	if s, ok := l.byID[trimmed]; ok {
		return s, true
	}
	return Skill{}, false
}

// Load reads every Markdown file under root.
//
// Hidden directories and hidden files are skipped, which is what keeps a
// git checkout usable as a library: .git alone holds thousands of files,
// none of them documentation.
//
// Symbolic links are not followed. A link is the one way a file outside
// the configured directory could be served from inside it, and an operator
// pointing at a checkout has not agreed to serve whatever that checkout
// links to.
func Load(root string) (*Library, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("no skills directory configured")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", root, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("opening skills directory %s: %w", abs, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("skills path %s is not a directory", abs)
	}

	lib := &Library{root: abs, byID: map[string]Skill{}}

	walkErr := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory that cannot be read is skipped rather than
			// failing the whole load: one unreadable subdirectory should
			// not cost the site every other skill.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if path != abs && strings.HasPrefix(name, ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		// Not a regular file: a symlink, socket or device. Skipped, see
		// the note about links above.
		if !d.Type().IsRegular() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(name), ".md") {
			return nil
		}
		if len(lib.skills) >= maxSkills {
			return fmt.Errorf("more than %d skills under %s; refusing to load the rest", maxSkills, abs)
		}

		rel, relErr := filepath.Rel(abs, path)
		if relErr != nil {
			return nil
		}
		skill, loadErr := loadSkill(abs, rel)
		if loadErr != nil {
			// One malformed file is not worth failing the library over,
			// but the caller should be able to say which one.
			return nil
		}
		if _, clash := lib.byID[skill.ID]; clash {
			// Two files claiming one ID: keep the first by sorted path so
			// the winner does not depend on directory order.
			return nil
		}
		lib.byID[skill.ID] = skill
		lib.skills = append(lib.skills, skill)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sort.Slice(lib.skills, func(i, j int) bool { return lib.skills[i].ID < lib.skills[j].ID })
	return lib, nil
}

// loadSkill reads and parses one file.
func loadSkill(root, rel string) (Skill, error) {
	full := filepath.Join(root, rel)
	info, err := os.Stat(full)
	if err != nil {
		return Skill{}, err
	}
	if info.Size() > maxSkillBytes {
		return Skill{}, fmt.Errorf("%s is larger than %d bytes", rel, maxSkillBytes)
	}
	raw, err := os.ReadFile(full) //nolint:gosec // path is under the operator-configured root
	if err != nil {
		return Skill{}, err
	}

	fm, body := splitFrontMatter(raw)
	id := skillID(rel)

	skill := Skill{
		ID:   id,
		Path: filepath.ToSlash(rel),
		Body: string(body),
	}
	if fm != nil {
		skill.Name = strings.TrimSpace(firstNonEmpty(fm.Name, fm.Title))
		skill.Description = strings.TrimSpace(firstNonEmpty(fm.Description, fm.Summary))
	}
	if skill.Name == "" {
		skill.Name = deriveName(rel, body)
	}
	if skill.Description == "" {
		skill.Description = deriveDescription(body)
	}
	return skill, nil
}

// skillID turns a relative path into an address.
//
// A file named SKILL.md takes its parent directory's name, because that is
// how a skill laid out as a directory reads: "gpu-jobs", not
// "gpu-jobs/SKILL".
func skillID(rel string) string {
	rel = filepath.ToSlash(rel)
	base := strings.TrimSuffix(rel, filepath.Ext(rel))
	if strings.EqualFold(filepath.Base(rel), "SKILL.md") {
		if dir := filepath.ToSlash(filepath.Dir(rel)); dir != "." {
			return dir
		}
	}
	return base
}

// splitFrontMatter separates a leading YAML block from the Markdown.
//
// Returns a nil header when the file has none, which is the common case for
// a document nobody has annotated yet -- and which must still load.
func splitFrontMatter(raw []byte) (*frontMatter, []byte) {
	trimmed := bytes.TrimLeft(raw, "\ufeff \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("---")) {
		return nil, raw
	}
	// Skip the opening fence and find its closing partner.
	rest := trimmed[3:]
	if i := bytes.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[i+1:]
	} else {
		return nil, raw
	}
	end := findFence(rest)
	if end < 0 {
		// An unterminated header is a document that happens to start with
		// a horizontal rule, not a broken skill.
		return nil, raw
	}

	var fm frontMatter
	if err := yaml.Unmarshal(rest[:end], &fm); err != nil {
		return nil, raw
	}
	body := rest[end:]
	if i := bytes.IndexByte(body, '\n'); i >= 0 {
		body = body[i+1:]
	}
	return &fm, bytes.TrimLeft(body, "\r\n")
}

// findFence returns the offset of the line that closes a front matter
// block, or -1.
func findFence(b []byte) int {
	offset := 0
	for offset < len(b) {
		lineEnd := bytes.IndexByte(b[offset:], '\n')
		var line []byte
		if lineEnd < 0 {
			line = b[offset:]
		} else {
			line = b[offset : offset+lineEnd]
		}
		if t := strings.TrimSpace(string(line)); t == "---" || t == "..." {
			return offset
		}
		if lineEnd < 0 {
			return -1
		}
		offset += lineEnd + 1
	}
	return -1
}

// deriveName falls back to the first Markdown heading, then the filename.
func deriveName(rel string, body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(t, "# "))
		}
	}
	base := filepath.Base(rel)
	if strings.EqualFold(base, "SKILL.md") {
		if dir := filepath.Base(filepath.Dir(rel)); dir != "." && dir != string(filepath.Separator) {
			return dir
		}
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// deriveDescription falls back to the document's first paragraph.
//
// Truncated, because this lands in a catalogue an agent reads in full
// before choosing: a skill whose "summary" is three pages defeats the
// point of having one.
func deriveDescription(body []byte) string {
	const maxLen = 300
	var para []string
	for _, line := range strings.Split(string(body), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			if len(para) > 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "```") {
			if len(para) > 0 {
				break
			}
			continue
		}
		para = append(para, t)
	}
	out := strings.Join(para, " ")
	if len(out) > maxLen {
		out = strings.TrimSpace(out[:maxLen]) + "..."
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
