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

package skills

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// write creates a file, making its parents.
func write(t *testing.T, root, rel, body string) string {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestLoadReadsFrontMatter(t *testing.T) {
	root := t.TempDir()
	write(t, root, "gpu.md", `---
name: Submitting GPU jobs
description: How to request a GPU on this access point.
---
Ask for one GPU with request_gpus.
`)

	lib, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if lib.Len() != 1 {
		t.Fatalf("loaded %d skills, want 1", lib.Len())
	}
	s, ok := lib.Get("gpu")
	if !ok {
		t.Fatal("skill not addressable by id")
	}
	if s.Name != "Submitting GPU jobs" {
		t.Errorf("name = %q", s.Name)
	}
	if s.Description != "How to request a GPU on this access point." {
		t.Errorf("description = %q", s.Description)
	}
	// The front matter must not survive into the body an agent reads.
	if strings.Contains(s.Body, "description:") || strings.HasPrefix(s.Body, "---") {
		t.Errorf("front matter leaked into the body: %q", s.Body)
	}
	if !strings.Contains(s.Body, "request_gpus") {
		t.Errorf("body missing content: %q", s.Body)
	}
}

// `summary` is accepted alongside `description`: it reads more naturally
// to somebody writing site documentation.
func TestSummaryIsAcceptedAsDescription(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.md", "---\nname: A\nsummary: The short version.\n---\nbody\n")
	lib, _ := Load(root)
	s, _ := lib.Get("a")
	if s.Description != "The short version." {
		t.Errorf("description = %q, want the summary", s.Description)
	}
}

// A document nobody has annotated must still load and still be useful in
// a catalogue, or a site gets nothing until it edits every file.
func TestSkillWithoutFrontMatter(t *testing.T) {
	root := t.TempDir()
	write(t, root, "policy.md", "# Queue policy\n\nJobs are limited to 72 hours of runtime.\n\nMore detail follows.\n")

	lib, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := lib.Get("policy")
	if !ok {
		t.Fatal("not loaded")
	}
	if s.Name != "Queue policy" {
		t.Errorf("name = %q, want the first heading", s.Name)
	}
	if !strings.Contains(s.Description, "72 hours") {
		t.Errorf("description = %q, want the first paragraph", s.Description)
	}
}

// A checkout is the expected input, and .git alone holds thousands of
// files -- none of them documentation.
func TestHiddenDirectoriesAreSkipped(t *testing.T) {
	root := t.TempDir()
	write(t, root, "real.md", "# Real\n")
	write(t, root, ".git/objects/deadbeef.md", "# Not a skill\n")
	write(t, root, ".hidden/notes.md", "# Also not\n")
	write(t, root, "docs/.draft.md", "# Hidden file\n")
	write(t, root, "docs/nested.md", "# Nested\n")

	lib, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range lib.List() {
		ids = append(ids, s.ID)
	}
	want := []string{"docs/nested", "real"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("ids = %v, want %v", ids, want)
	}
}

// A skill laid out as a directory reads as its directory name.
func TestSkillDotMDTakesItsDirectoryName(t *testing.T) {
	root := t.TempDir()
	write(t, root, "gpu-jobs/SKILL.md", "---\ndescription: d\n---\nbody\n")

	lib, _ := Load(root)
	if _, ok := lib.Get("gpu-jobs"); !ok {
		var ids []string
		for _, s := range lib.List() {
			ids = append(ids, s.ID)
		}
		t.Errorf("SKILL.md did not take its directory name; ids = %v", ids)
	}
	// Its name falls back to the directory too, not to "SKILL".
	s, _ := lib.Get("gpu-jobs")
	if s.Name == "SKILL" {
		t.Error("name fell back to the filename rather than the directory")
	}
}

// Only Markdown is a skill: a checkout carries scripts and data too.
func TestNonMarkdownIsIgnored(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.md", "# A\n")
	write(t, root, "script.sh", "#!/bin/sh\n")
	write(t, root, "data.json", "{}\n")
	write(t, root, "README.MD", "# Upper case extension\n")

	lib, _ := Load(root)
	if lib.Len() != 2 {
		var ids []string
		for _, s := range lib.List() {
			ids = append(ids, s.ID)
		}
		t.Errorf("loaded %v, want the two Markdown files (extension match is case-insensitive)", ids)
	}
}

// A link is the one way a file outside the configured directory could be
// served from inside it.
func TestSymlinksAreNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.md")
	if err := os.WriteFile(secret, []byte("# Secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	write(t, root, "real.md", "# Real\n")
	if err := os.Symlink(secret, filepath.Join(root, "linked.md")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkeddir")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	lib, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range lib.List() {
		if strings.Contains(s.Body, "Secret") {
			t.Errorf("served a file from outside the root via %s", s.Path)
		}
	}
	if lib.Len() != 1 {
		t.Errorf("loaded %d skills, want only the real one", lib.Len())
	}
}

// An ID can never escape the root, whatever the caller passes.
func TestGetCannotEscapeTheLibrary(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.md", "# A\n")
	lib, _ := Load(root)

	for _, probe := range []string{
		"../../../etc/passwd",
		"../a",
		"/etc/passwd",
		"a/../../b",
	} {
		if _, ok := lib.Get(probe); ok {
			t.Errorf("Get(%q) resolved to a skill", probe)
		}
	}
}

// Addressing by name is what an agent naturally does after reading the
// index, and the forms it is likely to produce should work.
func TestGetAcceptsNameAndTolerantForms(t *testing.T) {
	root := t.TempDir()
	write(t, root, "docs/gpu.md", "---\nname: GPU Jobs\ndescription: d\n---\nbody\n")
	lib, _ := Load(root)

	for _, probe := range []string{"docs/gpu", "GPU Jobs", "gpu jobs", "./docs/gpu", "docs/gpu.md"} {
		if _, ok := lib.Get(probe); !ok {
			t.Errorf("Get(%q) did not resolve", probe)
		}
	}
	if _, ok := lib.Get("nonexistent"); ok {
		t.Error("Get resolved something that does not exist")
	}
}

func TestLoadRejectsABadRoot(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Error("empty root must be an error")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("missing directory must be an error")
	}
	f := filepath.Join(t.TempDir(), "file.md")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f); err == nil {
		t.Error("a file is not a library")
	}
}

// An unterminated "---" is a document that opens with a horizontal rule,
// not a broken skill.
func TestUnterminatedFrontMatterIsNotFatal(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.md", "---\nthis never closes\n\n# Heading\n")
	lib, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := lib.Get("a")
	if !ok {
		t.Fatal("not loaded")
	}
	if !strings.Contains(s.Body, "never closes") {
		t.Errorf("body was truncated: %q", s.Body)
	}
}

// An oversized file is skipped, not loaded and not fatal.
func TestOversizedSkillIsSkipped(t *testing.T) {
	root := t.TempDir()
	write(t, root, "ok.md", "# Fine\n")
	write(t, root, "huge.md", strings.Repeat("x", maxSkillBytes+1))

	lib, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lib.Get("huge"); ok {
		t.Error("an oversized file was loaded")
	}
	if _, ok := lib.Get("ok"); !ok {
		t.Error("the oversized file cost us the rest of the library")
	}
}
