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

package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// skillsFixture writes a small library and returns its root.
func skillsFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"gpu.md": "---\nname: Submitting GPU jobs\ndescription: How to request a GPU here.\n---\n" +
			"Use request_gpus = 1 and the local GPU partition.\n",
		"policy/queue.md": "---\nname: Queue policy\ndescription: Runtime limits and priorities.\n---\n" +
			"Jobs are limited to 72 hours.\n",
	}
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func skillsServer(t *testing.T, dir string) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Config{
		ScheddProvider: func() *htcondor.Schedd { return htcondor.NewSchedd("test", "127.0.0.1:1") },
		Logger:         logger,
		SkillsDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestSkillsToolsOfferedOnlyWhenPublished(t *testing.T) {
	withSkills := skillsServer(t, skillsFixture(t))
	if !withSkills.hasSkills() {
		t.Fatal("fixture did not load")
	}

	listed := map[string]bool{}
	for _, tool := range withSkills.handleListTools(context.Background(), nil).(map[string]interface{})["tools"].([]Tool) {
		listed[tool.Name] = true
	}
	if !listed["skills_list"] || !listed["skills_get"] {
		t.Error("skills tools missing when a library is published")
	}

	// A deployment with no skills must not advertise tools that can only
	// answer "this access point publishes no skills".
	without := skillsServer(t, "")
	listed = map[string]bool{}
	for _, tool := range without.handleListTools(context.Background(), nil).(map[string]interface{})["tools"].([]Tool) {
		listed[tool.Name] = true
	}
	if listed["skills_list"] || listed["skills_get"] {
		t.Error("skills tools advertised with no library loaded")
	}
}

func TestSkillsListAndGet(t *testing.T) {
	s := skillsServer(t, skillsFixture(t))
	ctx := context.Background()

	res, err := s.toolSkillsList(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]interface{})
	if m["count"].(int) != 2 {
		t.Errorf("count = %v, want 2", m["count"])
	}

	// The filter narrows on id, name and description alike.
	res, err = s.toolSkillsList(ctx, map[string]interface{}{"query": "gpu"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.(map[string]interface{})["count"].(int); got != 1 {
		t.Errorf("filtered count = %d, want 1", got)
	}

	got, err := s.toolSkillsGet(ctx, map[string]interface{}{"id": "gpu"})
	if err != nil {
		t.Fatal(err)
	}
	body := got.(map[string]interface{})["content"].(string)
	if !strings.Contains(body, "request_gpus") {
		t.Errorf("content = %q", body)
	}
	// Front matter must not reach the agent as content.
	if strings.Contains(body, "description:") {
		t.Errorf("front matter leaked: %q", body)
	}
}

// A near-miss is the common case, so the error should name alternatives
// rather than only refusing.
func TestSkillsGetUnknownNamesAlternatives(t *testing.T) {
	s := skillsServer(t, skillsFixture(t))
	_, err := s.toolSkillsGet(context.Background(), map[string]interface{}{"id": "gpus"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "gpu") {
		t.Errorf("error does not suggest what exists: %v", err)
	}
}

func TestSkillResourcesListed(t *testing.T) {
	s := skillsServer(t, skillsFixture(t))

	res := s.handleListResources(context.Background(), nil).(map[string]interface{})
	uris := map[string]string{}
	for _, r := range res["resources"].([]Resource) {
		uris[r.URI] = r.MimeType
	}
	if uris[skillsIndexURI] != "application/json" {
		t.Errorf("index resource missing or wrong type: %v", uris)
	}
	for _, want := range []string{"skill://gpu", "skill://policy/queue"} {
		if uris[want] != "text/markdown" {
			t.Errorf("resource %s missing or wrong type: %v", want, uris)
		}
	}
}

func TestReadSkillResources(t *testing.T) {
	s := skillsServer(t, skillsFixture(t))

	// The index parses and lists every skill with a usable URI.
	idx, err := s.readSkillResource(skillsIndexURI)
	if err != nil {
		t.Fatal(err)
	}
	text := idx.(map[string]interface{})["contents"].([]map[string]interface{})[0]["text"].(string)
	var parsed struct {
		Count  int `json:"count"`
		Skills []struct {
			ID, URI string
		} `json:"skills"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("index is not valid JSON: %v", err)
	}
	if parsed.Count != 2 || len(parsed.Skills) != 2 {
		t.Errorf("index lists %d skills, want 2", len(parsed.Skills))
	}
	for _, sk := range parsed.Skills {
		if sk.URI != skillURIPrefix+sk.ID {
			t.Errorf("index URI %q does not address id %q", sk.URI, sk.ID)
		}
		if _, err := s.readSkillResource(sk.URI); err != nil {
			t.Errorf("URI from the index does not resolve: %s: %v", sk.URI, err)
		}
	}

	if _, err := s.readSkillResource("skill://nope"); err == nil {
		t.Error("unknown skill resource resolved")
	}
}

// The nudge the operator asked for: an agent reads the instructions before
// deciding anything, so the catalogue has to be there, not just a pointer
// to a tool it has no reason to call yet.
func TestInstructionsNudgeTowardSkills(t *testing.T) {
	s := skillsServer(t, skillsFixture(t))

	instr := s.instructions.Load()
	if instr == nil {
		t.Fatal("no instructions built")
	}
	text := *instr

	for _, want := range []string{
		"Site skills",
		"before using other tools",
		"skills_get",
		"skill://index.json",
		"Submitting GPU jobs",        // named inline
		"How to request a GPU here.", // with its description
		"Queue policy",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("instructions missing %q", want)
		}
	}
}

// With no library the section must be absent entirely, not empty-but-present.
func TestInstructionsOmitSkillsWhenNonePublished(t *testing.T) {
	s := skillsServer(t, "")
	if instr := s.instructions.Load(); instr != nil && strings.Contains(*instr, "Site skills") {
		t.Error("instructions advertise skills with none loaded")
	}
}

// The point of reloading: the checkout changed, the path did not.
func TestSetSkillsDirPicksUpChanges(t *testing.T) {
	root := skillsFixture(t)
	s := skillsServer(t, root)

	if _, ok := s.skillsLibrary().Get("storage"); ok {
		t.Fatal("precondition: storage should not exist yet")
	}

	if err := os.WriteFile(filepath.Join(root, "storage.md"),
		[]byte("---\nname: Storage\ndescription: Where to put data.\n---\nUse /staging.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.SetSkillsDir(root)

	if _, ok := s.skillsLibrary().Get("storage"); !ok {
		t.Error("a reload did not pick up a new file")
	}
	// And the initialize text must name it, or an agent connecting after
	// the reload never learns it exists.
	if instr := s.instructions.Load(); instr == nil || !strings.Contains(*instr, "Where to put data.") {
		t.Error("instructions were not rebuilt after the reload")
	}
}

// A directory that has momentarily gone away -- a checkout being replaced,
// an automount that has not come back -- must not strip agents of the
// site's guidance.
func TestFailedReloadKeepsThePreviousLibrary(t *testing.T) {
	s := skillsServer(t, skillsFixture(t))
	before := s.skillsLibrary().Len()

	s.SetSkillsDir(filepath.Join(t.TempDir(), "does-not-exist"))

	if got := s.skillsLibrary().Len(); got != before {
		t.Errorf("library size = %d after a failed reload, want the previous %d", got, before)
	}
}

// Clearing the setting is different from failing to read it: it is an
// operator saying "stop publishing these".
func TestEmptyDirUnpublishesSkills(t *testing.T) {
	s := skillsServer(t, skillsFixture(t))
	s.SetSkillsDir("")

	if s.hasSkills() {
		t.Error("skills still published after the directory was cleared")
	}
	if instr := s.instructions.Load(); instr != nil && strings.Contains(*instr, "Site skills") {
		t.Error("instructions still advertise skills after they were unpublished")
	}
}

// The reload poll is what lets a site keep its library current by updating
// a checkout -- nothing outside this process can signal it, so it looks.
// These tests cover the two ways that goes wrong: never noticing a change,
// and "noticing" one that did not happen.

// skillsServerPolling is skillsServer with the reload poll running.
func skillsServerPolling(t *testing.T, dir string, interval time.Duration) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Config{
		ScheddProvider:       func() *htcondor.Schedd { return htcondor.NewSchedd("test", "127.0.0.1:1") },
		Logger:               logger,
		SkillsDir:            dir,
		SkillsReloadInterval: interval,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// eventuallyWithin bounds how long a poll-driven assertion waits. Generous
// against a loaded CI machine; the loop below exits as soon as the
// condition holds, so a passing run does not pay it.
const eventuallyWithin = 5 * time.Second

// eventually polls cond until it holds or the deadline passes. A fixed
// sleep would either be flaky on a loaded machine or slow on every run.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(eventuallyWithin)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", eventuallyWithin, what)
}

func TestReloadPollPicksUpANewSkill(t *testing.T) {
	root := skillsFixture(t)
	s := skillsServerPolling(t, root, 10*time.Millisecond)

	if _, ok := s.skillsLibrary().Get("storage"); ok {
		t.Fatal("precondition: storage should not exist yet")
	}

	if err := os.WriteFile(filepath.Join(root, "storage.md"),
		[]byte("---\nname: Storage\ndescription: Where to put data.\n---\nUse /staging.\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	eventually(t, "the poll to notice a new skill", func() bool {
		_, ok := s.skillsLibrary().Get("storage")
		return ok
	})

	// And the initialize text has to name it: an agent connecting after the
	// reload learns what exists from there, so a library that updated
	// without the text updating is only half a reload.
	eventually(t, "the instructions to name the new skill", func() bool {
		instr := s.instructions.Load()
		return instr != nil && strings.Contains(*instr, "Where to put data.")
	})
}

func TestReloadPollNoticesADeletedSkill(t *testing.T) {
	root := skillsFixture(t)
	s := skillsServerPolling(t, root, 10*time.Millisecond)

	if _, ok := s.skillsLibrary().Get("gpu"); !ok {
		t.Fatal("precondition: gpu should exist")
	}
	if err := os.Remove(filepath.Join(root, "gpu.md")); err != nil {
		t.Fatal(err)
	}

	eventually(t, "the poll to notice a removed skill", func() bool {
		_, ok := s.skillsLibrary().Get("gpu")
		return !ok
	})
}

// The expensive half of a reload is not reading the files, it is bumping
// the catalogue generation: that invalidates the per-scope SDK servers the
// transport caches, so every connected scope rebuilds. A poll whose normal
// outcome is "nothing changed" must not do that.
func TestReloadPollDoesNotChurnTheCatalog(t *testing.T) {
	s := skillsServerPolling(t, skillsFixture(t), 5*time.Millisecond)

	settled := s.catalogGen.Load()
	// Long enough for many ticks to have fired; if any of them republished,
	// the generation moves.
	time.Sleep(150 * time.Millisecond)

	if got := s.catalogGen.Load(); got != settled {
		t.Errorf("catalog generation moved from %d to %d with no change on disk; "+
			"every poll is invalidating the cached per-scope servers", settled, got)
	}
}

// Same property for the operator-driven path: a condor_reconfig run for an
// unrelated reason should not disturb live sessions' catalogues.
func TestSetSkillsDirIsQuietWhenNothingChanged(t *testing.T) {
	root := skillsFixture(t)
	s := skillsServer(t, root)

	settled := s.catalogGen.Load()
	s.SetSkillsDir(root)
	s.SetSkillsDir(root)

	if got := s.catalogGen.Load(); got != settled {
		t.Errorf("catalog generation moved from %d to %d on a reload of identical content", settled, got)
	}

	// But a real change still gets through -- the check above must not have
	// been bought by pinning the library.
	if err := os.WriteFile(filepath.Join(root, "storage.md"),
		[]byte("---\nname: Storage\ndescription: Where to put data.\n---\nUse /staging.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.SetSkillsDir(root)
	if _, ok := s.skillsLibrary().Get("storage"); !ok {
		t.Error("a real change was skipped along with the no-op reloads")
	}
	if s.catalogGen.Load() == settled {
		t.Error("catalog generation did not move for a real change")
	}
}

// Zero interval is an operator saying "I will drive reloads myself".
func TestNoPollWhenTheIntervalIsZero(t *testing.T) {
	root := skillsFixture(t)
	s := skillsServerPolling(t, root, 0)

	if err := os.WriteFile(filepath.Join(root, "storage.md"),
		[]byte("---\nname: Storage\ndescription: Where to put data.\n---\nUse /staging.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	if _, ok := s.skillsLibrary().Get("storage"); ok {
		t.Error("the library reloaded with polling disabled")
	}
	// The explicit path still works, which is the whole bargain of setting
	// the interval to zero.
	s.SetSkillsDir(root)
	if _, ok := s.skillsLibrary().Get("storage"); !ok {
		t.Error("an explicit reload did not work with polling disabled")
	}
}

func TestCloseStopsThePoll(t *testing.T) {
	root := skillsFixture(t)
	s := skillsServerPolling(t, root, 5*time.Millisecond)

	// Let it run at least one tick so we know it was alive to begin with.
	eventually(t, "the poll to run once", func() bool {
		return s.skillsLibrary().Len() > 0
	})

	s.Close()
	s.Close() // idempotent: Close runs again from t.Cleanup

	if err := os.WriteFile(filepath.Join(root, "storage.md"),
		[]byte("---\nname: Storage\ndescription: Where to put data.\n---\nUse /staging.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	if _, ok := s.skillsLibrary().Get("storage"); ok {
		t.Error("the poll kept reloading after Close")
	}
}

// A directory that goes away mid-poll must not empty the library: agents
// mid-session keep the guidance they had, and the next poll recovers.
func TestPollSurvivesTheDirectoryVanishing(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "skills")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "gpu.md"),
		[]byte("---\nname: GPU\ndescription: Ask for a GPU.\n---\nrequest_gpus = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := skillsServerPolling(t, root, 5*time.Millisecond)
	before := s.skillsLibrary().Len()
	if before == 0 {
		t.Fatal("precondition: the library should have loaded")
	}

	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	if got := s.skillsLibrary().Len(); got != before {
		t.Errorf("library size = %d after the directory vanished, want the previous %d", got, before)
	}
}
