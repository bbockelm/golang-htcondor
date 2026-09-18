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
	"fmt"
	"strings"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/skills"
)

// Site skills: the local documentation an access point publishes to agents.
//
// Exposed two ways on purpose. As TOOLS, because an agent that has already
// decided it needs guidance will look for one; and as RESOURCES, because a
// client that lists resources up front can surface the catalogue to a user
// without calling anything. The same library backs both.

const (
	skillsIndexURI = "skill://index.json"
	skillURIPrefix = "skill://"
)

// skillsLibrary returns the loaded library, or nil.
func (s *Server) skillsLibrary() *skills.Library {
	return s.skills.Load()
}

// hasSkills reports whether this deployment published any.
func (s *Server) hasSkills() bool {
	return s.skillsLibrary().Len() > 0
}

// isSkillTool reports whether name is one of the skills_* tools.
func isSkillTool(name string) bool {
	return name == "skills_list" || name == "skills_get"
}

// skillTools is the catalogue entry for the two tools.
//
// Read-only and side-effect free, so they belong in the read-only scope
// alongside the documentation lookups.
func skillTools() []Tool {
	return []Tool{
		{
			Name: "skills_list",
			Description: "List the site-authored skills published by this access point. " +
				"Skills are this site's own documentation -- local conventions, policies and " +
				"worked procedures that generic HTCondor knowledge does not cover. Consult " +
				"them before using other tools when a task touches how work is done here.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type": "string",
						"description": "Optional case-insensitive filter matched against skill " +
							"id, name and description.",
					},
				},
			},
		},
		{
			Name: "skills_get",
			Description: "Read one site-authored skill in full, by id or name, as returned by " +
				"skills_list. Returns the Markdown document.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "The skill's id, or its name.",
					},
				},
				"required": []string{"id"},
			},
		},
	}
}

// toolSkillsList answers skills_list.
func (s *Server) toolSkillsList(_ context.Context, args map[string]interface{}) (interface{}, error) {
	lib := s.skillsLibrary()
	if lib.Len() == 0 {
		return nil, fmt.Errorf("this access point publishes no skills")
	}

	query, _ := args["query"].(string)
	query = strings.ToLower(strings.TrimSpace(query))

	type entry struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Path        string `json:"path"`
	}
	out := make([]entry, 0, lib.Len())
	for _, sk := range lib.List() {
		if query != "" &&
			!strings.Contains(strings.ToLower(sk.ID), query) &&
			!strings.Contains(strings.ToLower(sk.Name), query) &&
			!strings.Contains(strings.ToLower(sk.Description), query) {
			continue
		}
		out = append(out, entry{ID: sk.ID, Name: sk.Name, Description: sk.Description, Path: sk.Path})
	}

	return map[string]interface{}{
		"skills": out,
		"count":  len(out),
		"hint":   "Read one in full with skills_get.",
	}, nil
}

// toolSkillsGet answers skills_get.
func (s *Server) toolSkillsGet(_ context.Context, args map[string]interface{}) (interface{}, error) {
	lib := s.skillsLibrary()
	if lib.Len() == 0 {
		return nil, fmt.Errorf("this access point publishes no skills")
	}
	id, _ := args["id"].(string)
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id is required; call skills_list to see what is available")
	}

	sk, ok := lib.Get(id)
	if !ok {
		// Name the alternatives rather than only refusing: the caller has
		// a near-miss far more often than a wholly wrong idea.
		var available []string
		for _, s := range lib.List() {
			available = append(available, s.ID)
			if len(available) >= 20 {
				break
			}
		}
		return nil, fmt.Errorf("no skill %q; available ids include: %s", id, strings.Join(available, ", "))
	}

	return map[string]interface{}{
		"id":          sk.ID,
		"name":        sk.Name,
		"description": sk.Description,
		"path":        sk.Path,
		"content":     sk.Body,
	}, nil
}

// skillResources lists the library as MCP resources.
//
// The index is listed first and separately so a client that shows only the
// first few resources still shows the thing that explains the rest.
func (s *Server) skillResources() []Resource {
	lib := s.skillsLibrary()
	if lib.Len() == 0 {
		return nil
	}
	out := make([]Resource, 0, lib.Len()+1)
	out = append(out, Resource{
		URI:         skillsIndexURI,
		Name:        "Site skills index",
		Description: fmt.Sprintf("Catalogue of the %d site-authored skills published by this access point.", lib.Len()),
		MimeType:    "application/json",
	})
	for _, sk := range lib.List() {
		out = append(out, Resource{
			URI:         skillURIPrefix + sk.ID,
			Name:        sk.Name,
			Description: sk.Description,
			MimeType:    "text/markdown",
		})
	}
	return out
}

// readSkillResource serves skill://index.json and skill://<id>.
func (s *Server) readSkillResource(uri string) (interface{}, error) {
	lib := s.skillsLibrary()
	if lib.Len() == 0 {
		return nil, fmt.Errorf("this access point publishes no skills")
	}

	if uri == skillsIndexURI {
		type entry struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			URI         string `json:"uri"`
			Path        string `json:"path"`
		}
		index := make([]entry, 0, lib.Len())
		for _, sk := range lib.List() {
			index = append(index, entry{
				ID: sk.ID, Name: sk.Name, Description: sk.Description,
				URI: skillURIPrefix + sk.ID, Path: sk.Path,
			})
		}
		body, err := json.MarshalIndent(map[string]interface{}{
			"skills": index,
			"count":  len(index),
		}, "", "  ")
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"contents": []map[string]interface{}{{
				"uri":      uri,
				"mimeType": "application/json",
				"text":     string(body),
			}},
		}, nil
	}

	id := strings.TrimPrefix(uri, skillURIPrefix)
	sk, ok := lib.Get(id)
	if !ok {
		return nil, fmt.Errorf("unknown skill resource: %s", uri)
	}
	return map[string]interface{}{
		"contents": []map[string]interface{}{{
			"uri":      uri,
			"mimeType": "text/markdown",
			"text":     sk.Body,
		}},
	}, nil
}

// skillsInstructions is the section added to the initialize response when
// a deployment publishes skills.
//
// It names them inline rather than only pointing at a tool. An agent reads
// the instructions before deciding anything, so the catalogue is what makes
// it recognise that a task is covered here; a bare "call skills_list" is
// advice it has no reason to take until after it has already guessed.
func skillsInstructions(lib *skills.Library) string {
	if lib.Len() == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n## Site skills\n\n")
	fmt.Fprintf(&b, "This access point publishes %d site-authored skill(s): its own "+
		"documentation for how work is done here -- local conventions, queue policy, "+
		"which resources to request, worked procedures.\n\n", lib.Len())
	b.WriteString("**Consult the relevant skill before using other tools** when a task " +
		"touches any of the subjects below. They describe choices specific to this site " +
		"that general HTCondor knowledge will contradict or omit. Read one with the " +
		"`skills_get` tool, or the resource `skill://<id>`; the full catalogue is " +
		"`skills_list` and the resource `skill://index.json`.\n\n")

	const maxListed = 60
	listed := lib.List()
	truncated := false
	if len(listed) > maxListed {
		listed, truncated = listed[:maxListed], true
	}
	for _, sk := range listed {
		if d := strings.TrimSpace(sk.Description); d != "" {
			fmt.Fprintf(&b, "- `%s` -- %s: %s\n", sk.ID, sk.Name, d)
		} else {
			fmt.Fprintf(&b, "- `%s` -- %s\n", sk.ID, sk.Name)
		}
	}
	if truncated {
		fmt.Fprintf(&b, "\n(%d more; call `skills_list` for the rest.)\n", lib.Len()-maxListed)
	}
	return b.String()
}

// SetSkillsDir loads (or reloads) the skill library from disk.
//
// Called at construction and again on a reconfigure, which is how a site
// publishes an updated checkout without restarting the daemon: pull the
// repository, then condor_reconfig.
//
// A failed load leaves the previous library in place rather than emptying
// it. A directory that has momentarily gone missing -- a checkout being
// replaced, an automount that has not come back -- should not silently
// strip an agent of the site's guidance mid-session.
//
// The initialize text is rebuilt afterwards because it names the skills;
// sessions that initialize after this call see the new catalogue.
func (s *Server) SetSkillsDir(dir string) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		s.skills.Store(nil)
		s.rebuildInstructions()
		return
	}

	lib, err := skills.Load(dir)
	if err != nil {
		if s.logger != nil {
			s.logger.Error(logging.DestinationMCP,
				"Could not load site skills; keeping the previously loaded set",
				"dir", dir, "error", err, "loaded", s.skillsLibrary().Len())
		}
		return
	}

	s.skills.Store(lib)
	if s.logger != nil {
		s.logger.Info(logging.DestinationMCP, "Loaded site skills",
			"dir", lib.Root(), "count", lib.Len())
	}
	s.rebuildInstructions()
}
