package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
)

// maxSkillChars caps what one skill contributes to the conversation.
//
// Skills are prose written for people and are normally a few kilobytes,
// but the library accepts up to a megabyte per file, and a site that
// checks in something longer should not be able to spend a user's whole
// context on one tool call. The cut is announced in the text so the model
// knows it is reading a prefix rather than a short document.
const maxSkillChars = 24_000

// toolGetSiteSkill lets the chat assistant read one of the site's own
// skills, the same documents the MCP server serves agents through
// skills_get.
//
// The catalogue is already in the system prompt, so this tool is only
// ever called for a skill the model has seen named and decided is
// relevant; it does not need a search of its own. That is also why it is
// untagged: a site skill about the local GPU partition is as relevant on
// the submission page as on the jobs page.
func (s *Handler) toolGetSiteSkill() chat.Tool {
	return &chatTool{
		name: "get_site_skill",
		// Offered only where there is something to read. The catalogue
		// is in the system prompt for the same reason: both appear and
		// disappear with the library, which a reconfigure can replace
		// under a running server.
		available: func() bool { return s.chatSkills().Len() > 0 },
		description: `Read one of this site's own skills in full, by the id listed under ` +
			`"Site skills" in your instructions. Site skills are this access point's own ` +
			`documentation — local conventions, queue policy, which resources to request, ` +
			`worked procedures — and they describe choices that general HTCondor knowledge ` +
			`will contradict or omit. Read the relevant one before answering a question it covers.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"id": {
					"type": "string",
					"description": "The skill's id, or its name, as listed in your instructions."
				}
			},
			"required": ["id"]
		}`),
		exec: func(_ context.Context, _ string, in json.RawMessage) (string, error) {
			var args struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(in, &args); err != nil {
				return "", fmt.Errorf("invalid args: %w", err)
			}
			id := strings.TrimSpace(args.ID)
			if id == "" {
				return "", fmt.Errorf("id is required")
			}

			lib := s.chatSkills()
			if lib.Len() == 0 {
				return "", fmt.Errorf("this access point publishes no site skills")
			}
			sk, ok := lib.Get(id)
			if !ok {
				// Name what does exist. A model that misread an id from
				// the catalogue can correct itself on this turn; without
				// the list its only move is to guess again.
				return "", fmt.Errorf("no site skill %q; the skills published here are: %s",
					id, strings.Join(skillIDs(s), ", "))
			}

			body := sk.Body
			if len(body) > maxSkillChars {
				body = body[:maxSkillChars] + "\n\n[truncated: this skill is longer than one tool " +
					"call can carry]"
			}
			out := map[string]any{
				"id":          sk.ID,
				"name":        sk.Name,
				"description": sk.Description,
				"body":        body,
			}
			encoded, err := json.Marshal(out)
			if err != nil {
				return "", fmt.Errorf("encoding skill %q: %w", sk.ID, err)
			}
			return string(encoded), nil
		},
	}
}

// skillIDs is the published ids, sorted, for an error message that has to
// tell the model what it could have asked for instead.
func skillIDs(s *Handler) []string {
	list := s.chatSkills().List()
	ids := make([]string, 0, len(list))
	for _, sk := range list {
		ids = append(ids, sk.ID)
	}
	sort.Strings(ids)
	return ids
}
