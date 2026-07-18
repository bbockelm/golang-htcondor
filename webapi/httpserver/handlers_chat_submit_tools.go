package httpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
	"github.com/bbockelm/golang-htcondor/webapi/templates"
)

// Submit-page chat tools.
//
// Most are client-side stubs whose schemas live here so the LLM sees
// what's available; execution is in the SPA — the engine forwards
// the tool_use to the browser and the next POST carries the result
// back. The matching dispatch is in
// frontend/src/app/submit/page.tsx, which builds a hooks bag keyed
// by these tool names.
//
// One server-side tool (toolListSubmitTemplates) lives here too: it
// pulls the catalog the LLM should consult BEFORE inventing a new
// template, so a "scaffold a sleep job" prompt finds the existing
// "sleep" template instead of writing one from scratch.
//
// Design notes:
//   - Client-side tools are `clientSide: true`, `confirm: false`, and
//     tagged with `pages: ["submit"]` so they're invisible from the
//     jobs page (an LLM jailbreak that calls them outside their
//     context fails at the schema-advertise step).
//   - Schemas are deliberately specific: the LLM gets clear field
//     names instead of a generic "set_field(path, value)". Larger
//     tool list, but the model never has to guess paths.
//   - The user can click Submit ONLY by hand. There is no submit
//     tool here — that's a deliberate omission, not an oversight.

// toolListSubmitTemplates lists the user's available submit templates
// (built-in, global, and personal saved). Read-only, server-side.
//
// We expose this as a dedicated tool rather than embedding the list
// in the system prompt for two reasons:
//  1. The catalog grows as the user saves templates; embedding would
//     be stale on every save without a hot-reload.
//  2. The LLM only needs the catalog for "scaffold me X"-style prompts,
//     not for every turn — making it a tool keeps the per-turn
//     prompt small.
//
// We project name + description + columns + source (built-in / global
// / user) so the LLM has enough to recommend a template, but NOT the
// full body — bodies can be hundreds of lines and burn token budget
// for no gain at the recommendation step. The user (or a follow-up
// chat turn) reads the body via the SPA's library mode.
func (s *Handler) toolListSubmitTemplates() chat.Tool {
	return &chatTool{
		name:  "list_submit_templates",
		pages: submitPageTools,
		description: `List the user's available submit-file templates (built-in, ` +
			`site-global, and personal saved). Use BEFORE writing a custom submit-file ` +
			`body — if a template already exists for what the user wants ` +
			`(e.g. "sleep", "Python script with GPUs", "monte-carlo sweep"), recommend ` +
			`it via switch_to_custom_template (start_from="current") rather than ` +
			`scaffolding from scratch. Returns id, name, description, columns, and ` +
			`source for each template; bodies are NOT included to keep responses small.`,
		schema: json.RawMessage(`{"type":"object","properties":{}}`),
		exec: func(_ context.Context, actor string, _ json.RawMessage) (string, error) {
			if s.templateLibrary == nil {
				return "", fmt.Errorf("template library not configured on this server")
			}
			all, _ := s.templateLibrary.AllWithError(actor)
			out := make([]map[string]any, 0, len(all))
			for _, t := range all {
				cols := make([]string, 0, len(t.Columns))
				for _, c := range t.Columns {
					cols = append(cols, c.Name)
				}
				row := map[string]any{
					"id":          t.ID,
					"name":        t.Name,
					"description": t.Description,
					"columns":     cols,
					"source":      string(t.Source),
				}
				// User templates carry an owner; shared ones owned by
				// other users let the LLM disambiguate ("the 'analyze'
				// from alice" vs the user's own). Visibility is
				// useful so the LLM can hint "do you want to fork
				// alice's shared template?" rather than treating it
				// as if it were the actor's own.
				if t.Source == templates.SourceUser {
					row["owner"] = t.Owner
					row["visibility"] = string(t.Visibility)
					row["mine"] = t.Owner == actor
				}
				out = append(out, row)
			}
			body, _ := json.Marshal(map[string]any{
				"templates": out,
				"count":     len(out),
			})
			return string(body), nil
		},
	}
}

// toolHighlightSection asks the SPA to flash a labeled UI region.
// The LLM uses this as a "look here" gesture after answering.
func toolHighlightSection() chat.Tool {
	return &chatTool{
		name:       "highlight_section",
		pages:      submitPageTools,
		clientSide: true,
		description: `Briefly flash a section of the submit-page UI to draw the user's eye ` +
			`after you've answered. Use sparingly — once per answer at most. Sections: ` +
			`"template" (template picker / custom-draft body), "table" (per-job rows), ` +
			`"inputs" (shared input files), "resources" (CPU/memory/disk override), ` +
			`"submit" (the Submit button itself).`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"section": {
					"type": "string",
					"enum": ["template", "table", "inputs", "resources", "submit"]
				}
			},
			"required": ["section"]
		}`),
	}
}

// toolSetTemplateBody overwrites the custom-draft submit-file body.
// If the user is currently in library mode, the SPA forks the
// selected template into the custom draft first.
func toolSetTemplateBody() chat.Tool {
	return &chatTool{
		name:       "set_template_body",
		pages:      submitPageTools,
		clientSide: true,
		description: `Replace the custom submit-file body with new contents (the multi-line ` +
			`text block that becomes the HTCondor submit file). Use when the user asks you ` +
			`to scaffold or rewrite their submit file. The body should follow condor_submit ` +
			`syntax (executable, arguments, request_cpus, transfer_input_files, etc.) — ` +
			`but DO NOT include a 'queue' line. The page synthesizes the queue statement ` +
			`from the per-job table; including 'queue' here will be rejected. If the user ` +
			`is in library mode, the SPA forks the selected template into the custom ` +
			`draft before applying.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"contents": {
					"type": "string",
					"description": "Full submit-file body, with newlines preserved."
				}
			},
			"required": ["contents"]
		}`),
	}
}

// toolSetInlineScript writes the wrapper script that the submit page
// folds in as the executable. Creates the script when absent;
// overwrites otherwise.
func toolSetInlineScript() chat.Tool {
	return &chatTool{
		name:       "set_inline_script",
		pages:      submitPageTools,
		clientSide: true,
		description: `Create or overwrite the inline wrapper script in the user's draft. The ` +
			`SPA stages the script as a transferred input file and rewrites the submit body ` +
			`so 'executable = <filename>' uses it. Use this when the user wants to wrap ` +
			`their command (set up env vars, source modules, run a script before /after the ` +
			`payload). Provide a filename ending in .sh and shebang-prefixed contents.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"filename": {
					"type": "string",
					"description": "Script filename including extension (e.g. 'wrapper.sh'). Used as the executable name."
				},
				"content": {
					"type": "string",
					"description": "Full script contents including the #! line."
				}
			},
			"required": ["filename", "content"]
		}`),
	}
}

// toolClearInlineScript removes the wrapper script from the draft.
// The SPA also reverts the submit-file body's executable line if it
// was pointing at the script.
func toolClearInlineScript() chat.Tool {
	return &chatTool{
		name:        "clear_inline_script",
		pages:       submitPageTools,
		clientSide:  true,
		description: `Remove the inline wrapper script from the draft. Does nothing if no script is set.`,
		schema:      json.RawMessage(`{"type":"object","properties":{}}`),
	}
}

// toolSetResources toggles the resource-override checkbox and sets
// the CPU/memory/disk values. Pass only the fields you want changed;
// omitted fields leave the existing value alone.
func toolSetResources() chat.Tool {
	return &chatTool{
		name:       "set_resources",
		pages:      submitPageTools,
		clientSide: true,
		description: `Set per-job resource requests (CPU count, memory, disk). Enables the ` +
			`resource-override checkbox if it's off. Use when the user describes a workload ` +
			`size ("each job needs 8 GB of memory and 4 cores"). Memory is in MiB and disk ` +
			`is in MiB; convert from human units (GB, MB) before calling. Pass only the ` +
			`fields you want to change.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"cpus":      {"type": "integer", "minimum": 1, "maximum": 256, "description": "request_cpus"},
				"memory_mb": {"type": "integer", "minimum": 1, "description": "request_memory in MiB"},
				"disk_mb":   {"type": "integer", "minimum": 1, "description": "request_disk in MiB"}
			}
		}`),
	}
}

// toolAddTemplateInputFile drops a default attached file into the
// custom-draft template. Different from set_inline_script: this is
// for arbitrary supporting files (config, certificates, helper
// scripts) that should travel with every job.
func toolAddTemplateInputFile() chat.Tool {
	return &chatTool{
		name:       "add_template_input_file",
		pages:      submitPageTools,
		clientSide: true,
		description: `Add a default input file to the custom-draft template. The file is ` +
			`staged with every job submitted from this template. Use for supporting config ` +
			`or helper files that the user wants bundled. For the executable wrapper ` +
			`specifically, use set_inline_script instead.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name":    {"type": "string", "description": "Filename inside the job's working directory"},
				"content": {"type": "string", "description": "File contents (UTF-8 text)"}
			},
			"required": ["name", "content"]
		}`),
	}
}

// toolSetTableCount switches the table to "Run N copies" mode and
// sets the count. Use when the user just wants the same job to run
// N times (typical for stress tests, Monte Carlo runs, or anything
// that differentiates per-job via $(ProcId) instead of explicit
// columns). The page emits `queue N` rather than a `queue ... from`
// statement.
func toolSetTableCount() chat.Tool {
	return &chatTool{
		name:       "set_table_count",
		pages:      submitPageTools,
		clientSide: true,
		description: `Switch the per-job table to "Run N copies" mode and set the count. ` +
			`Use when the user wants N identical jobs and per-job parameter variation is ` +
			`unnecessary (or is handled in the body via $(ProcId)). Replaces any prior ` +
			`manual rows or upload selection. Default count is 1; cap is 10000.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"count": {
					"type": "integer",
					"description": "Number of jobs to submit (1 - 10000).",
					"minimum": 1,
					"maximum": 10000
				}
			},
			"required": ["count"]
		}`),
	}
}

// toolSetTemplateColumns edits the column list on the custom draft.
// Columns are the per-job variables a manual-mode table fills in.
// Pass each column as { name, description? }; existing columns are
// fully replaced. Use BEFORE set_table_rows so the row reshape
// matches the column count the agent expects.
func toolSetTemplateColumns() chat.Tool {
	return &chatTool{
		name:       "set_template_columns",
		pages:      submitPageTools,
		clientSide: true,
		description: `Replace the custom draft's column list. Each column is the name of a ` +
			`per-job variable (used in the submit-file body as $(name) and as a header in ` +
			`the manual table). Use BEFORE set_table_rows so the rows match the column ` +
			`count. Names must be valid HTCondor identifiers (letters/digits/underscores; ` +
			`must not start with a digit). The optional description shows as a tooltip on ` +
			`the column header.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"columns": {
					"type": "array",
					"description": "Ordered list of columns; replaces the existing list.",
					"items": {
						"type": "object",
						"properties": {
							"name":        {"type": "string"},
							"description": {"type": "string"}
						},
						"required": ["name"]
					}
				}
			},
			"required": ["columns"]
		}`),
	}
}

// toolSetTableRows replaces the per-job table with the supplied rows.
// The chat workflow on this page is: pick / scaffold a template
// (which defines the column names), THEN set rows so each row becomes
// one job. Without this tool the agent could only produce a template;
// the user would still have to fill the table by hand.
//
// The SPA enforces that each row has exactly len(active.columns)
// cells — extra cells are dropped, missing cells are padded empty —
// and flips tableSource to "manual" so this overrides any previous
// upload selection.
func toolSetTableRows() chat.Tool {
	return &chatTool{
		name:       "set_table_rows",
		pages:      submitPageTools,
		clientSide: true,
		description: `Replace the per-job table with the supplied rows. Each row becomes ` +
			`one HTCondor job; cells correspond positionally to the active template's ` +
			`columns. Use after the template is set so the column count matches. Switches ` +
			`the table to manual-edit mode (overriding any prior file-upload selection). ` +
			`Pass an empty list to clear the table.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"rows": {
					"type": "array",
					"description": "List of rows. Each row is an array of strings, one per template column.",
					"items": {
						"type": "array",
						"items": {"type": "string"}
					}
				}
			},
			"required": ["rows"]
		}`),
	}
}

// toolSelectTemplate switches the page into library mode and picks
// a specific template by id. Use this AFTER list_submit_templates
// has confirmed the id exists. Without this tool the agent could
// only describe a template; the user would still have to click it.
func toolSelectTemplate() chat.Tool {
	return &chatTool{
		name:       "select_template",
		pages:      submitPageTools,
		clientSide: true,
		description: `Select an existing library template by id (use list_submit_templates ` +
			`to discover ids). Switches the page into library mode and activates the named ` +
			`template — the user immediately sees that template's body, columns, and any ` +
			`default input files. Use this when an existing template matches what the user ` +
			`wants and they don't need custom edits. If they DO need edits on top, follow ` +
			`up with switch_to_custom_template (start_from="current") to fork the selection ` +
			`into the custom draft.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"id": {
					"type": "string",
					"description": "Template id from list_submit_templates."
				}
			},
			"required": ["id"]
		}`),
	}
}

// toolSwitchToCustomTemplate flips the template picker out of
// library mode into custom-edit mode. Optional start_from picks
// whether the new draft is blank or forked from the currently-
// selected library template.
func toolSwitchToCustomTemplate() chat.Tool {
	return &chatTool{
		name:       "switch_to_custom_template",
		pages:      submitPageTools,
		clientSide: true,
		description: `Switch the template picker out of library mode and into the custom-draft ` +
			`editor. Use before any tool that mutates the submit body if the user is currently ` +
			`viewing a library template. Default behavior forks the current selection so the ` +
			`user keeps their starting point; pass start_from="blank" to clear the slate.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"start_from": {
					"type": "string",
					"enum": ["current", "blank"],
					"description": "current (default): copy the selected library template into the draft. blank: empty draft."
				}
			}
		}`),
	}
}

// toolSetTemplateDescription edits the custom draft's name and/or
// description. Both fields are optional — omit one to leave it.
func toolSetTemplateDescription() chat.Tool {
	return &chatTool{
		name:       "set_template_description",
		pages:      submitPageTools,
		clientSide: true,
		description: `Update the custom draft's name or description. Use when the user wants ` +
			`to label their draft for "Save as template". Pass only the fields you want changed.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name":        {"type": "string"},
				"description": {"type": "string"}
			}
		}`),
	}
}

// ---------------------------------------------------------------------
// Inline files: in-draft files that ride along with the job. The
// existing inlineScript is the wrapper (mode 0755, becomes the
// executable). These tools manage *additional* sandbox files — most
// commonly a Python / R / SQL script that the wrapper invokes. The
// SPA encodes them in the per-job multipart upload as mode 0644.
//
// The agent often needs to iterate (read what it wrote, fix one
// section). All operations key by the file's `name`; collisions with
// the wrapper script are rejected (use set_inline_script for that).
// ---------------------------------------------------------------------

// toolAddInlineFile creates a new in-draft sandbox file. Errors if a
// file by that name already exists — the LLM should call
// set_inline_file_content to overwrite, or read first to check.
func toolAddInlineFile() chat.Tool {
	return &chatTool{
		name:       "add_inline_file",
		pages:      submitPageTools,
		clientSide: true,
		description: `Create a NEW in-draft file that rides along with the job (uploaded as ` +
			`mode 0644 in the job's sandbox; reachable by the executable as a relative path). ` +
			`Use for the payload script the wrapper invokes — e.g. analyze.py, model.R, ` +
			`query.sql. Errors if a file by that name already exists; use set_inline_file_content ` +
			`to overwrite or replace_in_inline_file to surgically edit. The wrapper script ` +
			`itself is managed via set_inline_script — don't use this tool for that.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name": {
					"type": "string",
					"description": "Filename (no path components). Must be unique within the draft."
				},
				"content": {
					"type": "string",
					"description": "Full file contents."
				}
			},
			"required": ["name", "content"]
		}`),
	}
}

// toolReadInlineFile returns the current contents of a draft inline
// file (additional or the wrapper script). Used so the agent can
// re-read what's there before issuing a replace, or quote sections
// back to the user.
func toolReadInlineFile() chat.Tool {
	return &chatTool{
		name:       "read_inline_file",
		pages:      submitPageTools,
		clientSide: true,
		description: `Return the current contents of a draft inline file by name. Works for both ` +
			`the wrapper script (the one set via set_inline_script) and additional files added ` +
			`via add_inline_file. Use BEFORE replace_in_inline_file when you need to confirm ` +
			`the exact bytes you're about to edit, or when the user asks "what's in foo.py?".`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name": {"type": "string", "description": "Filename to read."}
			},
			"required": ["name"]
		}`),
	}
}

// toolReplaceInInlineFile is a literal find/replace in an inline
// file. Refuses when the find string isn't found OR matches multiple
// times — the LLM must disambiguate by passing more surrounding
// context. This avoids "wrong line replaced" surprises that a regex
// or first-match policy would mask.
func toolReplaceInInlineFile() chat.Tool {
	return &chatTool{
		name:       "replace_in_inline_file",
		pages:      submitPageTools,
		clientSide: true,
		description: `Find/replace a literal substring inside a draft inline file. The 'find' ` +
			`string must appear EXACTLY ONCE in the file — pass enough surrounding context to ` +
			`disambiguate. Use for surgical edits: tweaking one line, fixing a typo, swapping ` +
			`a hard-coded path. To replace the whole file, use set_inline_file_content. To see ` +
			`what's currently there, call read_inline_file first.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name":    {"type": "string", "description": "Filename to edit."},
				"find":    {"type": "string", "description": "Literal substring to locate. Must match EXACTLY ONCE."},
				"replace": {"type": "string", "description": "Replacement text. Pass empty string to delete the match."}
			},
			"required": ["name", "find", "replace"]
		}`),
	}
}

// toolSetInlineFileContent overwrites a draft inline file's contents
// in full. Creates the file if it doesn't exist. Use for whole-file
// rewrites; smaller edits should go through replace_in_inline_file.
func toolSetInlineFileContent() chat.Tool {
	return &chatTool{
		name:       "set_inline_file_content",
		pages:      submitPageTools,
		clientSide: true,
		description: `Replace the entire contents of an additional inline file (NOT the wrapper ` +
			`script — use set_inline_script for that). Creates the file if absent. Use for ` +
			`whole-file rewrites; for smaller edits prefer replace_in_inline_file so partial ` +
			`changes don't blow away the user's work.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name":    {"type": "string", "description": "Filename to overwrite or create."},
				"content": {"type": "string", "description": "Full file contents."}
			},
			"required": ["name", "content"]
		}`),
	}
}

// toolDeleteInlineFile removes an additional inline file from the
// draft. Doesn't touch the wrapper script (clear_inline_script does).
func toolDeleteInlineFile() chat.Tool {
	return &chatTool{
		name:       "delete_inline_file",
		pages:      submitPageTools,
		clientSide: true,
		description: `Remove an additional inline file from the draft. No-op if the file isn't ` +
			`present. Does NOT touch the wrapper script — use clear_inline_script for that.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name": {"type": "string"}
			},
			"required": ["name"]
		}`),
	}
}

// ---------------------------------------------------------------------
// Save template
// ---------------------------------------------------------------------

// toolSaveTemplate opens a save-template confirmation dialog
// pre-populated with the agent's suggested name / description /
// visibility. The user can edit any of those fields in the dialog
// before clicking Save (or Overwrite if the id collides with their
// own existing template). This tool is ALWAYS dialog-gated: the
// actual POST happens from the dialog, not from this tool. The
// tool's return value reflects what the user did (saved / overwrote
// / canceled / renamed) so the LLM can react sensibly on the next
// turn ("I saved it as 'gpu-analyze' — anything else?").
//
// Visibility defaults to private. Pass "shared" to suggest a shared
// template, but the user can still flip it in the dialog.
func toolSaveTemplate() chat.Tool {
	return &chatTool{
		name:       "save_template",
		pages:      submitPageTools,
		clientSide: true,
		description: `Save the current custom draft as a reusable template. Opens a confirmation ` +
			`dialog where the user can rename it, edit the description, and toggle visibility ` +
			`(private vs. shared with everyone on this server) before saving. Use when the user ` +
			`says "save this as a template" or after scaffolding something they're likely to ` +
			`re-use ("submit 100 of these"). Pass a sensible suggested name (slug-friendly: ` +
			`lowercase, hyphens) and a one-sentence description; the user can override both. ` +
			`This tool will NOT save without an explicit user click in the dialog.`,
		schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"id": {
					"type": "string",
					"description": "Template id (slug-friendly: lowercase, hyphens, no spaces). The user can change it in the dialog."
				},
				"name": {
					"type": "string",
					"description": "Human-readable display name."
				},
				"description": {
					"type": "string",
					"description": "One-sentence summary of what the template scaffolds."
				},
				"visibility": {
					"type": "string",
					"enum": ["private", "shared"],
					"description": "Suggested visibility. Default 'private'. The user can flip this in the dialog."
				}
			},
			"required": ["id", "name"]
		}`),
	}
}
