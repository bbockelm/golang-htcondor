package mcpserver

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

// Every result any test in this package produces is validated against the
// schema the server publishes for that tool, by a hook finalizeToolResult
// calls. This is a safety net for a failure mode the server cannot see:
// the outputSchema is enforced by the CLIENT, so a handler that returns a
// field with the wrong type keeps working here and fails over there, on
// every call, for every user.
//
// It is a net, not a substitute for the fixtures below it. A field only
// gets checked when a test produces a value for it, and the empty results
// most tests assert on carry no values at all -- which is exactly how
// doc_search came to publish matched_line as an integer while returning
// text (#960). Covering a field means populating it.
//
// Failures are collected rather than reported inline: the hook has no
// *testing.T (it runs deep inside a handler, sometimes on another
// goroutine), and panicking there would be swallowed by the dispatcher's
// recover(). TestMain reports them after the run instead, so a violation
// fails the package with the tool, the path and the payload named.

var (
	schemaViolationMu sync.Mutex
	schemaViolations  []string
	resolvedSchemas   = map[string]*jsonschema.Resolved{}
)

func TestMain(m *testing.M) {
	checkStructuredAgainstSchema = recordSchemaViolation
	code := m.Run()
	checkStructuredAgainstSchema = nil

	if found := takeSchemaViolations(); len(found) > 0 {
		fmt.Fprintf(os.Stderr,
			"\n%d tool result(s) did not satisfy the output schema this server publishes.\n"+
				"A client that validates structuredContent rejects these calls outright.\n\n%s\n",
			len(found), strings.Join(found, "\n\n"))
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// takeSchemaViolations returns what was collected and empties the list,
// releasing the lock before TestMain exits.
func takeSchemaViolations() []string {
	schemaViolationMu.Lock()
	defer schemaViolationMu.Unlock()
	found := schemaViolations
	schemaViolations = nil
	sort.Strings(found)
	return found
}

// recordSchemaViolation validates one structuredContent payload the way a
// client does -- marshal, then validate the JSON value -- and files any
// failure for TestMain to report.
func recordSchemaViolation(tool string, structured interface{}) {
	schemaViolationMu.Lock()
	defer schemaViolationMu.Unlock()

	resolved, ok := resolvedSchemas[tool]
	if !ok {
		schema := outputSchemaFor(tool)
		if schema == nil {
			resolvedSchemas[tool] = nil
			return
		}
		raw, err := json.Marshal(schema)
		if err != nil {
			schemaViolations = append(schemaViolations,
				fmt.Sprintf("%s: its published schema does not marshal: %v", tool, err))
			resolvedSchemas[tool] = nil
			return
		}
		var s jsonschema.Schema
		if err := json.Unmarshal(raw, &s); err != nil {
			schemaViolations = append(schemaViolations,
				fmt.Sprintf("%s: its published schema is not a JSON Schema: %v", tool, err))
			resolvedSchemas[tool] = nil
			return
		}
		resolved, err = s.Resolve(nil)
		if err != nil {
			schemaViolations = append(schemaViolations,
				fmt.Sprintf("%s: its published schema does not resolve: %v", tool, err))
			resolvedSchemas[tool] = nil
			return
		}
		resolvedSchemas[tool] = resolved
	}
	if resolved == nil {
		return
	}

	raw, err := json.Marshal(structured)
	if err != nil {
		return // not representable as JSON; nothing the schema can say
	}
	var instance interface{}
	if err := json.Unmarshal(raw, &instance); err != nil {
		return
	}
	if err := resolved.Validate(instance); err != nil {
		schemaViolations = append(schemaViolations,
			fmt.Sprintf("%s: %v\npayload: %s", tool, err, raw))
	}
}
