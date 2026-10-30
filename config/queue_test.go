package config

import (
	"slices"
	"strings"
	"testing"
)

// Helper function to parse queue statements
func parseQueueStatements(input string) ([]Statement, error) {
	lexer := NewLexer(strings.NewReader(input))
	return Parse(lexer)
}

// parseQueueStatementsStrict is parseQueueStatements for inputs that must be
// rejected: Parse drops a bad statement and reports success, ParseStrict says
// so.
func parseQueueStatementsStrict(input string) ([]Statement, error) {
	lexer := NewLexer(strings.NewReader(input))
	return ParseStrict(lexer)
}

func TestQueueSimple(t *testing.T) {
	input := `
queue
`
	stmts, err := parseQueueStatements(input)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if len(stmts) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(stmts))
	}

	queueStmt, ok := stmts[0].(*QueueStatement)
	if !ok {
		t.Fatalf("Expected QueueStatement, got %T", stmts[0])
	}

	if queueStmt.Count != 1 {
		t.Errorf("Expected count 1, got %d", queueStmt.Count)
	}
}

func TestQueueWithCount(t *testing.T) {
	input := `
queue 10
`
	stmts, err := parseQueueStatements(input)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	queueStmt := stmts[0].(*QueueStatement)
	if queueStmt.Count != 10 {
		t.Errorf("Expected count 10, got %d", queueStmt.Count)
	}
}

func TestQueueFromFile(t *testing.T) {
	input := `
queue var1, var2 from inputfile.txt
`
	stmts, err := parseQueueStatements(input)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	queueStmt := stmts[0].(*QueueStatement)
	if len(queueStmt.VarNames) != 2 {
		t.Errorf("Expected 2 var names, got %d", len(queueStmt.VarNames))
	}
	if queueStmt.VarNames[0] != "var1" {
		t.Errorf("Expected var1, got %s", queueStmt.VarNames[0])
	}
	if queueStmt.VarNames[1] != "var2" {
		t.Errorf("Expected var2, got %s", queueStmt.VarNames[1])
	}
	if queueStmt.File != "inputfile.txt" {
		t.Errorf("Expected inputfile.txt, got %s", queueStmt.File)
	}
}

func TestQueueCountFromFile(t *testing.T) {
	input := `
queue 5 var from data.csv
`
	stmts, err := parseQueueStatements(input)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	queueStmt := stmts[0].(*QueueStatement)
	if queueStmt.Count != 5 {
		t.Errorf("Expected count 5, got %d", queueStmt.Count)
	}
	if queueStmt.File != "data.csv" {
		t.Errorf("Expected data.csv, got %s", queueStmt.File)
	}
}

func TestQueueIn(t *testing.T) {
	input := `
queue item in (apple, banana, cherry)
`
	stmts, err := parseQueueStatements(input)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	queueStmt := stmts[0].(*QueueStatement)
	if len(queueStmt.VarNames) != 1 || queueStmt.VarNames[0] != "item" {
		t.Errorf("Expected var name 'item', got %v", queueStmt.VarNames)
	}
	if len(queueStmt.Items) != 3 {
		t.Fatalf("Expected 3 items, got %d", len(queueStmt.Items))
	}
	expectedItems := []string{"apple", "banana", "cherry"}
	for i, expected := range expectedItems {
		if queueStmt.Items[i] != expected {
			t.Errorf("Item %d: expected %s, got %s", i, expected, queueStmt.Items[i])
		}
	}
}

func TestQueueCountIn(t *testing.T) {
	input := `
queue 2 var in (foo, bar)
`
	stmts, err := parseQueueStatements(input)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	queueStmt := stmts[0].(*QueueStatement)
	if queueStmt.Count != 2 {
		t.Errorf("Expected count 2, got %d", queueStmt.Count)
	}
	if len(queueStmt.Items) != 2 {
		t.Errorf("Expected 2 items, got %d", len(queueStmt.Items))
	}
}

func TestQueueMatching(t *testing.T) {
	input := `
queue matching files *.dat
`
	stmts, err := parseQueueStatements(input)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	queueStmt := stmts[0].(*QueueStatement)
	// For matching, the pattern is stored in File field
	if queueStmt.File == "" {
		t.Error("Expected File field to contain pattern")
	}
}

func TestQueueMatchingWithCount(t *testing.T) {
	input := `
queue 3 matching files
`
	stmts, err := parseQueueStatements(input)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	queueStmt := stmts[0].(*QueueStatement)
	if queueStmt.Count != 3 {
		t.Errorf("Expected count 3, got %d", queueStmt.Count)
	}
	if queueStmt.File != "files" {
		t.Errorf("Expected pattern 'files', got %s", queueStmt.File)
	}
}

// TestQueueItemListSplit pins how a parenthesised item list is split. Every
// expectation here was measured against HTCondor's own submit parser with the
// differential harness in fuzz/submit, not read off this package's code.
//
// The shape of the rule is not the obvious one: whitespace separates items
// just as a comma does, so a list never produces an item with two fields;
// the list runs to the LAST ')' on the line, which leaves any earlier ')' as
// an ordinary character inside an item; and quotes mean nothing at all.
func TestQueueItemListSplit(t *testing.T) {
	tests := []struct {
		name  string
		input string
		vars  []string
		count int
		items []string
	}{
		{
			name:  "whitespace separates items",
			input: "queue in (a b)",
			vars:  []string{"Item"},
			items: []string{"a", "b"},
		},
		{
			name:  "comma separates items",
			input: "queue in (a, b)",
			vars:  []string{"Item"},
			items: []string{"a", "b"},
		},
		{
			name:  "whitespace and comma both separate, so no item has two fields",
			input: "queue in (a b, c d)",
			vars:  []string{"Item"},
			items: []string{"a", "b", "c", "d"},
		},
		{
			name:  "runs of separators collapse",
			input: "queue in (a,b , c)",
			vars:  []string{"Item"},
			items: []string{"a", "b", "c"},
		},
		{
			name:  "a tab separates",
			input: "queue in (a\tb)",
			vars:  []string{"Item"},
			items: []string{"a", "b"},
		},
		{
			name:  "a trailing separator adds no item",
			input: "queue in (a b,)",
			vars:  []string{"Item"},
			items: []string{"a", "b"},
		},
		{
			name:  "a leading separator adds no item",
			input: "queue in (,a)",
			vars:  []string{"Item"},
			items: []string{"a"},
		},
		{
			name:  "quotes are not special",
			input: `queue in ("a b" c)`,
			vars:  []string{"Item"},
			items: []string{`"a`, `b"`, "c"},
		},
		{
			name:  "a loop variable does not change the split",
			input: "queue name in (alice bob)",
			vars:  []string{"name"},
			items: []string{"alice", "bob"},
		},
		{
			name:  "several loop variables do not change the split either",
			input: "queue x, y in (1 2, 3 4)",
			vars:  []string{"x", "y"},
			items: []string{"1", "2", "3", "4"},
		},
		{
			name:  "a count does not change the split",
			input: "queue 2 in (a b)",
			vars:  []string{"Item"},
			count: 2,
			items: []string{"a", "b"},
		},
		{
			name:  "no space is needed after the keyword",
			input: "queue in(a b)",
			vars:  []string{"Item"},
			items: []string{"a", "b"},
		},
		{
			name:  "the list ends at the last ')', so an earlier one is an item",
			input: "queue in(A  ))",
			vars:  []string{"Item"},
			items: []string{"A", ")"},
		},
		{
			name:  "a ')' with separators around it is its own item",
			input: "queue in (a ) b)",
			vars:  []string{"Item"},
			items: []string{"a", ")", "b"},
		},
		{
			name:  "a ')' with no separator before it stays inside its item",
			input: "queue in (a) b)",
			vars:  []string{"Item"},
			items: []string{"a)", "b"},
		},
		{
			name:  "only the final ')' ends the list",
			input: "queue in (a b))",
			vars:  []string{"Item"},
			items: []string{"a", "b)"},
		},
		{
			name:  "a multi-line 'in' list splits every line",
			input: "queue x in (\na b\n\n# comment\nc d\n)",
			vars:  []string{"x"},
			items: []string{"a", "b", "c", "d"},
		},
		{
			name:  "a 'from' list takes each line whole",
			input: "queue x from (\na b\nc\n)",
			vars:  []string{"x"},
			items: []string{"a b", "c"},
		},
		{
			name:  "a single-line 'from' list is one item",
			input: "queue from (a b)",
			vars:  []string{"Item"},
			items: []string{"a b"},
		},
		{
			name:  "a 'from' list keeps blank lines as empty items",
			input: "queue from (\nx\n\ny\n)",
			vars:  []string{"Item"},
			items: []string{"x", "", "y"},
		},
		{
			name:  "a count and loop variables with an inline 'from' list",
			input: "queue 2 x, y from (\n1 2\n3 4\n)",
			vars:  []string{"x", "y"},
			count: 2,
			items: []string{"1 2", "3 4"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmts, err := parseQueueStatements("\n" + tc.input + "\n")
			if err != nil {
				t.Fatalf("Failed to parse %q: %v", tc.input, err)
			}
			if len(stmts) != 1 {
				t.Fatalf("Expected 1 statement from %q, got %d", tc.input, len(stmts))
			}
			q, ok := stmts[0].(*QueueStatement)
			if !ok {
				t.Fatalf("Expected a queue statement, got %T", stmts[0])
			}
			if !slices.Equal(q.VarNames, tc.vars) {
				t.Errorf("vars: expected %v, got %v", tc.vars, q.VarNames)
			}
			if q.Count != tc.count {
				t.Errorf("count: expected %d, got %d", tc.count, q.Count)
			}
			if !slices.Equal(q.Items, tc.items) {
				t.Errorf("items: expected %q, got %q", tc.items, q.Items)
			}
		})
	}
}

// TestQueueItemListUnterminated covers the lists HTCondor rejects. A list
// whose first line does not end in ')' continues onto following lines, so one
// that never reaches a line beginning with ')' runs to end of file -- and so
// does `queue in ((a) b)`, whose body still begins with '(' after the outer
// pair is stripped.
func TestQueueItemListUnterminated(t *testing.T) {
	for _, input := range []string{
		"queue in (a b",
		"queue in (a b) c",
		"queue in ((a) b)",
		"queue from (\nx\ny\n",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseQueueStatementsStrict("\n" + input + "\n"); err == nil {
				t.Errorf("expected %q to be rejected", input)
			}
		})
	}
}
