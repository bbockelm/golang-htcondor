package htcondor

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbockelm/golang-htcondor/config"
)

// simpleIterator implements SubmitIterator for simple queue statements
type simpleIterator struct {
	count   int
	current int
}

func newSimpleIterator(count int) *simpleIterator {
	if count <= 0 {
		count = 1
	}
	return &simpleIterator{count: count}
}

func (s *simpleIterator) Next() bool {
	if s.current < s.count {
		s.current++
		return true
	}
	return false
}

func (s *simpleIterator) Values() map[string]string {
	return map[string]string{
		"ItemIndex": fmt.Sprintf("%d", s.current-1),
	}
}

func (s *simpleIterator) Count() int {
	return s.count
}

// listIterator implements SubmitIterator for "queue in (list)" statements
type listIterator struct {
	varNames []string
	items    []string
	count    int
	current  int
	itemIdx  int
	started  bool
}

func newListIterator(varNames []string, items []string, count int) *listIterator {
	if count <= 0 {
		count = 1
	}
	if len(varNames) == 0 {
		varNames = []string{"ITEM"}
	}
	return &listIterator{
		varNames: varNames,
		items:    items,
		count:    count,
		itemIdx:  -1, // Start at -1 so first Next() moves to 0
		current:  -1,
	}
}

func (l *listIterator) Next() bool {
	// For "queue N var in (items)", we queue N jobs per item
	if !l.started {
		l.started = true
		l.current = 0
		l.itemIdx = 0
		return l.itemIdx < len(l.items)
	}

	l.current++
	if l.current >= l.count {
		l.current = 0
		l.itemIdx++
	}

	return l.itemIdx < len(l.items)
}

func (l *listIterator) Values() map[string]string {
	if l.itemIdx >= len(l.items) {
		return map[string]string{}
	}

	values := map[string]string{
		"ItemIndex": fmt.Sprintf("%d", l.itemIdx),
		"Step":      fmt.Sprintf("%d", l.current),
	}

	// Set the variable(s) to the current item
	item := l.items[l.itemIdx]
	if len(l.varNames) == 1 {
		values[l.varNames[0]] = item
	} else {
		// Split item by whitespace for multiple variables
		parts := strings.Fields(item)
		for i, varName := range l.varNames {
			if i < len(parts) {
				values[varName] = parts[i]
			} else {
				values[varName] = ""
			}
		}
	}

	return values
}

func (l *listIterator) Count() int {
	return len(l.items) * l.count
}

// fileIterator implements SubmitIterator for "queue from file" statements
type fileIterator struct {
	varNames []string
	lines    []string
	count    int
	current  int
	lineIdx  int
	started  bool
}

func newFileIterator(varNames []string, filename string, count int) (*fileIterator, error) {
	if count <= 0 {
		count = 1
	}
	if len(varNames) == 0 {
		varNames = []string{"ITEM"}
	}

	// Read lines from file
	//nolint:gosec // G304: Queue file path comes from user submit description
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open queue file %q: %w", filename, err)
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading queue file %q: %w", filename, err)
	}

	return &fileIterator{
		varNames: varNames,
		lines:    lines,
		count:    count,
		lineIdx:  -1, // Start at -1 so first Next() moves to 0
		current:  -1,
	}, nil
}

func (f *fileIterator) Next() bool {
	// For "queue N var from file", we queue N jobs per line
	if !f.started {
		f.started = true
		f.current = 0
		f.lineIdx = 0
		return f.lineIdx < len(f.lines)
	}

	f.current++
	if f.current >= f.count {
		f.current = 0
		f.lineIdx++
	}

	return f.lineIdx < len(f.lines)
}

func (f *fileIterator) Values() map[string]string {
	if f.lineIdx >= len(f.lines) {
		return map[string]string{}
	}

	values := map[string]string{
		"ItemIndex": fmt.Sprintf("%d", f.lineIdx),
		"Step":      fmt.Sprintf("%d", f.current),
		"Row":       fmt.Sprintf("%d", f.lineIdx),
	}

	// Parse line into variable values
	line := f.lines[f.lineIdx]

	if len(f.varNames) == 1 {
		values[f.varNames[0]] = line
	} else {
		// Split by comma or whitespace
		var parts []string
		if strings.Contains(line, ",") {
			parts = strings.Split(line, ",")
		} else {
			parts = strings.Fields(line)
		}

		// Trim whitespace from each part
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}

		// Assign to variables
		for i, varName := range f.varNames {
			if i < len(parts) {
				values[varName] = parts[i]
			} else {
				values[varName] = ""
			}
		}
	}

	return values
}

func (f *fileIterator) Count() int {
	return len(f.lines) * f.count
}

// matchingIterator implements SubmitIterator for "queue matching pattern" statements
type matchingIterator struct {
	varNames []string
	files    []string
	count    int
	current  int
	fileIdx  int
	started  bool
}

func newMatchingIterator(varNames []string, pattern string, count int) (*matchingIterator, error) {
	if count <= 0 {
		count = 1
	}
	if len(varNames) == 0 {
		varNames = []string{"ITEM"}
	}

	// Use glob to match files
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
	}

	// If no matches, that's ok - we just won't queue any jobs
	return &matchingIterator{
		varNames: varNames,
		files:    matches,
		count:    count,
		fileIdx:  -1, // Start at -1 so first Next() moves to 0
		current:  -1,
	}, nil
}

func (m *matchingIterator) Next() bool {
	// For "queue N matching pattern", we queue N jobs per matched file
	if !m.started {
		m.started = true
		m.current = 0
		m.fileIdx = 0
		return m.fileIdx < len(m.files)
	}

	m.current++
	if m.current >= m.count {
		m.current = 0
		m.fileIdx++
	}

	return m.fileIdx < len(m.files)
}

func (m *matchingIterator) Values() map[string]string {
	if m.fileIdx >= len(m.files) {
		return map[string]string{}
	}

	values := map[string]string{
		"ItemIndex": fmt.Sprintf("%d", m.fileIdx),
		"Step":      fmt.Sprintf("%d", m.current),
	}

	// Set variable to matched filename
	filename := m.files[m.fileIdx]
	if len(m.varNames) == 1 {
		values[m.varNames[0]] = filename
	} else {
		// For matching with multiple variables, just use the filename for the first
		values[m.varNames[0]] = filename
		for i := 1; i < len(m.varNames); i++ {
			values[m.varNames[i]] = ""
		}
	}

	return values
}

func (m *matchingIterator) Count() int {
	return len(m.files) * m.count
}

// queueFileAccess says which local paths a queue statement may read.
// An itemdata file or a `matching` glob reads the filesystem of
// whatever process is parsing, which is not the submitter when the
// submit file arrived over an API — so the default is nothing, plus the
// temp files ParseSubmitFile wrote itself for the inline
// `from ((rows))` form.
type queueFileAccess struct {
	allowAny   bool
	allowPaths []string
}

func (a queueFileAccess) permit(path string) error {
	if a.allowAny {
		return nil
	}
	for _, allowed := range a.allowPaths {
		if allowed == path {
			return nil
		}
	}
	return fmt.Errorf("queue statement may not read %q: this submit file is parsed without access to the local host; "+
		"use the inline form (queue vars from ((rows))) or an explicit item list instead", path)
}

// createIteratorFromQueue creates an appropriate iterator from a QueueStatement
func createIteratorFromQueue(qs *config.QueueStatement, access queueFileAccess) (SubmitIterator, error) {
	count := qs.Count
	if count == 0 {
		count = 1
	}

	// Determine which type of queue statement this is
	hasVars := len(qs.VarNames) > 0
	hasItems := len(qs.Items) > 0
	hasFile := qs.File != ""

	if !hasVars && !hasItems && !hasFile {
		// Simple: queue [N]
		return newSimpleIterator(count), nil
	}

	if hasItems && !hasFile {
		// List form: queue [N] var1, var2 in (item1, item2, ...)
		return newListIterator(qs.VarNames, qs.Items, count), nil
	}

	if hasFile && !hasItems {
		// Could be either "from file" or "matching pattern"
		// We distinguish by checking if VarNames is empty (matching) or not (from)
		// Actually, both can have VarNames. The distinction is in how the parser
		// set up the QueueStatement. For "matching", File contains the pattern.
		// For "from", File contains the filename.

		if err := access.permit(qs.File); err != nil {
			return nil, err
		}

		// Let's check if the File looks like a glob pattern
		if strings.ContainsAny(qs.File, "*?[]") {
			// Matching form: queue [N] [var] matching pattern
			return newMatchingIterator(qs.VarNames, qs.File, count)
		}

		// From file form: queue [N] var1, var2 from filename
		return newFileIterator(qs.VarNames, qs.File, count)
	}

	return nil, fmt.Errorf("invalid queue statement: cannot determine iterator type")
}
