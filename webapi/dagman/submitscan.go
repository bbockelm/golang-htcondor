package dagman

import (
	"bufio"
	"strings"
)

// This is a deliberately shallow reader of submit descriptions. It exists
// to answer one question -- which files does this node need staged with
// the DAG -- and it is wrong to grow it into a second condor_submit.
//
// It reads literal values only. A value containing a macro reference is
// reported as unresolvable rather than guessed at: VARS can supply a
// different value per node, and a wrong guess here would either demand a
// file that is never used or, worse, quietly approve a workflow that is
// missing one.

// submitValues returns the values assigned to key, split as a submit file
// splits a file list. A value that depends on a macro is dropped.
func submitValues(body, key string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 8*1024), 1024*1024)
	for sc.Scan() {
		k, v, ok := submitAssignment(sc.Text())
		if !ok || !strings.EqualFold(k, key) {
			continue
		}
		for _, f := range strings.Split(v, ",") {
			f = strings.TrimSpace(f)
			f = strings.Trim(f, `"`)
			if f == "" || strings.Contains(f, "$(") {
				continue
			}
			out = append(out, f)
		}
	}
	return out
}

// submitString returns the last literal value assigned to key, or "".
// Last wins, because a submit file is a sequence of macro assignments and
// the one in force at `queue` is the last one written.
func submitString(body, key string) string {
	out := ""
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 8*1024), 1024*1024)
	for sc.Scan() {
		k, v, ok := submitAssignment(sc.Text())
		if !ok || !strings.EqualFold(k, key) {
			continue
		}
		out = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return out
}

// submitBool reads a submit-file boolean, returning def when the key is
// absent or not a recognizable boolean.
func submitBool(body, key string, def bool) bool {
	v := submitString(body, key)
	switch strings.ToLower(v) {
	case "true", "yes", "t", "1":
		return true
	case "false", "no", "f", "0":
		return false
	}
	return def
}

// submitInputFiles is every file a node needs staged alongside the DAG:
// its declared inputs, its stdin, and its executable when that is a
// relative path being transferred.
//
// Node jobs run with Iwd set to the DAG's own spool directory, so these
// have to be in the DAG's spool -- not the node's, which does not exist
// as a separate thing. Missing this is the classic way a DAG that submits
// cleanly fails on its first node.
func submitInputFiles(body string) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(f string) {
		if f == "" || seen[f] {
			return
		}
		seen[f] = true
		out = append(out, f)
	}
	for _, f := range submitValues(body, "transfer_input_files") {
		add(f)
	}
	if in := submitString(body, "input"); in != "" && !strings.Contains(in, "$(") {
		add(in)
	}
	// The executable is transferred by default, but only a relative path
	// is ours to stage: an absolute one names a binary on the machine that
	// runs the job.
	if exe := submitString(body, "executable"); exe != "" &&
		!strings.Contains(exe, "$(") &&
		!strings.HasPrefix(exe, "/") &&
		submitBool(body, "transfer_executable", true) {
		add(exe)
	}
	return out
}

// submitAssignment splits one submit-file line into key and value.
// Returns ok=false for comments, blanks, and anything that is not an
// assignment (a bare `queue`, most obviously).
func submitAssignment(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	i := strings.IndexAny(line, "=")
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])
	// Submit files allow `key = value` and `key=value`; they do not allow
	// whitespace inside a key, so a "key" with a space in it means this
	// line was something else (an expression, a queue statement).
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, value, true
}
