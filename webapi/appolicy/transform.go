package appolicy

import (
	"fmt"
	"strings"
)

// TransformSummary is what one JOB_TRANSFORM_<Name> does to a job, as far
// as can be said without running it: which jobs it applies to, and which
// attributes it touches. The values it writes are not reported -- they
// are often built from macros, and the transform text can carry anything.
type TransformSummary struct {
	// OK is false when the text could not be summarized; Reason says why.
	OK     bool
	Reason string
	// Requirements is the REQUIREMENTS expression, "" for every job.
	Requirements string
	// Universe is the UNIVERSE restriction, "" for every universe.
	Universe string
	// The attributes each command touches, in order of appearance. A COPY
	// or RENAME is "from -> to"; a regex operand keeps its slashes.
	Set, Default, EvalSet, Copy, Rename, Delete []string
	// Conditional is true when some of those commands sit inside an
	// if/else, so they apply to only some of the matching jobs.
	Conditional bool
}

// SummarizeTransform reads a transform the way the schedd's transform
// language does (condor_utils/xform_utils.cpp, docs/classads/transforms):
// one statement per line -- a command keyword and its arguments, a macro
// assignment, or an if/elif/else/endif -- with REQUIREMENTS, UNIVERSE and
// NAME as envelope statements.
//
// It does not guess. A line that is none of those makes the whole
// transform "could not summarize": a list of attributes with one missing
// is worse than no list, because it reads as complete.
func SummarizeTransform(text string) TransformSummary {
	text = strings.TrimSpace(text)
	if text == "" {
		return TransformSummary{Reason: "it is empty"}
	}
	if strings.HasPrefix(text, "[") {
		// The schedd's own loader refuses this form outright
		// (job_transforms.cpp: "ClassAd format, which is no longer
		// supported. Ignoring.").
		return TransformSummary{Reason: "it is written in the old ClassAd ([ ... ]) form, which current schedds ignore"}
	}

	var s TransformSummary
	depth := 0
	hereTag := ""
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if hereTag != "" {
			if line == hereTag {
				hereTag = ""
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		word, rest := splitWord(line)
		lower := strings.ToLower(word)

		switch lower {
		case "if":
			depth++
			continue
		case "elif", "else":
			continue
		case "endif":
			if depth > 0 {
				depth--
			}
			continue
		}
		if isDirective(line, "error") || isDirective(line, "warning") {
			// "error : text" stops the transform, "warning : text"
			// annotates it; neither touches an attribute.
			continue
		}
		if tag, ok := hereDocTag(line); ok {
			// name @=tag ... @tag: a multi-line macro assignment.
			hereTag = tag
			continue
		}
		if isAssignment(line) {
			continue
		}

		if !s.command(lower, rest, depth > 0) {
			return TransformSummary{Reason: fmt.Sprintf("line %d (%q) is not a transform statement", i+1, truncate(line, 60))}
		}
	}
	s.OK = true
	return s
}

// command records one command line. False means the keyword is not one
// the transform language has, or it is missing its arguments.
func (s *TransformSummary) command(keyword, rest string, conditional bool) bool {
	rest = strings.TrimSpace(rest)
	switch keyword {
	case "requirements":
		if rest == "" {
			return false
		}
		s.Requirements = rest
		return true
	case "universe":
		s.Universe = rest
		return rest != ""
	case "name", "transform":
		return true
	case "evalmacro":
		// Sets a temporary macro, not an attribute.
		return rest != ""
	}

	first, after := splitWord(rest)
	first = strings.TrimRight(first, ",=")
	if first == "" {
		return false
	}
	second, _ := splitWord(strings.TrimLeft(strings.TrimSpace(after), ",="))
	switch keyword {
	case "set":
		s.Set = append(s.Set, first)
	case "default":
		s.Default = append(s.Default, first)
	case "evalset":
		s.EvalSet = append(s.EvalSet, first)
	case "delete":
		s.Delete = append(s.Delete, first)
	case "copy", "rename":
		if second == "" {
			return false
		}
		pair := first + " -> " + second
		if keyword == "copy" {
			s.Copy = append(s.Copy, pair)
		} else {
			s.Rename = append(s.Rename, pair)
		}
	default:
		return false
	}
	if conditional {
		s.Conditional = true
	}
	return true
}

// Compact is a one-line form of the summary, for a structured value.
func (s TransformSummary) Compact() string {
	if !s.OK {
		return "could not summarize: " + s.Reason
	}
	var parts []string
	if s.Requirements != "" {
		parts = append(parts, "REQUIREMENTS "+s.Requirements)
	}
	if s.Universe != "" {
		parts = append(parts, "UNIVERSE "+s.Universe)
	}
	for _, c := range []struct {
		kw    string
		attrs []string
	}{
		{"SET", s.Set}, {"DEFAULT", s.Default}, {"EVALSET", s.EvalSet},
		{"COPY", s.Copy}, {"RENAME", s.Rename}, {"DELETE", s.Delete},
	} {
		if len(c.attrs) > 0 {
			parts = append(parts, c.kw+" "+strings.Join(c.attrs, ", "))
		}
	}
	if len(parts) == 0 {
		return "no attribute changes"
	}
	return strings.Join(parts, "; ")
}

// Prose describes the summary as sentences.
func (s TransformSummary) Prose() string {
	if !s.OK {
		return "Could not summarize: " + s.Reason + "."
	}
	var b strings.Builder
	switch {
	case s.Requirements != "" && s.Universe != "":
		fmt.Fprintf(&b, "Applies to %s-universe jobs where %s.", s.Universe, quoteExpr(s.Requirements))
	case s.Requirements != "":
		fmt.Fprintf(&b, "Applies to jobs where %s.", quoteExpr(s.Requirements))
	case s.Universe != "":
		fmt.Fprintf(&b, "Applies to every %s-universe job.", s.Universe)
	default:
		b.WriteString("Applies to every job.")
	}
	var acts []string
	add := func(verb string, attrs []string) {
		if len(attrs) > 0 {
			acts = append(acts, verb+" "+strings.Join(attrs, ", "))
		}
	}
	add("sets", s.Set)
	add("sets, where the job has no value,", s.Default)
	add("sets to a value computed at submit", s.EvalSet)
	add("copies", s.Copy)
	add("renames", s.Rename)
	add("deletes", s.Delete)
	if len(acts) == 0 {
		b.WriteString(" It changes no job attribute.")
		return b.String()
	}
	b.WriteString(" It " + strings.Join(acts, "; ") + ".")
	if s.Conditional {
		b.WriteString(" Some of these happen only under conditions inside the transform.")
	}
	return b.String()
}

// splitWord splits off the first whitespace-delimited word.
func splitWord(s string) (word, rest string) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// isAssignment reports a macro assignment, "name = value" or
// "name=value": a single word before the '='. A command such as
// "SET Foo = 1" has two words there, which is how the schedd's own parser
// tells them apart.
func isAssignment(line string) bool {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return false
	}
	name := strings.TrimSpace(line[:i])
	if name == "" || strings.ContainsAny(name, " \t") {
		return false
	}
	for _, r := range name {
		if !isMacroNameRune(r) {
			return false
		}
	}
	return true
}

// isMacroNameRune reports a character a macro name may hold, counting
// the $(...) of a name built from another macro.
func isMacroNameRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("_.$():", r)
}

// isDirective recognizes "<kw> : text".
func isDirective(line, kw string) bool {
	if len(line) <= len(kw) || !strings.EqualFold(line[:len(kw)], kw) {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(line[len(kw):]), ":")
}

// hereDocTag recognizes "name @=tag", the start of a multi-line macro
// assignment that ends at a line "@tag".
func hereDocTag(line string) (string, bool) {
	i := strings.Index(line, "@=")
	if i <= 0 || strings.ContainsAny(strings.TrimSpace(line[:i]), " \t") {
		return "", false
	}
	tag := strings.TrimSpace(line[i+2:])
	if tag == "" {
		return "", false
	}
	return "@" + tag, true
}
