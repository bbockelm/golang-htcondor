package config

// Selective macro expansion, ported from HTCondor's config.cpp: the
// selective_expand_macro overload that takes a set of knob names to leave
// alone, and the SkipKnobsBody callback that drives it.
//
// It exists for one caller: the submit digest a late-materialization
// submission sends to the schedd. The digest is the submit file with
// everything the submitting client can settle already settled, and everything
// that varies per proc -- $(Process), $(Item), a queue statement's loop
// variables -- left as a macro reference for the schedd to expand when it
// materializes each job. Expanding those here would bake the first proc's
// values into every job the factory makes.

import (
	"errors"
	"strings"
)

// SelectiveExpand expands the macro references in value whose names skip
// rejects, leaving the rest written as they are.
//
// skip is called with a reference's knob name: the body of $(NAME) up to its
// ':' default, or the first argument of a macro function such as
// $BASENAME(NAME). Returning true leaves that reference in place. $(DOLLAR)
// is always left in place, and $ENV() and $RANDOM_INTEGER() are always
// evaluated, as HTCondor's SkipKnobsBody does.
//
// The second return value counts the references left in place. Only whether
// it is zero is meaningful: a reference the scan passes over more than once,
// which happens when an expansion earlier in the value makes the scan restart,
// is counted each time. HTCondor's own count has the same property and its
// one caller asks only whether anything was skipped.
//
// A reference whose evaluation fails is left in place and counted rather than
// failing the call, because the usual reason is that evaluating it would have
// needed one of the names skip is protecting. Only a non-terminating expansion
// (ErrMacroLoop) is reported as an error.
func (c *Config) SelectiveExpand(value string, skip func(name string) bool) (string, int, error) {
	e := &expander{c: c}
	return e.selectiveExpand(value, skip)
}

// knobName is the name selective expansion matches a reference by: the body
// up to the ':' of a $(NAME:default), or up to the first ',' of a macro
// function's argument list.
func knobName(id int, body string) string {
	sep := byte(',')
	if id == macroNormal {
		sep = ':'
	}
	if i := strings.IndexByte(body, sep); i >= 0 {
		return body[:i]
	}
	return body
}

//nolint:gocyclo // ported as one function, as in config.cpp
func (e *expander) selectiveExpand(value string, skip func(string) bool) (string, int, error) {
	pending := 0

	// reject is next_config_macro's body check: true means "not this one,
	// keep searching", which is how a reference is left in place.
	reject := func(id int, body string) bool {
		if isDollarBody(id, body) {
			pending++
			return true
		}
		switch id {
		case macroENV, macroRandomInteger:
			return false
		case macroNormal:
			if skip(knobName(id, body)) {
				pending++
				return true
			}
			return false
		}
		if id > macroNone && skip(knobName(id, body)) {
			pending++
			return true
		}
		return false
	}

	tmp := value
	// from is where the next search starts. A reference left in place is
	// stepped over; the text a substitution produces is searched again, so
	// a macro that expands to another macro still expands.
	from := 0
	for from <= len(tmp) {
		pos := nextConfigMacro(tmp[from:], isConfigMacro, reject)
		if err := e.charge(pos); err != nil {
			return "", pending, err
		}
		if pos.id == macroNone {
			break
		}
		dollar, bodyStart, bodyEnd := from+pos.dollar, from+pos.bodyStart, from+pos.bodyEnd
		body := tmp[bodyStart:bodyEnd]

		// A macro function whose first argument names a knob that itself
		// still holds a protected reference cannot be evaluated either: the
		// answer would depend on a value the schedd has not filled in yet.
		if pos.id > macroRandomInteger && !e.canEvaluate(pos.id, body, skip, &pending) {
			from = bodyEnd + 1
			continue
		}

		tv, err := e.evaluate(tmp[dollar+1:bodyStart-1], pos.id, body)
		if err != nil {
			if errors.Is(err, ErrMacroLoop) {
				return "", pending, err
			}
			// HTCondor assumes a failed evaluation is selective expansion's
			// doing and steps over the reference rather than aborting.
			if pos.id != macroENV {
				pending++
			}
			from = bodyEnd + 1
			continue
		}
		tmp = tmp[:dollar] + tv + tmp[bodyEnd+1:]
		from = dollar
		if err := e.step(len(tmp)); err != nil {
			return "", pending, err
		}
	}
	return tmp, pending, nil
}

// canEvaluate reports whether a macro function's arguments are settled enough
// to evaluate it (ConfigMacroSkipCount::can_evaluate). It is false when the
// knob the function reads still holds a reference skip is protecting.
func (e *expander) canEvaluate(id int, body string, skip func(string) bool, pending *int) bool {
	check := func(index int) bool {
		name, ok := nthListItem(body, ',', index)
		if !ok {
			return true
		}
		raw, found := e.c.lookupMacro(name)
		if !found {
			return true
		}
		_, skipped, err := e.selectiveExpand(raw, skip)
		if err != nil || skipped > 0 {
			*pending++
			return false
		}
		return true
	}
	if !check(0) {
		return false
	}
	// $CHOICE(INDEX,LIST) with exactly two arguments reads the second as a
	// knob name too; with more, the arguments are the list itself.
	if id == macroChoice {
		if _, more := nthListItem(body, ',', 2); !more {
			if _, ok := nthListItem(body, ',', 1); ok && !check(1) {
				return false
			}
		}
	}
	return true
}
