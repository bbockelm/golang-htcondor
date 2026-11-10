// Copyright (c) 2025, Brian Bockelman
// SPDX-License-Identifier: Apache-2.0

package htcondor

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// Automatic memory retry: what a job carries so that being evicted for
// using more memory than it asked for leads to a larger request rather
// than a hold.
//
// The job does not carry a policy expression for this. It carries a job
// TRANSFORM, as text, in TransformBody_RequestMemory, plus the name
// RequestMemory in TransformOnEvict to say that the transform is the one
// to run when the job is vacated. The transform's own REQUIREMENTS line
// is what limits it to the vacate reason that means "over memory": the
// schedd runs the body only when the job came back with
// VacateReasonSubCode 102.
//
// Without any of this a job held for exceeding its memory request is
// never retried with a larger one, which is the whole feature. The three
// submit commands that ask for it -- retry_request_memory,
// retry_request_memory_max and retry_request_memory_increase -- all land
// in setBuiltInOnEvictCheck below, which is
// SubmitHash::SetBuiltInOnEvictCheck.

// Attribute and submit-command names for the on-evict transform.
const (
	attrTransformOnEvict     = "TransformOnEvict"
	attrTransformBodyPrefix  = "TransformBody_"
	attrRequestMemory        = "RequestMemory"
	commandRequestMemory     = "request_memory"
	commandRetryMemory       = "retry_request_memory"
	commandRetryMemoryMax    = "retry_request_memory_max"
	commandRetryMemoryIncrBy = "retry_request_memory_increase"
)

// onEvictBodySeparator separates the lines of a transform body. The body
// is stored as one job attribute, and the job queue log is line
// oriented, so the lines are joined with RS (0x1e) rather than newlines.
const onEvictBodySeparator = "\x1e"

// memoryOverRequestRequirements is the REQUIREMENTS line of the memory
// transform: the vacate reasons the startd and the starter use when they
// take a job away, narrowed by the sub-code that means the job went over
// its memory request. Without this clause the transform would raise the
// request after every eviction, including a drained machine or a
// preempting job.
const memoryOverRequestRequirements = "(VacateReasonCode==21 || VacateReasonCode == 34) && VacateReasonSubCode == 102"

// setRequestMemory stores RequestMemory and, when the value is a plain
// size, whatever automatic retry the submit file asked for.
//
// The retry commands are read here rather than beside the other submit
// commands because condor_submit reads them here: they are reachable
// only when request_memory is a size it could parse. An expression --
// `request_memory = MY.VM_Memory`, `request_memory = ifThenElse(...)` --
// takes the whole family out of play, since the transform has no number
// to grow from.
func (sf *SubmitFile) setRequestMemory(ad *classad.ClassAd, raw string) error {
	mb, rest, ok := splitLeadingSize(raw, unitMiB)
	if !ok {
		return setRequestSize(ad, attrRequestMemory, raw, unitMiB)
	}
	_ = ad.Set(attrRequestMemory, mb)

	// `request_memory = 128, 2048` is the short spelling: the second
	// value is the request to retry with, and it supersedes the
	// retry_request_memory commands because condor_submit never looks at
	// them in that case.
	if rest != "" {
		return sf.setBuiltInOnEvictCheck(ad, attrRequestMemory, commandRequestMemory, unitMiB, rest, "")
	}

	// submit_param treats a command whose value expands to nothing as
	// unset, so `retry_request_memory =` leaves the family alone instead
	// of asking for a retry to an empty value.
	value := func(key string) string {
		v, ok := sf.submitCommand(key)
		if !ok {
			return ""
		}
		return strings.TrimSpace(v)
	}

	list := value(commandRetryMemory)
	maxValue := value(commandRetryMemoryMax)
	increase := value(commandRetryMemoryIncrBy)

	switch {
	case list != "":
		// The list form supersedes the other two. condor_submit warns
		// that retry_request_memory_increase is ignored here; the Go
		// parser has nowhere to put a warning, so it is silently
		// ignored, as it is on the C++ side once the warning is read.
		return sf.setBuiltInOnEvictCheck(ad, attrRequestMemory, commandRetryMemory, unitMiB, list, "")
	case maxValue != "" || increase != "":
		return sf.setBuiltInOnEvictCheck(ad, attrRequestMemory, commandRetryMemoryMax, unitMiB, maxValue, increase)
	}
	return nil
}

// setBuiltInOnEvictCheck builds the on-evict transform for one resource
// request, following SubmitHash::SetBuiltInOnEvictCheck.
//
// line is the sequence of values the job should retry with, the last of
// which may be an expression; increase is a separate increment to apply
// on each retry. Either may be empty. The three shapes they make are:
//
//   - a sequence of two or more values. The values go into
//     Retry<attr> as a list and the transform walks it with an index,
//     stopping at the last entry.
//   - an increment with a ceiling. Next<attr> is an expression OVER
//     <attr>, so it grows with each retry, and Max<attr> caps it:
//     the transform is EVALSET <attr> MIN({Next<attr>, Max<attr>}).
//   - a single value, or an increment with no ceiling. There is nothing
//     to grow, so the transform sets one value and the job retries at
//     that size however many times it is evicted.
//
// Only the first two keep anything on the job ad. Everything else lives
// in the transform body, which is text the schedd runs later.
func (sf *SubmitFile) setBuiltInOnEvictCheck(ad *classad.ClassAd, attr, command string, base int64, line, increase string) error {
	seq, tail := parseSizeSequence(line, base)

	// The tail is whatever followed the numbers: an expression, which
	// the schedd evaluates at retry time rather than condor_submit at
	// submit time.
	var tailExpr *classad.Expr
	if tail != "" {
		e, err := classad.ParseExpr(tail)
		if err != nil {
			return fmt.Errorf("%s = %s is invalid, must be an expression or number", command, tail)
		}
		tailExpr = e
	}

	// A sequence that does not grow would make the job retry at a size
	// it has already been evicted for.
	if len(seq) > 1 {
		prev := int64(0)
		for _, v := range seq {
			if v <= prev {
				return fmt.Errorf("%s must have an increasing sequence of values, but %d is not greater than %d", command, v, prev)
			}
			prev = v
		}
	}

	// The final value of the sequence is the ceiling. It is held apart
	// from the rest because the shapes below use it differently.
	var ceiling string
	haveCeiling, ceilingIsExpr := false, false
	switch {
	case tailExpr != nil:
		ceiling, haveCeiling, ceilingIsExpr = unparseReference(tailExpr), true, true
	case len(seq) > 0:
		ceiling, haveCeiling = strconv.FormatInt(seq[len(seq)-1], 10), true
		seq = seq[:len(seq)-1]
	case increase == "":
		// No values and no increment: nothing was asked for.
		return nil
	}

	var body string
	switch {
	case len(seq) > 0:
		items := make([]string, 0, len(seq)+1)
		for _, n := range seq {
			items = append(items, strconv.FormatInt(n, 10))
		}
		items = append(items, ceiling)

		retryAttr := "Retry" + attr
		indexAttr := retryAttr + "Index"
		if err := setExprAttr(ad, retryAttr, command, "{"+strings.Join(items, ",")+"}"); err != nil {
			return err
		}
		// The index attribute is deliberately NOT set here: it is
		// absent until the first retry, and the `?:0` in the body is
		// what reads an absent index as the first entry.
		body = fmt.Sprintf("EVALSET %s %s[%s?:0]%sEVALSET %s MIN({size(%s)-1, (%s?:0)+1})",
			attr, retryAttr, indexAttr, onEvictBodySeparator, indexAttr, retryAttr, indexAttr)

	case increase != "":
		step, err := retryIncrement(attr, base, increase)
		if err != nil {
			return err
		}
		if haveCeiling {
			if err := setExprAttr(ad, "Max"+attr, command, ceiling); err != nil {
				return err
			}
			if err := setExprAttr(ad, "Next"+attr, command, step); err != nil {
				return err
			}
			body = fmt.Sprintf("EVALSET %s MIN({Next%s, Max%s})", attr, attr, attr)
		} else {
			// No ceiling, so there is nothing to stop the expression
			// growing without bound and no reason to keep it as one:
			// condor_submit evaluates it once, against the request the
			// job starts with, and stores the single number.
			scratch := classad.New()
			if n, ok := ad.EvaluateAttrInt(attr); ok {
				_ = scratch.Set(attr, n)
			}
			if err := setExprAttr(scratch, "Increment", command, step); err != nil {
				return err
			}
			n, ok := scratch.EvaluateAttrInt("Increment")
			if !ok {
				return fmt.Errorf("%s retry increment (%s) must evaluate to an integer at submit time", attr, increase)
			}
			body = fmt.Sprintf("SET %s %d", attr, n)
		}

	default:
		// A single value. SET stores it as written; EVALSET makes the
		// schedd evaluate the expression when the retry happens, which
		// is the point of allowing one.
		verb := "SET"
		if ceilingIsExpr {
			verb = "EVALSET"
		}
		body = fmt.Sprintf("%s %s %s", verb, attr, ceiling)
	}

	requirements := memoryOverRequestRequirements
	if v, ok := sf.param("ON_EVICT_CHECK_" + attr + "_REQUIREMENTS"); ok && strings.TrimSpace(v) != "" {
		requirements = v
	}
	_ = ad.Set(attrTransformBodyPrefix+attr, "REQUIREMENTS "+requirements+onEvictBodySeparator+body)

	addTransformOnEvict(ad, attr)
	return nil
}

// retryIncrement turns retry_request_memory_increase into the expression
// stored as Next<attr>.
//
// A size ("128", "1G") is an amount to ADD, so it becomes `<attr> + n`
// -- an expression over the request, which is what makes each retry
// larger than the last. Anything else has to reference <attr> itself for
// the same reason; an increment that does not, like `MemoryUsage * 2`,
// would hand every retry the same value and is rejected rather than
// quietly turned into a fixed request.
func retryIncrement(attr string, base int64, increase string) (string, error) {
	notAnIncrement := fmt.Errorf("%s retry increment must be a positive number or an expression that references %s", attr, attr)

	if n, ok := parseSizeWithUnits(increase, base); ok {
		if n <= 0 {
			return "", notAnIncrement
		}
		return fmt.Sprintf("%s + %d", attr, n), nil
	}

	expr, err := classad.ParseExpr(increase)
	if err != nil {
		return "", notAnIncrement
	}
	scratch := classad.New()
	_ = scratch.Set(attr, int64(0))
	if len(scratch.InternalRefs(expr)) == 0 {
		return "", notAnIncrement
	}
	return increase, nil
}

// addTransformOnEvict names attr in TransformOnEvict, which is the list
// of transform bodies the schedd runs when the job is vacated. A body
// nothing names is never run.
func addTransformOnEvict(ad *classad.ClassAd, attr string) {
	list, _ := ad.EvaluateAttrString(attrTransformOnEvict)
	for _, name := range strings.Fields(strings.ReplaceAll(list, ",", " ")) {
		if strings.EqualFold(name, attr) {
			return
		}
	}
	if list != "" {
		list += " "
	}
	_ = ad.Set(attrTransformOnEvict, list+attr)
}

// splitLeadingSize reads one size off the front of a submit value and
// returns whatever followed the comma after it. ok is false when the
// value does not start with a size at all, which is how an expression is
// told apart from a number.
func splitLeadingSize(value string, base int64) (n int64, rest string, ok bool) {
	head := value
	if comma := strings.IndexByte(value, ','); comma >= 0 {
		head, rest = value[:comma], value[comma+1:]
	}
	n, ok = parseSizeWithUnits(head, base)
	if !ok {
		return 0, "", false
	}
	return n, rest, true
}

// parseSizeSequence splits a comma-separated list of sizes into the
// numbers at the front and whatever text is left, which is an expression
// when it is not empty. `128, 256, MAX({RequestMemory, MemoryUsage})`
// gives [128 256] and the MAX call.
//
// A comma inside that trailing expression is not a separator: the split
// stops at the first item that is not a size, so the rest of the line is
// handed over whole.
func parseSizeSequence(line string, base int64) (seq []int64, rest string) {
	p := line
	for p != "" {
		n, tail, ok := splitLeadingSize(p, base)
		if !ok {
			break
		}
		seq = append(seq, n)
		p = tail
	}
	return seq, strings.TrimSpace(p)
}

// unparseReference renders an expression the way HTCondor's own
// unparser does (ExprTreeToString), which is not how Go's
// Expr.String() renders it: `2 * 1024` rather than `(2 * 1024)`,
// `MAX({ a,b })` rather than `MAX({a, b})`.
//
// It matters because the transform body is TEXT inside a job attribute.
// An expression stored as an expression would compare equal either way,
// but one the schedd re-parses out of a string has to be spelled the way
// condor_submit spells it.
func unparseReference(expr *classad.Expr) string {
	scratch := classad.New()
	scratch.InsertExpr("X", expr)
	return strings.TrimPrefix(scratch.MarshalOld(), "X = ")
}
