package htcondor

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
)

// The GPU request family: the keywords that constrain WHICH GPU a job may
// run on, and the RequireGPUs expression condor_submit derives from them.
//
// This is SubmitHash::SetRequestGpus' property-constraint block plus
// SetResourceRequirements, from src/condor_utils/submit_utils.cpp, with
// the cuda_version half of SetRequirements alongside them because it is
// the same family read at the same late point.

// setGPUPropertyConstraints reads the keywords that constrain WHICH GPU a
// job may run on, which SubmitHash::SetRequestGpus reads in the same place:
// at the end of the request_gpus handling, and only when that handling put
// a RequestGPUs on the ad.
func (sf *SubmitFile) setGPUPropertyConstraints(ad *classad.ClassAd) error {
	// SubmitHash::SetRequestGpus reads none of these keywords unless the
	// job already asked for a GPU: the whole block is inside
	// `if (job->Lookup(ATTR_REQUEST_GPUS))`, so `gpus_minimum_capability`
	// in a file with no `request_gpus` -- or with `request_gpus =
	// undefined`, which assigns nothing -- sets nothing at all. A later
	// `+RequestGPUs` does not reopen it: the custom attributes are
	// applied after this pass on both sides.
	if _, wantsGPUs := ad.Lookup("RequestGpus"); !wantsGPUs {
		return nil
	}

	// Each keyword also answers to its attribute name as a second
	// spelling, which is what submit_param(key, attr) means.
	//
	// require_gpus is an EXPRESSION, not a string: these are constraints
	// on a GPU's property ad ("Capability >= 8.0"), and stored as a
	// string the startd would be comparing text to a number and would
	// match nothing.
	if v := sf.submitParam("require_gpus", "RequireGPUs"); v != "" {
		if err := setExprAttr(ad, "RequireGPUs", "require_gpus", v); err != nil {
			return err
		}
	}
	if v := sf.submitParam("gpus_minimum_capability", "GPUsMinCapability"); v != "" {
		if err := setExprAttr(ad, "GPUsMinCapability", "gpus_minimum_capability", v); err != nil {
			return err
		}
	}
	if v := sf.submitParam("gpus_maximum_capability", "GPUsMaxCapability"); v != "" {
		if err := setExprAttr(ad, "GPUsMaxCapability", "gpus_maximum_capability", v); err != nil {
			return err
		}
	}
	// A MB quantity, so a bare number is already megabytes.
	if v := sf.submitParam("gpus_minimum_memory", "GPUsMinMemory"); v != "" {
		if err := setSizeAttr(ad, "GPUsMinMemory", v, unitMiB); err != nil {
			return err
		}
	}
	if v := sf.submitParam("gpus_minimum_runtime", "GPUsMinRuntime"); v != "" {
		if err := setGPUsMinRuntime(ad, v); err != nil {
			return err
		}
	}

	return nil
}

// setGPUsMinRuntime stores gpus_minimum_runtime the way
// SubmitHash::SetRequestGpus does: a CUDA runtime version written as "x"
// or "x.y" is canonicalized to the integer x*1000 + y*10, so 12.1 becomes
// 12010 -- the form the startd advertises in a GPU's MaxSupportedVersion.
// A number that is already above 1000 with no minor part is taken to be in
// that canonical form already and kept as written.
//
// Anything else (a version with three parts, a minor part of 100 or more,
// a negative, an expression) is stored as a ClassAd expression instead,
// which is what SubmitHash falls back to.
func setGPUsMinRuntime(ad *classad.ClassAd, raw string) error {
	if major, minor, rest, ok := strIsProcID(raw); ok && rest == "" && minor >= -1 && minor < 100 {
		var ver int64
		if minor == -1 && major > 1000 {
			ver = int64(major)
		} else {
			ver = int64(major) * 1000
			if minor > 0 {
				ver += int64(minor) * 10
			}
		}
		_ = ad.Set("GPUsMinRuntime", ver)
		return nil
	}
	return setExprAttr(ad, "GPUsMinRuntime", "gpus_minimum_runtime", raw)
}

// strIsProcID is StrIsProcId() from condor_utils/proc_id.cpp, which parses
// "x" or "x.y" into a cluster and a proc. It is reused here because
// SetRequestGpus reuses it: a CUDA runtime version is written in the same
// shape as a job id, and HTCondor reads it with the same function.
//
// The cluster must be non-negative; the proc may be negative, and is -1
// when there is no second part. rest is the unparsed remainder, which the
// GPU caller requires to be empty -- StrIsProcId itself also accepts a
// trailing space or comma.
func strIsProcID(s string) (cluster, proc int, rest string, ok bool) {
	cluster, rest, got := scanInt32(s)
	if got && (rest == "" || isProcIDBreak(rest[0])) {
		// A bare number: the proc is absent, which StrIsProcId reports
		// as -1.
		return cluster, -1, rest, cluster >= 0
	}
	// strtol() leaves the end pointer at the start of the string when it
	// consumes nothing, so a leading '.' still reaches the branch below
	// with a cluster of 0: ".5" parses as 0.5, and that branch never
	// rechecks the cluster.
	if rest == "" || rest[0] != '.' {
		return cluster, -1, rest, false
	}
	rest = rest[1:]
	if rest == "" || isProcIDBreak(rest[0]) {
		// "x." parses the same as "x".
		return cluster, -1, rest, cluster >= 0
	}
	// The proc may be negative, but the sign has to be glued to the
	// digits -- strtol would otherwise accept "x. -1".
	negative := rest[0] == '-'
	digits := rest
	if negative {
		digits = digits[1:]
	}
	if digits == "" || digits[0] < '0' || digits[0] > '9' {
		return cluster, -1, digits, false
	}
	proc, rest, got = scanInt32(digits)
	if !got {
		return cluster, -1, rest, false
	}
	if negative {
		proc = -proc
	}
	return cluster, proc, rest, rest == "" || isSpaceByte(rest[0])
}

// isProcIDBreak reports the characters StrIsProcId treats as the end of a
// cluster number: whitespace or a comma.
func isProcIDBreak(c byte) bool { return isSpaceByte(c) || c == ',' }

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// scanInt32 is C's strtol() at base 10 assigned to an int, which is what
// StrIsProcId does: leading whitespace is skipped, an optional sign and a
// run of digits are consumed, and the 64-bit result is truncated to 32
// bits on the way into the variable. got is false when no digits were
// consumed, which is how strtol reports that it moved nowhere.
func scanInt32(s string) (value int, rest string, got bool) {
	i := 0
	for i < len(s) && isSpaceByte(s[i]) {
		i++
	}
	start := i
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	digits := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == digits {
		return 0, s, false
	}
	n, err := strconv.ParseInt(s[start:i], 10, 64)
	if err != nil {
		// strtol() saturates at LONG_MIN/LONG_MAX rather than failing.
		n = math.MaxInt64
		if s[start] == '-' {
			n = math.MinInt64
		}
	}
	//nolint:gosec // G115: the truncation IS the behavior being matched --
	// strtol() returns a long and StrIsProcId assigns it to an int.
	return int(int32(n)), s[i:], true
}

// wrapExprForAnd is wrapExprForOr for an expression about to become the LEFT
// side of an `&&` -- the LOGICAL_AND_OP call of WrapExprTreeInParensForOp.
//
// Only `||` and the ternary `? :` bind more loosely than `&&`, so those are
// the two shapes that need the parentheses. Everything else is left alone,
// because adding parentheses changes the expression TREE even where it does
// not change the value.
func wrapExprForAnd(value string) (string, error) {
	expr, err := classad.ParseExpr(value)
	if err != nil {
		return "", err
	}
	scratch := classad.New()
	scratch.InsertExpr("X", expr)
	tree := scratch.AST()
	if tree == nil || len(tree.Attributes) != 1 {
		return "(" + value + ")", nil
	}
	switch root := tree.Attributes[0].Value.(type) {
	case *ast.ConditionalExpr:
		return "(" + value + ")", nil
	case *ast.BinaryOp:
		if root.Op == "||" {
			return "(" + value + ")", nil
		}
	}
	return value, nil
}

// gpuPropertyNames are the attributes of a GPU's property ad that a
// gpus_*_* keyword constrains, paired with the job attribute holding the
// bound and the comparison between them. The ORDER is the order
// SubmitHash::SetResourceRequirements emits the clauses in, and it is part
// of the answer: the clauses are joined with `&&`, which is
// left-associative, so a different order is a different expression tree.
var gpuPropertyNames = []struct {
	prop string
	attr string
	op   string
}{
	{"Capability", "GPUsMinCapability", ">="},
	{"Capability", "GPUsMaxCapability", "<="},
	{"GlobalMemoryMb", "GPUsMinMemory", ">="},
	{"MaxSupportedVersion", "GPUsMinRuntime", ">="},
}

// setGPUResourceRequirements is SubmitHash::SetResourceRequirements plus the
// cuda_version half of SetRequirements. Both run late, after the custom
// attributes, and both read the job AD rather than the submit file -- so a
// `+GPUsMinCapability` reaches the derived expression even though the
// `gpus_minimum_capability` KEYWORD would have been ignored without a
// request_gpus.
//
// What it derives is the constraint a GPU has to satisfy. Without it a job
// that asked for a compute capability, a device memory or a CUDA runtime
// carries those bounds as job attributes that nothing reads, so it matches
// a card that cannot run it: the bounds only bite through RequireGPUs,
// which is what the startd evaluates against each GPU's property ad.
func (sf *SubmitFile) setGPUResourceRequirements(ad *classad.ClassAd) error {
	if err := sf.deriveRequireGPUs(ad); err != nil {
		return err
	}
	return sf.finalizeCUDAVersion(ad)
}

// deriveRequireGPUs turns the GPU property bounds on the ad into the
// RequireGPUs expression the startd evaluates against each GPU.
func (sf *SubmitFile) deriveRequireGPUs(ad *classad.ClassAd) error {
	if _, ok := ad.Lookup("RequestGpus"); !ok {
		return nil
	}

	// A require_gpus the user wrote themselves wins over the derived
	// clause for any property it already mentions, so the two never
	// contradict each other. SetResourceRequirements decides that by
	// evaluating the references against a stand-in property ad; the
	// values below are HTCondor's own, and only the NAMES matter.
	// TARGET.Capability is deliberately not a property reference -- it
	// names the machine ad, not the GPU -- and it does not suppress
	// anything.
	props := classad.New()
	_ = props.Set("Capability", 7.5)
	_ = props.Set("GlobalMemoryMb", 11012)
	_ = props.Set("DriverVersion", 12.1)
	_ = props.Set("MaxSupportedVersion", 12010)

	covered := make(map[string]bool)
	existing, hasExisting := ad.Lookup("RequireGPUs")
	if hasExisting {
		for _, name := range props.InternalRefs(existing) {
			covered[strings.ToLower(name)] = true
		}
		// An explicitly MY-scoped reference is an internal reference
		// too. GetExprReferences puts it in the same bucket as an
		// unqualified one, and InternalRefs does not report it.
		scratch := classad.New()
		scratch.InsertExpr("X", existing)
		if tree := scratch.AST(); tree != nil && len(tree.Attributes) == 1 {
			collectMyScopeRefs(tree.Attributes[0].Value, covered)
		}
	}

	var clauses []string
	for _, c := range gpuPropertyNames {
		if covered[strings.ToLower(c.prop)] {
			continue
		}
		if _, ok := ad.Lookup(c.attr); !ok {
			continue
		}
		clauses = append(clauses, c.prop+" "+c.op+" "+c.attr)
	}
	if len(clauses) == 0 {
		return nil
	}

	derived := strings.Join(clauses, " && ")
	if hasExisting {
		wrapped, err := wrapExprForAnd(existing.String())
		if err != nil {
			return fmt.Errorf("require_gpus: %q is not a valid ClassAd expression: %w", existing.String(), err)
		}
		derived = wrapped + " && " + derived
	}
	return setExprAttr(ad, "RequireGPUs", "require_gpus", derived)
}

// collectMyScopeRefs adds the lower-cased name of every MY-scoped
// attribute reference in an expression to seen.
func collectMyScopeRefs(e ast.Expr, seen map[string]bool) {
	switch n := e.(type) {
	case nil:
		return
	case *ast.AttributeReference:
		if n.Scope == ast.MyScope {
			seen[strings.ToLower(n.Name)] = true
		}
	case *ast.BinaryOp:
		collectMyScopeRefs(n.Left, seen)
		collectMyScopeRefs(n.Right, seen)
	case *ast.UnaryOp:
		collectMyScopeRefs(n.Expr, seen)
	case *ast.ParenExpr:
		collectMyScopeRefs(n.Inner, seen)
	case *ast.ConditionalExpr:
		collectMyScopeRefs(n.Condition, seen)
		collectMyScopeRefs(n.TrueExpr, seen)
		collectMyScopeRefs(n.FalseExpr, seen)
	case *ast.ElvisExpr:
		collectMyScopeRefs(n.Left, seen)
		collectMyScopeRefs(n.Right, seen)
	case *ast.FunctionCall:
		for _, arg := range n.Args {
			collectMyScopeRefs(arg, seen)
		}
	case *ast.ListLiteral:
		for _, el := range n.Elements {
			collectMyScopeRefs(el, seen)
		}
	case *ast.SelectExpr:
		collectMyScopeRefs(n.Record, seen)
	case *ast.SubscriptExpr:
		collectMyScopeRefs(n.Container, seen)
		collectMyScopeRefs(n.Index, seen)
	}
}

// finalizeCUDAVersion rewrites the CUDAVersion string the cuda_version
// keyword stored as the integer the startd compares against, which is what
// SetRequirements does on its way to building the clause
// `CUDAVersion <= TARGET.CUDAMaxSupportedVersion`.
//
// The encoding is NOT the one gpus_minimum_runtime uses, however alike the
// two look: "12.1" is 12001 here and 12010 there, because this one adds the
// minor version rather than ten times it. A value in neither form fails the
// submit outright.
//
// It runs only where SetRequirements reaches that code, which is the
// subtlety: the function returns early -- leaving the string in place and
// accepting a value it would otherwise reject -- when the Requirements
// expression is being taken from somewhere else entirely.
func (sf *SubmitFile) finalizeCUDAVersion(ad *classad.ClassAd) error {
	sf.cudaClause = false
	if !sf.generatesRequirements() {
		return nil
	}
	raw, ok := classad.GetAs[string](ad, "CUDAVersion")
	if !ok {
		return nil
	}
	ver, ok := cudaVersionNumber(raw)
	if !ok {
		return fmt.Errorf("cuda_version must be of the form 'x' or 'x.y', where x and y are positive integers")
	}
	_ = ad.Set("CUDAVersion", ver)
	// The clause belongs to this conversion, and setRequirements adds it.
	sf.cudaClause = true
	return nil
}

// generatesRequirements reports whether SubmitHash::SetRequirements would
// reach the point where it generates clauses, rather than returning early
// with a Requirements expression it was handed.
func (sf *SubmitFile) generatesRequirements() bool {
	// A FACTORY.Requirements is used verbatim and nothing else runs, but
	// only when the submitter wrote no `requirements` of their own.
	if sf.submitParam("requirements", "") == "" {
		if sf.submitParam("FACTORY.Requirements", "") != "" {
			return false
		}
	}
	// MY.Requirements / +Requirements replace the generated expression
	// wholesale, warning if `requirements` was given as well.
	if v, ok := sf.customAttrValue("Requirements"); ok && strings.TrimSpace(v) != "" {
		return false
	}
	// A non-Condor-C grid job gets no generated requirements at all.
	if sf.universe == UniverseGrid {
		res, _ := sf.submitCommandAlt("grid_resource", "GridResource")
		gridType, _, _ := strings.Cut(strings.TrimSpace(res), " ")
		if !strings.EqualFold(gridType, "condor") {
			return false
		}
	}
	return true
}

// customAttrValue returns the value of a `+Attr` / `MY.Attr` assignment,
// macro-expanded, and whether the submit file made one.
func (sf *SubmitFile) customAttrValue(name string) (string, bool) {
	if sf == nil {
		return "", false
	}
	for _, key := range sf.cfg.Keys() {
		attr, ok := customAttrName(key)
		if !ok || !strings.EqualFold(attr, name) {
			continue
		}
		if v, ok := sf.cfg.Get(key); ok {
			return v, true
		}
	}
	return "", false
}

// cudaVersionNumber parses a cuda_version the way SetRequirements does,
// with scanf("%u.%u") and then scanf("%u"), each required to consume the
// whole string. The arithmetic is deliberately 32-bit unsigned, because
// that is the width scanf wrote into and the width the multiply happens in.
func cudaVersionNumber(s string) (int64, bool) {
	if major, rest, ok := scanUint32(s); ok && strings.HasPrefix(rest, ".") {
		if minor, rest, ok := scanUint32(rest[1:]); ok && rest == "" {
			return int64(major*1000 + minor%100), true
		}
	}
	if major, rest, ok := scanUint32(s); ok && rest == "" {
		if major < 1000 {
			return int64(major * 1000), true
		}
		return int64(major), true
	}
	return 0, false
}

// scanUint32 is scanf's %u: leading whitespace, an optional sign, and a run
// of digits, accumulated as an unsigned long and truncated into an unsigned
// int -- which is why "-1" reads back as 4294967295 rather than failing.
func scanUint32(s string) (value uint32, rest string, ok bool) {
	i := 0
	for i < len(s) && isSpaceByte(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	digits := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == digits {
		return 0, s, false
	}
	n, err := strconv.ParseUint(s[digits:i], 10, 64)
	if err != nil {
		// strtoul() saturates at ULONG_MAX rather than failing.
		n = math.MaxUint64
	}
	//nolint:gosec // G115: the truncation IS the behavior being matched --
	// scanf %u writes an unsigned int, which is why "-1" reads 4294967295.
	v := uint32(n)
	if neg {
		v = -v
	}
	return v, s[i:], true
}
