package config

// Macro expansion, ported from HTCondor's config.cpp (v25.14.1): the char*
// overload of expand_macro that param() uses, with next_config_macro,
// evaluate_macro_func and expand_self_macro. The port keeps HTCondor's
// algorithm rather than approximating it, because the details are what a
// configuration sees: the scan restarts from the start of the string after
// every substitution (so the result of one expansion is itself expanded),
// a $(NAME) body may hold only identifier characters before its ':', the
// special functions ($INT, $SUBSTR, $F...) take everything up to the first
// ')', and $(DOLLAR) is replaced only after everything else.
//
// The one deliberate difference: HTCondor's loop never ends on a reference
// cycle (A = $(B), B = $(A)), and recursion through a special function
// ($SUBSTR(A,...) inside A) overflows its stack; this one stops after
// maxExpandSteps substitutions, a value of maxExpandLen bytes, maxExpandWork
// bytes rescanned or maxExpandDepth nested expansions, and reports
// ErrMacroLoop.

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// ErrMacroLoop reports a macro expansion that does not terminate, such as a
// reference cycle. HTCondor's own expansion loops forever on one.
var ErrMacroLoop = errors.New("macro expansion does not terminate (reference cycle?)")

// ErrHTCondorUndefined reports a construct on which HTCondor's own code has no
// defined result -- it reads past the end of a buffer or crashes -- so there
// is no behavior to match. The parse or expansion fails instead.
var ErrHTCondorUndefined = errors.New("HTCondor's behavior is undefined here")

const (
	maxExpandSteps = 2000
	maxExpandLen   = 1 << 18
	maxExpandWork  = 1 << 24 // bytes rescanned, summed over the steps
)

// Macro ids, as config.cpp numbers them.
const (
	macroNone          = 0
	macroNormal        = -1
	macroENV           = 1
	macroRandomChoice  = 2
	macroRandomInteger = 3
	macroChoice        = 4
	macroSubstr        = 5
	macroInt           = 6
	macroReal          = 7
	macroString        = 8
	macroEval          = 9
	macroBasename      = 10
	macroDirname       = 11
	macroFilename      = 12
)

// macroBody says which characters a macro body may hold (MACRO_BODY_CHARS).
type macroBody int

const (
	bodyAnything    macroBody = iota // anything up to the first ')'
	bodyIDCharColon                  // identifier characters, then ':' and a default
	bodyMetaArg                      // digits and ?#+, then ':' and a default
)

// colonDefExtraChars are the characters allowed after the ':' of $(NAME:def)
// beyond identifier characters (COLON_DEF_EXTRACHARSET).
const colonDefExtraChars = "$ ,\\:"

func cIsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}
func cIsDigit(c byte) bool { return c >= '0' && c <= '9' }
func cIsAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func cIsAlnum(c byte) bool { return cIsAlpha(c) || cIsDigit(c) }

// isIDChar is condor_isidchar: the characters of a parameter name.
func isIDChar(c byte) bool { return cIsAlnum(c) || c == '_' || c == '.' || c == '/' }

// isValidParamName is is_valid_param_name.
func isValidParamName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isIDChar(name[i]) {
			return false
		}
	}
	return true
}

var specialMacroNames = []struct {
	name string
	id   int
}{
	{"$ENV", macroENV},
	{"$RANDOM_CHOICE", macroRandomChoice},
	{"$RANDOM_INTEGER", macroRandomInteger},
	{"$CHOICE", macroChoice},
	{"$SUBSTR", macroSubstr},
	{"$INT", macroInt},
	{"$REAL", macroReal},
	{"$STRING", macroString},
	{"$EVAL", macroEval},
	{"$BASENAME", macroBasename},
	{"$DIRNAME", macroDirname},
}

// isSpecialConfigMacro is is_special_config_macro: prefix is the text from
// the '$' up to (not including) the '('.
func isSpecialConfigMacro(prefix string) (int, macroBody) {
	if len(prefix) <= 1 {
		return macroNone, bodyAnything
	}
	if prefix[1] == 'F' {
		isFname := true
		for i := 2; i < len(prefix); i++ {
			if strings.IndexByte("pnxdqabfwu", prefix[i]|0x20) < 0 {
				isFname = false
				break
			}
		}
		if isFname {
			return macroFilename, bodyAnything
		}
	}
	for _, p := range specialMacroNames {
		if prefix == p.name {
			if p.id == macroENV {
				return p.id, bodyIDCharColon
			}
			return p.id, bodyAnything
		}
	}
	return macroNone, bodyAnything
}

// isConfigMacro is is_config_macro: $(...) and the special functions, but
// never $$(...).
func isConfigMacro(prefix string) (int, macroBody) {
	if len(prefix) == 1 {
		return macroNormal, bodyIDCharColon
	}
	if prefix[1] == '$' {
		return macroNone, bodyAnything
	}
	return isSpecialConfigMacro(prefix)
}

// isMetaArgMacro is is_meta_arg_macro: only $(<digits>...).
func isMetaArgMacro(prefix string) (int, macroBody) {
	if len(prefix) == 1 {
		return macroNormal, bodyMetaArg
	}
	return macroNone, bodyAnything
}

// macroPos locates one macro reference found by nextConfigMacro:
// value[dollar:bodyStart-1] is the prefix ("$", "$ENV", ...),
// value[bodyStart:bodyEnd] the body and value[bodyEnd] the closing ')'.
type macroPos struct {
	id        int
	dollar    int
	bodyStart int
	bodyEnd   int
}

func (p macroPos) funcName(value string) string { return value[p.dollar+1 : p.bodyStart-1] }
func (p macroPos) body(value string) string     { return value[p.bodyStart:p.bodyEnd] }

// nextConfigMacro is next_config_macro (the char* overload): find the first
// macro reference whose prefix checkPrefix accepts,
// whose body has only the characters its kind allows, and that skip does not
// reject. It returns id macroNone when there is none.
//
//nolint:gocyclo // ported as one function, as in config.cpp
func nextConfigMacro(value string,
	checkPrefix func(string) (int, macroBody),
	skip func(id int, body string) bool) macroPos {
	n := len(value)
	tv := 0
	for {
		// Find the next '$prefix(' that checkPrefix accepts.
		var id int
		var bc macroBody
		dollar := -1
		for {
			if tv > n {
				return macroPos{}
			}
			k := strings.IndexByte(value[tv:], '$')
			if k < 0 {
				return macroPos{}
			}
			d := tv + k
			p := d + 1
			if p < n && value[p] == '$' {
				p++ // $$ may be part of the prefix
			}
			for p < n && (cIsAlnum(value[p]) || value[p] == '_') {
				p++
			}
			if p < n && value[p] == '(' {
				id, bc = checkPrefix(value[d:p])
				if id != macroNone {
					dollar = d
					tv = p
					break
				}
			}
			tv = p
		}

		// tv is at the '('.
		name := tv + 1
		v := name
		retry := false
		switch bc {
		case bodyAnything:
			for v < n && value[v] != ')' {
				v++
			}
		case bodyIDCharColon, bodyMetaArg:
			isMeta := bc == bodyMetaArg
			afterColon := 0
			for v < n && value[v] != ')' {
				ch := value[v]
				v++
				if ch == ':' && afterColon == 0 {
					afterColon = v - name
					continue
				}
				if afterColon != 0 {
					switch {
					case ch == '(':
						if k := strings.IndexByte(value[v:], ')'); k >= 0 {
							v += k + 1
							continue
						}
					case isMeta, strings.IndexByte(colonDefExtraChars, ch) >= 0:
						continue
					}
				}
				if isMeta {
					if !cIsDigit(ch) && ch != '?' && ch != '#' && ch != '+' {
						retry = true
						break
					}
				} else if !isIDChar(ch) {
					retry = true
					break
				}
			}
		}
		if retry {
			tv = name
			continue
		}
		if v < n && value[v] == ')' {
			if skip != nil && skip(id, value[name:v]) {
				tv = v
				continue
			}
			return macroPos{id: id, dollar: dollar, bodyStart: name, bodyEnd: v}
		}
		tv = name
	}
}

// isDollarBody reports whether a normal macro's body is DOLLAR.
func isDollarBody(id int, body string) bool {
	return id == macroNormal && len(body) == 6 && asciiEqualFold(body, "DOLLAR")
}

// expander carries the step budget through one top-level expansion, including
// the nested expansions the special functions perform.
type expander struct {
	c     *Config
	steps int
	work  int
	depth int // nested expansions, which the special functions start
}

// maxExpandDepth bounds nested expansion: `A = $SUBSTR(B,0)` with B's value
// referring back to A recurses without ever completing a substitution, and
// HTCondor overflows its stack on it.
const maxExpandDepth = 200

func (e *expander) step(length int) error {
	e.steps++
	e.work += length
	if e.steps > maxExpandSteps || length > maxExpandLen || e.work > maxExpandWork {
		return ErrMacroLoop
	}
	return nil
}

// expandMacro expands every macro reference in value (expand_macro).
func (c *Config) expandMacro(value string) (string, error) {
	e := &expander{c: c}
	return e.expand(value)
}

func (e *expander) expand(value string) (string, error) {
	e.depth++
	defer func() { e.depth-- }()
	if e.depth > maxExpandDepth {
		return "", ErrMacroLoop
	}
	tmp := value
	for {
		pos := nextConfigMacro(tmp, isConfigMacro, isDollarBody)
		if pos.id == macroNone {
			break
		}
		tv, err := e.evaluate(pos.funcName(tmp), pos.id, pos.body(tmp))
		if err != nil {
			return "", err
		}
		tmp = tmp[:pos.dollar] + tv + tmp[pos.bodyEnd+1:]
		if err := e.step(len(tmp)); err != nil {
			return "", err
		}
	}
	// $(DOLLAR) is replaced last, so the '$' it yields is never expanded.
	dollarOnly := func(id int, body string) bool { return !isDollarBody(id, body) }
	for {
		pos := nextConfigMacro(tmp, isConfigMacro, dollarOnly)
		if pos.id == macroNone {
			break
		}
		tmp = tmp[:pos.dollar] + "$" + tmp[pos.bodyEnd+1:]
	}
	return tmp, nil
}

// expandSelfMacro expands only the references to self in value
// (expand_self_macro). HTCondor applies it to a definition's value before
// storing it, so `A = $(A) more` appends to A's previous value.
func (c *Config) expandSelfMacro(value, self string) (string, error) {
	e := &expander{c: c}
	return e.expandSelf(value, self)
}

func (e *expander) expandSelf(value, self string) (string, error) {
	self2 := ""
	prefix := ""
	for _, p := range []string{e.c.options.LocalName, e.c.options.Subsystem} {
		if p == "" || prefix != "" {
			continue
		}
		if len(self) > len(p)+1 && asciiEqualFold(self[:len(p)], p) && self[len(p)] == '.' {
			self2 = self[len(p)+1:]
			prefix = p
		}
	}
	matches := func(name, s string) bool {
		return s != "" && (len(name) == len(s) || (len(name) > len(s) && name[len(s)] == ':')) &&
			asciiEqualFold(name[:len(s)], s)
	}
	onlySelf := func(id int, body string) bool {
		if id != macroNormal && id != macroFilename {
			return true
		}
		return !matches(body, self) && !matches(body, self2)
	}
	tmp := value
	for {
		pos := nextConfigMacro(tmp, isConfigMacro, onlySelf)
		if pos.id == macroNone {
			return tmp, nil
		}
		tv, err := e.evaluate(pos.funcName(tmp), pos.id, pos.body(tmp))
		if err != nil {
			return "", err
		}
		tmp = tmp[:pos.dollar] + tv + tmp[pos.bodyEnd+1:]
		if err := e.step(len(tmp)); err != nil {
			return "", err
		}
	}
}

// lookupMacro is lookup_macro: the raw (unexpanded) value of a parameter,
// honoring the subsystem/local-name prefixes, case-insensitively.
func (c *Config) lookupMacro(name string) (string, bool) {
	return c.lookupValue(name)
}

// evaluate is evaluate_macro_func (the char* overload): the value one macro
// reference is replaced with. funcName is the text between '$' and '('.
//
//nolint:gocyclo // one case per HTCondor macro function, as in config.cpp
func (e *expander) evaluate(funcName string, id int, body string) (string, error) {
	c := e.c
	switch id {
	case macroNormal:
		name, def, hasDef := strings.Cut(body, ":")
		v, ok := c.lookupMacro(name)
		if hasDef && (!ok || v == "") {
			v = def
		}
		return v, nil

	case macroENV:
		name, def, hasDef := strings.Cut(body, ":")
		if c.options.NoLocalAccess {
			return "", fmt.Errorf("$ENV() is not allowed here: this text is parsed without access to the local host")
		}
		v, ok := os.LookupEnv(name)
		if !ok {
			if hasDef {
				return def, nil
			}
			return "UNDEFINED", nil
		}
		return v, nil

	case macroRandomChoice:
		return e.randomChoice(body)

	case macroRandomInteger:
		return e.randomInteger(body), nil

	case macroChoice:
		return e.choice(body)

	case macroSubstr:
		return e.substr(body)

	case macroInt, macroReal:
		return e.number(id, body)

	case macroString:
		return e.str(body)

	case macroEval:
		return e.eval(body)

	case macroDirname, macroBasename, macroFilename:
		return e.filename(funcName, id, body)
	}
	return "", nil
}

// lookupAndExpand looks name up as a macro, falling back to the literal
// text, and expands the result if it holds a '$'. This is the pattern most
// of the special functions share.
func (e *expander) lookupAndExpand(name string) (string, error) {
	v, ok := e.c.lookupMacro(name)
	if !ok {
		v = name
	}
	if strings.IndexByte(v, '$') >= 0 {
		return e.expand(v)
	}
	return v, nil
}

func (e *expander) randomChoice(body string) (string, error) {
	entries := splitTrimmed(body, ",")
	if len(entries) == 1 {
		if lval, ok := e.c.lookupMacro(entries[0]); ok {
			if strings.IndexByte(lval, '$') >= 0 {
				x, err := e.expand(lval)
				if err != nil {
					return "", err
				}
				lval = x
			}
			entries = splitTrimmed(lval, ", \t\r\n")
		}
	}
	if len(entries) == 0 {
		return "", nil
	}
	//nolint:gosec // G404: HTCondor uses get_random_int_insecure here too
	return entries[rand.Intn(len(entries))], nil
}

func (e *expander) randomInteger(body string) string {
	entries := strings.Split(body, ",")
	arg := func(i int) string {
		if i < len(entries) {
			return trimC(entries[i])
		}
		return ""
	}
	minV, ok := cStrtol(arg(0))
	if !ok {
		minV = 0
	}
	maxV, ok := cStrtol(arg(1))
	if !ok {
		maxV = minV
	}
	step := int64(1)
	if s := arg(2); s != "" {
		if v, ok := cStrtol(s); ok {
			step = v
		}
	}
	if step < 1 {
		step = 1
	}
	if minV > maxV {
		minV = maxV
	}
	num := (step + maxV - minV) / step
	if num <= 0 {
		num = 1
	}
	//nolint:gosec // G404: HTCondor uses get_random_int_insecure here too
	return strconv.FormatInt(minV+rand.Int63n(num)*step, 10)
}

func (e *expander) choice(body string) (string, error) {
	ival, ok := nthListItem(body, ',', 0)
	if !ok {
		ival = ""
	}
	ival, err := e.lookupAndExpand(ival)
	if err != nil {
		return "", err
	}
	index, isInt := e.stringIsLong(ival)
	if !isInt || index < 0 || index >= math.MaxInt32 {
		index = 0
	}
	lval, ok := nthListItem(body, ',', 1)
	if !ok {
		return "", nil
	}
	items := body[strings.Index(body, ",")+1:]
	if !strings.Contains(items, ",") {
		list, ok := e.c.lookupMacro(lval)
		if !ok {
			return "", nil
		}
		x, err := e.expand(list)
		if err != nil {
			return "", err
		}
		items = x
	} else {
		items = strings.TrimLeft(items, " \t\n\v\f\r")
	}
	item, ok := nthListItem(items, ',', int(index))
	if !ok {
		return "", nil
	}
	return item, nil
}

// nthListItem is nth_list_item with trimming: the index'th sep-separated
// item of list, without surrounding whitespace.
func nthListItem(list string, sep byte, index int) (string, bool) {
	p := 0
	for ii := 0; ; ii++ {
		e := strings.IndexByte(list[p:], sep)
		end := len(list)
		if e >= 0 {
			end = p + e
		}
		if ii == index {
			s, t := p, end
			for s < t && cIsSpace(list[s]) {
				s++
			}
			for t > s && cIsSpace(list[t-1]) {
				t--
			}
			return list[s:t], true
		}
		if e < 0 {
			return "", false
		}
		p = end + 1
	}
}

func (e *expander) substr(body string) (string, error) {
	name, rest, ok := strings.Cut(body, ",")
	if !ok {
		return "", nil
	}
	startArg, lenArg, hasLen := strings.Cut(rest, ",")

	arg, err := e.lookupAndExpand(startArg)
	if err != nil {
		return "", err
	}
	start, isInt := e.stringIsLong(arg)
	if !isInt || start < math.MinInt32 || start >= math.MaxInt32 {
		return "", nil
	}
	subLen := int64(math.MaxInt32 / 2)
	if hasLen {
		arg, err := e.lookupAndExpand(lenArg)
		if err != nil {
			return "", err
		}
		l, isInt := e.stringIsLong(arg)
		if !isInt || l < math.MinInt32 || l > math.MaxInt32 {
			return "", nil
		}
		subLen = l
	}

	mval, ok := e.c.lookupMacro(name)
	if !ok {
		return "", nil
	}
	if strings.IndexByte(mval, '$') >= 0 {
		if mval, err = e.expand(mval); err != nil {
			return "", err
		}
	}
	cch := int64(len(mval))
	if start < 0 {
		start += cch
	}
	if start < 0 {
		start = 0
	} else if start > cch {
		start = cch
	}
	cch -= start
	if subLen < 0 {
		subLen += cch
	}
	if subLen < 0 {
		subLen = 0
	} else if subLen > cch {
		subLen = cch
	}
	return mval[start : start+subLen], nil
}

// number is $INT(name[,fmt]) and $REAL(name[,fmt]).
func (e *expander) number(id int, body string) (string, error) {
	name, format, hasFmt := strings.Cut(body, ",")
	if hasFmt {
		want := pftInt
		if id == macroReal {
			want = pftFloat
		}
		if validatePrintfFormat(format, want) <= 0 {
			return format, nil
		}
	}
	mval, err := e.lookupAndExpand(name)
	if err != nil {
		return "", err
	}
	if id == macroInt {
		v, ok := e.stringIsLong(mval)
		if !ok {
			return "", nil
		}
		if !hasFmt {
			format = "%lld"
		}
		out, err := cSprintfInt(format, v)
		return truncateC(out, 55), err
	}
	v, ok := e.stringIsDouble(mval)
	if !ok {
		return "", nil
	}
	if !hasFmt {
		out, err := cSprintfFloat("%.16G", v)
		return truncateC(out, 55), err
	}
	out, err := cSprintfFloat(format, v)
	if err != nil {
		return "", err
	}
	out = truncateC(out, 55)
	if !strings.Contains(out, ".") {
		if len(out) > 54 {
			// HTCondor's 57-byte buffer has no room for the ".0" it appends.
			return "", fmt.Errorf("%w: $REAL format output overflows HTCondor's buffer", ErrHTCondorUndefined)
		}
		out += ".0"
	}
	return out, nil
}

// str is $STRING(name[,fmt]).
func (e *expander) str(body string) (string, error) {
	name, format, hasFmt := strings.Cut(body, ",")
	if hasFmt && validatePrintfFormat(format, pftString) <= 0 {
		return format, nil
	}
	mval, err := e.lookupAndExpand(name)
	if err != nil {
		return "", err
	}
	if expr, err := parseConfigExpr(mval); err == nil {
		if v := expr.Eval(classad.New()); v.IsString() {
			s, _ := v.StringValue()
			mval = s
		}
	}
	if hasFmt {
		out, err := cSprintfString(format, mval)
		return truncateC(out, len(out)), err
	}
	return mval, nil
}

// eval is $EVAL(name).
func (e *expander) eval(body string) (string, error) {
	v, ok := e.c.lookupMacro(body)
	if !ok {
		v = body
	}
	expanded := ""
	haveExpanded := false
	if strings.IndexByte(v, '$') >= 0 {
		x, err := e.expand(v)
		if err != nil {
			return "", err
		}
		v, expanded, haveExpanded = x, x, true
	}
	if expr, err := parseConfigExpr(v); err == nil {
		r := expr.Eval(classad.New())
		if r.IsString() {
			s, _ := r.StringValue()
			return s, nil
		}
		return r.String(), nil
	}
	if haveExpanded {
		return expanded, nil
	}
	return "", nil
}

// stringIsLong is string_is_long_param: a decimal integer literal (with
// optional surrounding whitespace), or else a ClassAd expression that
// evaluates to a number.
func (e *expander) stringIsLong(s string) (int64, bool) {
	if v, ok := cStrtollWhole(s); ok {
		return v, true
	}
	expr, err := parseConfigExpr(s)
	if err != nil {
		return 0, false
	}
	r := expr.Eval(classad.New())
	switch {
	case r.IsInteger():
		n, _ := r.IntValue()
		return n, true
	case r.IsReal():
		f, _ := r.RealValue()
		return truncToInt64(f), true
	case r.IsBool():
		b, _ := r.BoolValue()
		if b {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// stringIsDouble is string_is_double_param.
func (e *expander) stringIsDouble(s string) (float64, bool) {
	if v, ok := cStrtodWhole(s); ok {
		return v, true
	}
	expr, err := parseConfigExpr(s)
	if err != nil {
		return 0, false
	}
	r := expr.Eval(classad.New())
	switch {
	case r.IsInteger():
		n, _ := r.IntValue()
		return float64(n), true
	case r.IsReal():
		f, _ := r.RealValue()
		return f, true
	case r.IsBool():
		b, _ := r.BoolValue()
		if b {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func truncToInt64(f float64) int64 {
	switch {
	case math.IsNaN(f):
		return math.MinInt64
	case f >= math.MaxInt64:
		return math.MinInt64 // x86-64 cvttsd2si yields the "integer indefinite"
	case f <= math.MinInt64:
		return math.MinInt64
	}
	return int64(f)
}

// cStrtol parses like strtol(s, &end, 10): leading whitespace, an optional
// sign and as many digits as there are. ok is false when there are none.
func cStrtol(s string) (int64, bool) {
	v, n := cStrtoll(s)
	return v, n > 0
}

// cStrtoll returns strtoll(s, &end, 10) and the number of bytes consumed (0
// when no digits were found). Overflow clamps, as strtoll does.
func cStrtoll(s string) (int64, int) {
	i := 0
	for i < len(s) && cIsSpace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	var v uint64
	overflow := false
	for i < len(s) && cIsDigit(s[i]) {
		d := uint64(s[i] - '0')
		if v > (math.MaxUint64-d)/10 {
			overflow = true
		} else {
			v = v*10 + d
		}
		i++
	}
	if i == start {
		return 0, 0
	}
	if neg {
		if overflow || v > 1<<63 {
			return math.MinInt64, i
		}
		return -int64(v), i
	}
	if overflow || v > math.MaxInt64 {
		return math.MaxInt64, i
	}
	return int64(v), i
}

// cStrtollWhole is the literal half of string_is_long_param: the whole string
// (bar trailing whitespace) must be consumed.
func cStrtollWhole(s string) (int64, bool) {
	v, n := cStrtoll(s)
	if n == 0 {
		return 0, false
	}
	for n < len(s) && cIsSpace(s[n]) {
		n++
	}
	return v, n == len(s)
}

// cStrtodWhole is the literal half of string_is_double_param.
func cStrtodWhole(s string) (float64, bool) {
	v, n := cStrtod(s)
	if n == 0 {
		return 0, false
	}
	for n < len(s) && cIsSpace(s[n]) {
		n++
	}
	return v, n == len(s)
}

// cStrtod returns strtod(s, &end) and the number of bytes consumed.
//
//nolint:gocyclo // strtod's grammar: sign, inf/nan, hex and decimal forms
func cStrtod(s string) (float64, int) {
	i := 0
	for i < len(s) && cIsSpace(s[i]) {
		i++
	}
	start := i
	j := i
	if j < len(s) && (s[j] == '+' || s[j] == '-') {
		j++
	}
	rest := asciiLower(s[j:])
	switch {
	case strings.HasPrefix(rest, "infinity"):
		j += 8
	case strings.HasPrefix(rest, "inf"):
		j += 3
	case strings.HasPrefix(rest, "nan"):
		j += 3
		if j < len(s) && s[j] == '(' {
			k := j + 1
			for k < len(s) && (cIsAlnum(s[k]) || s[k] == '_') {
				k++
			}
			if k < len(s) && s[k] == ')' {
				j = k + 1
			}
		}
	case strings.HasPrefix(rest, "0x") && len(rest) > 2 && (isHexDigit(rest[2]) || (rest[2] == '.' && len(rest) > 3 && isHexDigit(rest[3]))):
		k := j + 2
		digits := 0
		for k < len(s) && isHexDigit(s[k]) {
			k++
			digits++
		}
		if k < len(s) && s[k] == '.' {
			k++
			for k < len(s) && isHexDigit(s[k]) {
				k++
				digits++
			}
		}
		if digits > 0 {
			if k < len(s) && (s[k] == 'p' || s[k] == 'P') {
				m := k + 1
				if m < len(s) && (s[m] == '+' || s[m] == '-') {
					m++
				}
				if m < len(s) && cIsDigit(s[m]) {
					for m < len(s) && cIsDigit(s[m]) {
						m++
					}
					k = m
				}
			}
			j = k
		}
		lit := s[start:j]
		if !strings.ContainsAny(lit[strings.Index(asciiLower(lit), "0x"):], "pP") {
			lit += "p0"
		}
		v, _ := strconv.ParseFloat(lit, 64)
		return v, j
	default:
		k := j
		digits := 0
		for k < len(s) && cIsDigit(s[k]) {
			k++
			digits++
		}
		if k < len(s) && s[k] == '.' {
			k++
			for k < len(s) && cIsDigit(s[k]) {
				k++
				digits++
			}
		}
		if digits == 0 {
			return 0, 0
		}
		if k < len(s) && (s[k] == 'e' || s[k] == 'E') {
			m := k + 1
			if m < len(s) && (s[m] == '+' || s[m] == '-') {
				m++
			}
			if m < len(s) && cIsDigit(s[m]) {
				for m < len(s) && cIsDigit(s[m]) {
					m++
				}
				k = m
			}
		}
		j = k
	}
	v, err := strconv.ParseFloat(s[start:j], 64)
	if err != nil {
		var ne *strconv.NumError
		if errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange) {
			return v, j // ±Inf or 0 on over/underflow, as strtod
		}
		if strings.HasPrefix(asciiLower(strings.TrimLeft(s[start:j], "+-")), "nan") {
			return math.NaN(), j
		}
		return 0, 0
	}
	return v, j
}

func isHexDigit(c byte) bool {
	return cIsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// splitTrimmed splits s on any of seps, trims each piece and drops empty
// ones, as HTCondor's split() does.
func splitTrimmed(s, seps string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(seps, r) }) {
		if f = trimC(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// truncateC is what a C string in an n+1 byte snprintf buffer keeps: at most
// n bytes, ending at the first NUL (which %c of 0 writes).
func truncateC(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return s
}

// filename is $DIRNAME, $BASENAME and the $F[fpdnxqabwu] family.
//
//nolint:gocyclo // ported as one function, as in config.cpp
func (e *expander) filename(funcName string, id int, body string) (string, error) {
	killSuffix := ""
	hasKill := false
	if id == macroBasename {
		if i := strings.LastIndexByte(body, ','); i >= 0 && !strings.Contains(body[i:], ")") {
			killSuffix = strings.TrimLeft(body[i+1:], " \t\n\v\f\r")
			hasKill = true
			body = body[:i]
		}
	}
	mval, err := e.lookupAndExpand(body)
	if err != nil {
		return "", err
	}

	parts := 0
	numDirs := 0
	quoted, fullPath, bare, argQuote := false, false, false, false
	var toPathChar byte
	switch id {
	case macroBasename:
		parts = 1 | 2
	case macroDirname:
		parts = 4
	default:
		p := strings.TrimPrefix(funcName, "F")
		for i := 0; i < len(p); i++ {
			switch p[i] | 0x20 {
			case 'x':
				parts |= 0x1
			case 'n':
				parts |= 0x2
			case 'p':
				parts |= 0x4
			case 'd':
				parts |= 0x8
				numDirs++
			case 'a':
				argQuote = true
			case 'b':
				bare = true
			case 'f':
				fullPath = true
			case 'w':
				toPathChar = '\\'
			case 'u':
				toPathChar = '/'
			case 'q':
				quoted = true
			}
		}
	}

	var quoteChar byte
	if quoted {
		quoteChar = '"'
		if argQuote {
			quoteChar = '\''
		}
	}
	umval := strlenUnquote(mval)
	if umval == "" && len(mval) == 2 && (mval[1] == '"' || (quoteChar != 0 && mval[1] == quoteChar)) {
		// strlen_unquote leaves a zero-length string that starts at the
		// closing quote; strcpy_quoted strips it as a leading quote, takes
		// the length to -1 and memcpy's that. HTCondor corrupts its heap.
		return "", fmt.Errorf("%w: %s of an empty quoted string", ErrHTCondorUndefined, "$"+funcName)
	}
	var buf []byte
	if fullPath || parts != 0 || toPathChar != 0 || bare {
		// strdup_full_path_quoted with no cwd is strdup_path_quoted.
		buf = strdupPathQuoted(umval, quoteChar, toPathChar)
	} else {
		buf = strcpyQuoted(umval, quoteChar)
	}
	// buf has room for a trailing quote and terminator, as the C buffer does.
	buf = append(buf, 0, 0, 0)
	cstr := func(b []byte) int { // strlen
		for i, c := range b {
			if c == 0 {
				return i
			}
		}
		return len(b)
	}
	ixend := cstr(buf)
	ixn := 0
	for i := 0; i < ixend; i++ {
		if buf[i] == '/' {
			ixn = i + 1
		}
	}
	// condor_basename_extension_ptr(buf+ixn)
	ixx := ixend
	for p := ixend; p > ixn; p-- {
		if buf[p] == '.' {
			ixx = p
			break
		}
	}
	if hasKill {
		cch := len(killSuffix)
		if ixend-cch >= ixn && asciiEqualFold(killSuffix, string(buf[ixend-cch:ixend])) {
			ixx = ixend - cch
			parts &^= 1
		}
	}
	if ixn == 0 && parts&(2|1) != 0 {
		parts &^= 4 | 8
	}

	tv := 0
	switch parts & 0xF {
	case 1:
		tv = ixx
		if bare && ixx < ixend {
			tv++
		}
	case 2 | 1:
		tv = ixn
	case 2:
		tv = ixn
		ixend = ixx
	case 0, 4 | 2 | 1, 4 | 1:
		tv = 0
	case 4:
		tv = 0
		ixend = ixn
		if bare && ixn > 0 {
			ixend = ixn - 1
		}
	case 4 | 2:
		tv = 0
		ixend = ixx
	default:
		if ixn > 0 {
			var ok bool
			if tv, ok = basenamePlusDirs(buf[:cstr(buf)], numDirs); !ok {
				return "", fmt.Errorf("%w: $F with more d's than directories (HTCondor pops an empty vector)", ErrHTCondorUndefined)
			}
			switch parts & 3 {
			case 2:
				ixend = ixx
			case 0:
				ixend = ixn
				if bare && ixn > 0 {
					ixend = ixn - 1
				}
			}
		} else {
			ixend = 1
			tv = ixend
		}
	}

	if quoted {
		if buf[tv] != quoteChar {
			if tv == 0 {
				// HTCondor ASSERTs here; it cannot happen with a quote char
				// at buf[0], which strcpyQuoted always writes.
				return "", nil
			}
			tv--
			buf[tv] = quoteChar
		}
		if ixend > 1 && buf[ixend-1] == quoteChar {
			ixend--
		}
		buf[ixend] = quoteChar
		ixend++
	}
	// HTCondor terminates the buffer at ixend and returns the string at tv,
	// which runs to the first NUL: past ixend when tv is beyond it.
	buf[ixend] = 0
	return string(buf[tv : tv+cstr(buf[tv:])]), nil
}

// strlenUnquote is strlen_unquote: drop one pair of matching outer quotes.
func strlenUnquote(s string) string {
	if len(s) > 1 && s[0] == s[len(s)-1] && (s[0] == '"' || s[0] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// strcpyQuoted is strcpy_quoted: copy s without a leading '"' (or leading
// quoted char) and the matching trailing one, adding quoted around it.
func strcpyQuoted(s string, quoted byte) []byte {
	cch := len(s)
	var qc byte
	if len(s) > 0 && (s[0] == '"' || (quoted != 0 && s[0] == quoted)) {
		qc = s[0]
		s = s[1:]
		cch--
	}
	if cch > 0 && s[cch-1] == qc {
		cch--
	}
	out := make([]byte, 0, cch+3)
	if quoted != 0 {
		out = append(out, quoted)
	}
	out = append(out, s[:cch]...)
	if quoted != 0 {
		out = append(out, quoted)
	}
	return out
}

// strdupPathQuoted is strdup_path_quoted.
func strdupPathQuoted(s string, quoted, toPathChar byte) []byte {
	out := strcpyQuoted(s, quoted)
	if toPathChar != 0 {
		from := byte('/')
		if toPathChar == '/' {
			from = '\\'
		}
		// HTCondor converts the first cch+1 bytes of the buffer (cch being
		// the input length), which can stop short of a trailing quote.
		lim := len(s) + 1
		for i := 0; i < len(out) && i < lim; i++ {
			if out[i] == from {
				out[i] = toPathChar
			}
		}
	}
	return out
}

// basenamePlusDirs is condor_basename_plus_dirs, returning an index into buf.
// ok is false when numDirs exceeds the separators, where HTCondor pops an
// empty std::vector.
func basenamePlusDirs(buf []byte, numDirs int) (int, bool) {
	var seps []int
	p := 0
	if len(buf) >= 2 && buf[0] == '\\' && buf[1] == '\\' {
		if len(buf) >= 4 && buf[2] == '.' && buf[3] == '\\' {
			seps = append(seps, 4)
			p = 4
		} else {
			seps = append(seps, 2)
			p = 2
		}
	}
	for ; p < len(buf); p++ {
		if buf[p] == '\\' || buf[p] == '/' {
			seps = append(seps, p+1)
		}
	}
	if numDirs > len(seps) {
		return 0, false
	}
	seps = seps[:len(seps)-numDirs]
	if len(seps) > 0 {
		return seps[len(seps)-1], true
	}
	return 0, true
}

// HTCondor compares parameter names with strcasecmp and tolower in the C
// locale: only ASCII letters fold. The strings package folds Unicode (and
// treats invalid UTF-8 as U+FFFD, so any two invalid bytes compare equal),
// which would match names HTCondor keeps apart.

func asciiUpper(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'a' && b[j] <= 'z' {
					b[j] -= 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// parseConfigExpr parses a ClassAd expression the way HTCondor's config
// functions do (ParseClassAdRvalExpr / ClassAd::AssignExpr): old ClassAd
// syntax, and the whole text must be one expression. The classad package
// parses an expression as the value of a one-attribute record, so it also
// accepts a trailing ';' (the record's separator); HTCondor's parser does
// not, and neither does this.
func parseConfigExpr(s string) (*classad.Expr, error) {
	if strings.HasSuffix(strings.TrimRight(s, " \t\n\v\f\r"), ";") {
		return nil, errors.New("not a single expression")
	}
	return classad.ParseExprOld(s)
}
