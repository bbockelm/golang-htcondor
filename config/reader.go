package config

// The configuration-file reader, ported from HTCondor's config.cpp
// (v25.14.1): getline_implementation, which assembles logical lines, and
// Parse_macros, which classifies and applies each one. HTCondor reads a
// config file line by line, applying each line before reading the next; an
// `if` is evaluated against the values defined so far, and the lines of a
// false branch are skipped without being looked at.
//
// As in HTCondor, a line the reader rejects (no operator, an illegal name,
// an unterminated @= value) fails the whole source. Differences from
// HTCondor, both outside HTCondorCompat mode:
//   - an `if` condition HTCondor rejects as complex is handed to
//     evaluateCondition, which understands comparisons, && and ||;
//   - an include path in quotes has the quotes removed.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// getline options (CONFIG_GETLINE_OPT_*).
const (
	glOptCommentDoesntContinue     = 1
	glOptContinueMayBeCommentedOut = 2
	glOptOld                       = 0
	glOptNew                       = glOptCommentDoesntContinue | glOptContinueMayBeCommentedOut
)

// configMaxNestingDepth is CONFIG_MAX_NESTING_DEPTH.
const configMaxNestingDepth = 20

// lineSource reads logical lines from config text (getline_implementation).
type lineSource struct {
	data string
	pos  int
	line int // physical lines read
}

// getline returns the next logical line: whitespace trimmed from both ends,
// and a line ending in a backslash joined to the next one. ok is false at
// the end of the input.
//
// It reproduces two quirks of HTCondor's reader. A last line with no newline
// is returned as read, untrimmed. And with
// glOptContinueMayBeCommentedOut, a '#' line in the middle of a continued
// line contributes only its last character.
func (ls *lineSource) getline(opts int) (string, bool) {
	if ls.pos >= len(ls.data) {
		return "", false
	}
	var buf []byte
	linePtr := 0
	for {
		if ls.pos >= len(ls.data) {
			if len(buf) == 0 {
				return "", false
			}
			return string(buf), true
		}
		chunk := ls.data[ls.pos:]
		if nl := strings.IndexByte(chunk, '\n'); nl >= 0 {
			chunk = chunk[:nl+1]
		}
		ls.pos += len(chunk)
		buf = append(buf, chunk...)
		if chunk[len(chunk)-1] != '\n' {
			continue // the input ended without a newline
		}
		ls.line++

		end := len(buf)
		for end > linePtr && cIsSpace(buf[end-1]) {
			end--
		}
		buf = buf[:end]
		p := linePtr
		for p < len(buf) && cIsSpace(buf[p]) {
			p++
		}
		inComment := p < len(buf) && buf[p] == '#'
		if inComment && linePtr != 0 && opts&glOptContinueMayBeCommentedOut != 0 {
			p = len(buf) - 1
			inComment = false
		}
		if p != linePtr {
			buf = append(buf[:linePtr], buf[p:]...)
		}
		if len(buf) > 0 && buf[len(buf)-1] == '\\' {
			buf = buf[:len(buf)-1]
			if !inComment || opts&glOptCommentDoesntContinue == 0 {
				linePtr = len(buf)
				continue
			}
		}
		return string(buf), true
	}
}

func blankLine(s string) bool {
	for i := 0; i < len(s); i++ {
		if !cIsSpace(s[i]) {
			return false
		}
	}
	return true
}

// parseAndExecute reads configuration text and applies it.
func (c *Config) parseAndExecute(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return c.parseMacros(string(data), 0)
}

// parseMacros is Parse_macros for a config source (no submit callback).
//
//nolint:gocyclo // ported as one function, as in config.cpp
func (c *Config) parseMacros(data string, depth int) error {
	src := &lineSource{data: data}
	glOpt := glOptNew
	optMetaColon := 1 // CONFIG_OPT_COLON_IS_META_ONLY
	ifs := newIfStack()
	hereName, hereTag := "", ""
	var hereData strings.Builder
	bad := func(format string, args ...any) error {
		return fmt.Errorf("config line %d: "+format, append([]any{src.line}, args...)...)
	}

	for {
		line, ok := src.getline(glOpt)
		if !ok {
			if hereName != "" {
				return fmt.Errorf("config: end of input while scanning for '@%s'", hereTag)
			}
			break
		}

		if line == "" || line[0] == '#' || blankLine(line) {
			switch asciiLower(line) {
			case "#opt:oldcomment":
				glOpt = glOptOld
			case "#opt:newcomment":
				glOpt = glOptNew
			case "#opt:strict":
				optMetaColon = 2
			}
			continue
		}

		if hereName != "" {
			if line[0] == '@' && line[1:] == hereTag {
				if err := c.storeHereDoc(hereName, hereData.String()); err != nil {
					return err
				}
				hereName, hereTag = "", ""
				hereData.Reset()
				continue
			}
			if hereData.Len() > 0 {
				hereData.WriteByte('\n')
			}
			hereData.WriteString(line)
			continue
		}

		// A ':' starting a line of an if body is ignored (pre-8.1.5 compat).
		if line[0] == ':' {
			if ifs.insideIf() || (len(line) >= 3 && line[1] == 'i' && line[2] == 'f' && (len(line) == 3 || cIsSpace(line[3]))) {
				line = line[1:]
			}
		}

		if isIf, err := c.lineIsIf(&ifs, line); isIf {
			if err != nil {
				return fmt.Errorf("config line %d: %w", src.line, err)
			}
			continue
		}
		if !ifs.enabled() {
			continue
		}

		if err := c.parseConfigLine(line, depth, &hereName, &hereTag, &optMetaColon, bad); err != nil {
			return err
		}
	}

	if ifs.insideIf() {
		return fmt.Errorf("config line %d: endif(s) not found before end-of-file", src.line)
	}
	return nil
}

// storeHereDoc stores the value of a NAME @=tag ... @tag block.
func (c *Config) storeHereDoc(name, data string) error {
	value, err := c.expandSelfMacro(data, name)
	if err != nil {
		return err
	}
	return c.insertMacro(name, value)
}

// parseConfigLine applies one enabled, non-if line of a config source. It
// sets *hereName/*hereTag when the line opens an @= block.
//
//nolint:gocyclo // ported from Parse_macros
func (c *Config) parseConfigLine(line string, depth int, hereName, hereTag *string, optMetaColon *int, bad func(string, ...any) error) error {
	// The name runs to the first whitespace, '=' or ':'.
	ptr := 0
	for ptr < len(line) && !cIsSpace(line[ptr]) && line[ptr] != '=' && line[ptr] != ':' {
		ptr++
	}
	if ptr == len(line) {
		if line != "" && line[0] == '[' {
			return nil // a [section] line, for .ini compatibility
		}
		return bad("no operator in %q", line)
	}

	name := line[:ptr]
	nameEnd := ptr
	op := line[ptr]
	pop := ptr
	ptr++
	var plusSep byte
	doublePlus := 0
	if op != '=' && op != ':' {
		// Whitespace ended the name: the operator comes later, and any words
		// in between are ignored.
		for ptr < len(line) && cIsSpace(line[ptr]) {
			ptr++
		}
		for ptr < len(line) && line[ptr] != '=' && line[ptr] != ':' && line[ptr] != '@' && line[ptr] != '+' {
			ptr++
		}
		pop = ptr
		op = 0
		if ptr < len(line) {
			op = line[ptr]
			ptr++
			switch op {
			case '@':
				if ptr < len(line) && line[ptr] == '=' {
					ptr++
				} else {
					op = 0
				}
			case '+':
				if ptr == len(line) && c.options.HTCondorCompat {
					// HTCondor's strchr(",;|&*", *ptr) matches the line's
					// terminator here and reads on past it.
					return fmt.Errorf("%w: line %q ends in '+' (HTCondor reads past the end of the line)", ErrHTCondorUndefined, line)
				}
				if ptr < len(line) && strings.IndexByte(",;|&*", line[ptr]) >= 0 {
					plusSep = line[ptr]
					doublePlus = 1
					ptr++
					if ptr < len(line) && line[ptr] == plusSep {
						doublePlus = 2
						ptr++
					}
				}
				if ptr < len(line) && line[ptr] == '=' {
					ptr++
				} else {
					op = 0
				}
			}
		}
	}
	if op != '=' && op != ':' && op != '@' && op != '+' {
		return bad("no operator in %q", line)
	}
	for ptr < len(line) && cIsSpace(line[ptr]) {
		ptr++
	}
	rhs := line[ptr:]

	hasAt := 0
	if name != "" && name[0] == '@' {
		hasAt = 1
	}
	keyword := asciiLower(name[hasAt:])
	isInclude := op == ':' && keyword == "include"
	isMeta := op == ':' && keyword == "use"
	isError := op == ':' && keyword == "error"
	isWarning := op == ':' && keyword == "warning"

	switch {
	case isMeta:
		// The metaknob category is the word(s) between "use" and the ':'.
		name = ""
		if nameEnd < pop {
			name = strings.TrimRight(strings.TrimLeft(line[nameEnd:pop], " \t\n\v\f\r"), " \t\n\v\f\r")
		}
	case isError || isWarning:
		msg, err := c.expandMacro(rhs)
		if err != nil {
			return err
		}
		if isError {
			return fmt.Errorf("configuration error: %s", msg)
		}
		fmt.Fprintf(os.Stderr, "Configuration warning: %s\n", msg)
		return nil
	case isInclude:
		return c.applyInclude(line, nameEnd, pop, depth)
	case op == ':':
		// Colon assignment: accepted (with a warning in HTCondor), unless
		// #opt:strict.
		if *optMetaColon < 2 || asciiEqualFold(name, "RunBenchmarks") {
			op = '='
		} else {
			return bad("obsolete use of ':' for parameter assignment at %s : %s", name, rhs)
		}
	}

	// The name may contain macros; HTCondor expands it before using it.
	expName, err := c.expandMacro(name)
	if err != nil {
		return err
	}

	if isMeta {
		return c.readMetaConfig(depth+1, expName, rhs)
	}

	if !isValidParamName(expName) {
		return bad("illegal identifier: <%s>", expName)
	}
	if op == '@' {
		*hereName = expName
		*hereTag = rhs
		return nil
	}

	crhs := rhs
	if op == '+' {
		if cur, ok := c.lookupMacro(expName); ok && cur != "" {
			var b strings.Builder
			b.WriteString(cur)
			switch {
			case plusSep != 0 && doublePlus > 1:
				b.WriteByte(' ')
				b.WriteByte(plusSep)
				b.WriteByte(plusSep)
				b.WriteByte(' ')
			case plusSep != 0:
				b.WriteByte(plusSep)
			default:
				b.WriteByte(' ')
			}
			b.WriteString(rhs)
			crhs = b.String()
		}
	}
	value, err := c.expandSelfMacro(crhs, expName)
	if err != nil {
		return err
	}
	return c.insertMacro(expName, value)
}

// insertMacro is insert_macro: store a value, expanding references to the
// name itself against its previous value when it is already defined.
func (c *Config) insertMacro(name, value string) error {
	if _, ok := c.resolveKey(name); ok {
		v, err := c.expandSelfMacro(value, name)
		if err != nil {
			return err
		}
		value = v
	}
	c.putValue(name, value)
	return nil
}

// applyInclude handles `include [ifexist] [command [into file]] : source`.
// keywords are line[nameEnd:pop], the source follows the ':' at pop.
func (c *Config) applyInclude(line string, nameEnd, pop, depth int) error {
	if c.options.NoLocalAccess || c.options.NoInclude {
		return fmt.Errorf("include directives are not allowed here: this text is parsed without access to the local host")
	}
	ifExist, isCommand := false, false
	words := strings.Fields(line[nameEnd:pop])
	i := 0
	if i < len(words) && (words[i] == "ifexist" || words[i] == "ifexists") {
		ifExist = true
		i++
	}
	if i < len(words) {
		if words[i] != "output" && words[i] != "command" {
			return fmt.Errorf("config: unexpected keyword(s) '%s' after include", strings.Join(words, " "))
		}
		isCommand = true
		i++
		if i < len(words) && words[i] == "into" {
			return fmt.Errorf("config: 'include command into' is not supported")
		}
	}
	source := strings.TrimLeft(line[pop+1:], " \t\n\v\f\r")
	source, err := c.expandMacro(source)
	if err != nil {
		return err
	}
	if !c.options.HTCondorCompat {
		source = strings.Trim(source, `"`)
	}
	if depth+1 >= configMaxNestingDepth {
		return fmt.Errorf("config: includes nested too deep")
	}
	if !isCommand {
		if t := strings.TrimRight(source, " |"); t != source && strings.HasSuffix(strings.TrimRight(source, " "), "|") {
			source, isCommand = t, true
		}
	}
	if isCommand {
		err := c.includeCommand(source)
		if err != nil && ifExist {
			return nil
		}
		return err
	}
	return c.includeFile(source, ifExist)
}

// ifStack is ConfigIfStack: the yes/no state of the enclosing if blocks as
// bits, bit 0 being the top level.
type ifStack struct {
	state, estate, istate, top uint64
}

func newIfStack() ifStack { return ifStack{state: 1, top: 1} }

func (s *ifStack) enabled() bool {
	mask := s.top | (s.top - 1)
	return s.state&mask == mask
}
func (s *ifStack) insideIf() bool   { return s.top > 1 }
func (s *ifStack) insideElse() bool { return s.top > 1 && s.istate&s.top == 0 }

func (s *ifStack) beginIf(b bool) bool {
	s.top <<= 1
	s.istate |= s.top
	if b {
		s.state |= s.top
		s.estate |= s.top
	} else {
		s.state &^= s.top
		s.estate &^= s.top
	}
	return s.top != 0
}

func (s *ifStack) beginElse() bool {
	if s.istate&s.top == 0 {
		return false
	}
	s.istate &^= s.top
	if (s.estate|s.state)&s.top != 0 {
		s.state &^= s.top
	} else {
		s.state |= s.top
	}
	return s.top > 1
}

func (s *ifStack) beginElif(b bool) bool {
	if s.istate&s.top == 0 {
		return false
	}
	switch {
	case s.estate&s.top != 0:
		s.state &^= s.top
	case b:
		s.estate |= s.top
		s.state |= s.top
	default:
		s.state &^= s.top
	}
	return s.top > 1
}

func (s *ifStack) endIf() bool {
	s.istate &^= s.top
	s.top >>= 1
	if s.top == 0 {
		s.top, s.state = 1, 1
		s.istate, s.estate = 0, 0
		return false
	}
	return true
}

// keywordLine reports whether line starts with keyword (case-insensitively)
// followed by whitespace or the end of the line.
func keywordLine(line, keyword string) bool {
	n := len(keyword)
	return len(line) >= n && asciiEqualFold(line[:n], keyword) && (len(line) == n || cIsSpace(line[n]))
}

// lineIsIf is ConfigIfStack::line_is_if.
func (c *Config) lineIsIf(s *ifStack, line string) (bool, error) {
	switch {
	case keywordLine(line, "if"):
		expr := strings.TrimLeft(line[2:], " \t\n\v\f\r")
		b := s.enabled()
		if b {
			var err error
			if b, err = c.testIfExpression(expr); err != nil {
				return true, fmt.Errorf("%s is not a valid if condition because %w", expr, err)
			}
		}
		if !s.beginIf(b) {
			return true, errors.New("if nesting too deep")
		}
		return true, nil
	case keywordLine(line, "else"):
		if !s.beginElse() {
			if s.insideElse() {
				return true, errors.New("else is not allowed after else")
			}
			return true, errors.New("else without matching if")
		}
		return true, nil
	case keywordLine(line, "elif"):
		expr := strings.TrimLeft(line[4:], " \t\n\v\f\r")
		b := s.estate&s.top == 0 && s.state&(s.top-1) == s.top-1
		if b {
			var err error
			if b, err = c.testIfExpression(expr); err != nil {
				return true, fmt.Errorf("%s is not a valid elif condition because %w", expr, err)
			}
		}
		if !s.beginElif(b) {
			if s.insideElse() {
				return true, errors.New("elif is not allowed after else")
			}
			return true, errors.New("elif without matching if")
		}
		return true, nil
	case keywordLine(line, "endif"):
		if !s.endIf() {
			return true, errors.New("endif without matching if")
		}
		return true, nil
	}
	return false, nil
}

// testIfExpression is Test_config_if_expression. Outside HTCondorCompat
// mode, a condition HTCondor cannot evaluate goes to evaluateCondition.
func (c *Config) testIfExpression(expr string) (bool, error) {
	orig := expr
	expanded := false
	if strings.IndexByte(expr, '$') >= 0 {
		x, err := c.expandMacro(expr)
		if err != nil {
			return false, err
		}
		expr = strings.TrimRight(x, " \t\n\v\f\r")
		expanded = true
	}
	expr = strings.TrimLeft(expr, " \t\n\v\f\r")
	inverted := false
	if strings.HasPrefix(expr, "!") {
		inverted = true
		expr = strings.TrimLeft(expr[1:], " \t\n\v\f\r")
	}
	var value bool
	if expanded && expr == "" {
		value = false
	} else {
		v, err := c.evaluateConfigIf(expr)
		if err != nil {
			if c.options.HTCondorCompat {
				return false, err
			}
			return c.evaluateCondition(orig)
		}
		value = v
	}
	if inverted {
		return !value, nil
	}
	return value, nil
}

// if-expression characterizations (expr_character_t).
const (
	ciftEmpty = iota
	ciftNumber
	ciftBool
	ciftIdentifier
	ciftVersion
	ciftIfdef
	ciftMacro
	ciftComplex
)

// matchesLiteralIgnoreCase is matches_literal_ignore_case: ptr, less
// leading whitespace, is lit (lower case), followed by only whitespace (or,
// with noTrailingToken false, by a non-alphanumeric).
func matchesLiteralIgnoreCase(ptr, lit string, noTrailingToken bool) bool {
	i := 0
	for i < len(ptr) && cIsSpace(ptr[i]) {
		i++
	}
	for j := 0; j < len(lit); j++ {
		if i >= len(ptr) || ptr[i]|0x20 != lit[j] {
			return false
		}
		i++
	}
	if noTrailingToken {
		for i < len(ptr) && cIsSpace(ptr[i]) {
			i++
		}
		return i == len(ptr)
	}
	return i == len(ptr) || !cIsAlnum(ptr[i])
}

// characterizeIfExpression is Characterize_config_if_expression.
//
//nolint:gocyclo // a port of a classification table
func characterizeIfExpression(expr string, keywordCheck bool) int {
	p := 0
	for p < len(expr) && cIsSpace(expr[p]) {
		p++
	}
	if p == len(expr) {
		return ciftEmpty
	}
	begin := expr[p:]
	if expr[p] == '-' {
		p++
	}
	const (
		ctSpace = 0x01
		ctDigit = 0x02
		ctAlpha = 0x04
		ctIdent = 0x08
		ctCmp   = 0x10
		ctSum   = 0x20
		ctLogic = 0x40
		ctGroup = 0x80
		ctMoney = 0x100
		ctColon = 0x200
		ctOther = 0x400
		ctFloat = 0x1000
		ctMacro = 0x2000
	)
	set := 0
	at := func(i int) byte {
		if i < len(expr) {
			return expr[i]
		}
		return 0
	}
	for p < len(expr) {
		ch := expr[p]
		p++
		next := at(p)
		switch {
		case cIsDigit(ch):
			set |= ctDigit
		case ch == '.':
			if set == ctDigit || next == 0 || cIsDigit(next) {
				set |= ctFloat
			} else {
				set |= ctIdent
			}
		case ch == 'e' || ch == 'E':
			if set&^ctFloat == ctDigit {
				set |= ctFloat
			} else {
				set |= ctAlpha
			}
		case ch == '-' || ch == '+':
			if set != ctDigit|ctFloat {
				set |= ctSum
			}
		case cIsAlpha(ch):
			set |= ctAlpha
		case ch == '_' || ch == '/':
			set |= ctIdent
		case ch >= '<' && ch <= '>':
			set |= ctCmp
		case ch == '!' && next == '=':
			set |= ctCmp
		case ch == '$':
			set |= ctMoney
			if next == '(' {
				set |= ctMacro
			}
		case cIsSpace(ch):
			if next != 0 && !cIsSpace(next) {
				set |= ctSpace
			}
		case ch == '&' || ch == '|':
			set |= ctLogic
		case ch >= '{' && ch <= '}', ch == '(' || ch == ')', ch == '[' || ch == ']':
			set |= ctGroup
		case ch == ':':
			set |= ctColon
		default:
			set |= ctOther
		}
	}

	switch set {
	case 0:
		return ciftEmpty
	case ctDigit, ctDigit | ctFloat:
		return ciftNumber
	case ctAlpha:
		if matchesLiteralIgnoreCase(expr, "false", true) || matchesLiteralIgnoreCase(expr, "true", true) {
			return ciftBool
		}
		if keywordCheck {
			if matchesLiteralIgnoreCase(begin, "version", true) {
				return ciftVersion
			}
			if matchesLiteralIgnoreCase(begin, "defined", true) {
				return ciftIfdef
			}
		}
		return ciftIdentifier
	case ctAlpha | ctDigit, ctAlpha | ctDigit | ctFloat, ctAlpha | ctIdent, ctAlpha | ctIdent | ctDigit,
		ctAlpha | ctIdent | ctDigit | ctFloat:
		return ciftIdentifier
	case ctAlpha | ctSpace | ctCmp | ctDigit, ctAlpha | ctSpace | ctCmp | ctDigit | ctFloat:
		if keywordCheck && matchesLiteralIgnoreCase(begin, "version", false) {
			return ciftVersion
		}
		return ciftComplex
	case ctAlpha | ctSpace, ctAlpha | ctSpace | ctColon, ctAlpha | ctSpace | ctIdent,
		ctAlpha | ctSpace | ctIdent | ctColon, ctAlpha | ctSpace | ctDigit,
		ctAlpha | ctSpace | ctDigit | ctIdent, ctAlpha | ctSpace | ctDigit | ctFloat,
		ctAlpha | ctSpace | ctDigit | ctIdent | ctFloat:
		if keywordCheck && matchesLiteralIgnoreCase(begin, "defined", false) {
			return ciftIfdef
		}
		return ciftComplex
	}
	if set&ctMacro != 0 && set&^(ctMoney|ctIdent|ctAlpha|ctDigit|ctMacro|ctColon) == 0 {
		return ciftMacro
	}
	return ciftComplex
}

// isCruftyBool is is_crufty_bool: yes/t/no/f.
func isCruftyBool(expr string) (result, ok bool) {
	if matchesLiteralIgnoreCase(expr, "yes", true) || matchesLiteralIgnoreCase(expr, "t", true) {
		return true, true
	}
	if matchesLiteralIgnoreCase(expr, "no", true) || matchesLiteralIgnoreCase(expr, "f", true) {
		return false, true
	}
	return false, false
}

// evaluateConfigIf is Evaluate_config_if.
func (c *Config) evaluateConfigIf(expr string) (bool, error) {
	ec := characterizeIfExpression(expr, true)
	switch ec {
	case ciftNumber:
		v, _ := cStrtod(expr)
		return v < 0 || v > 0, nil
	case ciftBool:
		return matchesLiteralIgnoreCase(expr, "true", true), nil
	case ciftIdentifier:
		if r, ok := isCruftyBool(expr); ok {
			return r, nil
		}
	case ciftVersion:
		return evaluateIfVersion(expr)
	case ciftIfdef:
		return c.evaluateIfDefined(expr)
	}
	if ec == ciftComplex {
		return false, errors.New("complex conditionals are not supported")
	}
	return false, errors.New("expression is not a conditional")
}

func (c *Config) evaluateIfDefined(expr string) (bool, error) {
	ptr := strings.TrimLeft(expr[7:], " \t\n\v\f\r")
	if ptr == "" {
		return false, nil
	}
	switch ec := characterizeIfExpression(ptr, false); {
	case ec == ciftIdentifier:
		v, ok := c.lookupMacro(ptr)
		if !ok {
			if _, crufty := isCruftyBool(ptr); crufty {
				return true, nil
			}
			return false, nil
		}
		return v != "", nil
	case ec == ciftNumber || ec == ciftBool:
		return true, nil
	case len(ptr) >= 4 && asciiEqualFold(ptr[:4], "use "):
		meta := strings.TrimLeft(ptr[4:], " \t\n\v\f\r")
		result := false
		cat, knob, hasKnob := strings.Cut(meta, ":")
		if table := metaknobCategory(cat); table != nil {
			if !hasKnob || knob == "" {
				result = true
			} else if _, ok := table[asciiLower(knob)]; ok {
				result = true
			}
		}
		if strings.ContainsAny(meta, " \t\r") {
			return false, errors.New("defined use meta argument with internal spaces will never match")
		}
		return result, nil
	}
	return false, errors.New("defined argument must be param name, boolean, or number")
}

// evaluateIfVersion handles `version <op> x.y[.z]` against
// CondorVersionCompat, the HTCondor release this package tracks.
func evaluateIfVersion(expr string) (bool, error) {
	ptr := strings.TrimLeft(expr[7:], " \t\n\v\f\r")
	op := 0
	orEqual := false
	negated := strings.HasPrefix(ptr, "!")
	if negated {
		ptr = ptr[1:]
	}
	if ptr != "" && ptr[0] >= '<' && ptr[0] <= '>' {
		op = int(ptr[0]) - '='
		ptr = ptr[1:]
	}
	if ptr != "" && ptr[0] == '=' {
		orEqual = true
		ptr = ptr[1:]
	}
	ptr = strings.TrimLeft(ptr, " \t\n\v\f\r")
	if ptr != "" && (ptr[0] == 'v' || ptr[0] == 'V') {
		ptr = ptr[1:]
	}
	maj, minor, sub, n := scanVersion(ptr)
	if n < 2 || maj < 6 {
		return false, errors.New("the version literal is invalid")
	}
	mine := parseVersionTriple(CondorVersionCompat)
	if n < 3 {
		sub = mine[2]
	}
	other := [3]int{maj, minor, sub}
	diff := 0 // other compared to mine
	for i := 0; i < 3; i++ {
		if other[i] != mine[i] {
			if other[i] < mine[i] {
				diff = 1
			} else {
				diff = -1
			}
			break
		}
	}
	result := diff == op || (orEqual && diff == 0)
	if negated {
		result = !result
	}
	return result, nil
}

// scanVersion is sscanf(s, "%d.%d.%d"): it returns the fields it read.
func scanVersion(s string) (a, b, c, n int) {
	var vals [3]int
	for n < 3 {
		if n > 0 {
			if !strings.HasPrefix(s, ".") {
				break
			}
			s = s[1:]
		}
		v, used := cStrtoll(s)
		if used == 0 {
			break
		}
		vals[n] = int(v)
		s = s[used:]
		n++
	}
	return vals[0], vals[1], vals[2], n
}

func parseVersionTriple(v string) [3]int {
	a, b, c, _ := scanVersion(v)
	return [3]int{a, b, c}
}

// CondorVersionCompat is the HTCondor release whose configuration language
// this package implements; `if version ...` compares against it.
const CondorVersionCompat = "25.14.1"
