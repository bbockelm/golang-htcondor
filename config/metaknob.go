package config

// Metaknobs (`use CATEGORY : Knob(args), ...`), ported from HTCondor's
// config.cpp (v25.14.1): read_meta_config, MetaKnobAndArgs, expand_meta_args
// and Parse_config_string, the parser HTCondor runs a metaknob's body
// through. The bodies themselves are the $CATEGORY.Knob entries of the
// vendored param_info table, looked up there directly, so `use` works the
// same with or without SkipDefaults.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	metaknobOnce   sync.Once
	metaknobTables map[string]map[string]string // category -> knob -> body, lower-cased keys
)

// metaknobCategory returns the knobs of a metaknob category (param_meta_table),
// or nil. Matching ignores case and anything from a ':' on.
func metaknobCategory(category string) map[string]string {
	metaknobOnce.Do(func() {
		metaknobTables = make(map[string]map[string]string)
		for _, pd := range paramDefaults {
			if !strings.HasPrefix(pd.Name, "$") {
				continue
			}
			cat, knob, ok := strings.Cut(pd.Name[1:], ".")
			if !ok {
				continue
			}
			cat = asciiLower(cat)
			if metaknobTables[cat] == nil {
				metaknobTables[cat] = make(map[string]string)
			}
			metaknobTables[cat][asciiLower(knob)] = pd.Default
		}
	})
	if i := strings.IndexByte(category, ':'); i >= 0 {
		category = category[:i]
	}
	return metaknobTables[asciiLower(category)]
}

// readMetaConfig is read_meta_config: apply each `Knob(args)` of rhs from
// the named category.
func (c *Config) readMetaConfig(depth int, name, rhs string) error {
	if name == "" {
		return fmt.Errorf("use needs a keyword before : %s", rhs)
	}
	table := metaknobCategory(name)
	if table == nil {
		return fmt.Errorf("use %s: unknown metaknob category", name)
	}
	knob, args := "", ""
	remain := rhs
	for remain != "" {
		next := metaKnobAndArgs(remain, &knob, &args)
		if len(next) == len(remain) {
			break
		}
		remain = next
		body, ok := table[asciiLower(knob)]
		if !ok {
			return fmt.Errorf("use %s: does not recognise %s", name, knob)
		}
		if args != "" || hasMetaArgs(body) {
			x, err := expandMetaArgs(body, args)
			if err != nil {
				return err
			}
			body = x
		}
		if err := c.parseConfigString(body, depth); err != nil {
			return fmt.Errorf("use %s: %s is invalid: %w", name, knob, err)
		}
	}
	return nil
}

// metaKnobAndArgs is MetaKnobAndArgs::init_from_string: read one knob name
// and its optional (args) from p, returning the rest. As in HTCondor, knob
// and args keep their previous values when p holds no new ones.
func metaKnobAndArgs(p string, knob, args *string) string {
	i := 0
	for i < len(p) && (cIsSpace(p[i]) || p[i] == ',') {
		i++
	}
	e := i
	for e < len(p) && !cIsSpace(p[e]) && p[e] != ',' && p[e] != '(' {
		e++
	}
	if e == i {
		return p[e:]
	}
	*knob = p[i:e]
	i = e
	for i < len(p) && cIsSpace(p[i]) {
		i++
	}
	if i < len(p) && p[i] == '(' {
		if end, ok := findCloseBrace(p, i, 25, "(["); ok && p[end] == ')' {
			*args = p[i+1 : end]
			i = end
		}
		i++
		for i < len(p) && cIsSpace(p[i]) {
			i++
		}
	}
	if i > len(p) {
		i = len(p)
	}
	return p[i:]
}

// findCloseBrace is find_close_brace: the index of the bracket closing the
// one at open, recursing into the brackets in recurseSet.
func findCloseBrace(s string, open, depth int, recurseSet string) (int, bool) {
	if depth < 0 || open >= len(s) {
		return 0, false
	}
	openCh := s[open]
	closeCh := openCh
	switch openCh {
	case '(':
		closeCh = ')'
	case '[':
		closeCh = ']'
	case '{':
		closeCh = '}'
	case '<':
		closeCh = '>'
	}
	p := open
	for {
		p++
		if p >= len(s) {
			return 0, false
		}
		if s[p] == closeCh {
			return p, true
		}
		if s[p] == openCh || strings.IndexByte(recurseSet, s[p]) >= 0 {
			e, ok := findCloseBrace(s, p, depth-1, recurseSet)
			if !ok {
				return 0, false
			}
			p = e
		}
	}
}

// hasMetaArgs is has_meta_args: does value hold a $(<digit>...) reference?
func hasMetaArgs(value string) bool {
	for i := strings.Index(value, "$("); i >= 0; {
		if i+2 < len(value) && cIsDigit(value[i+2]) {
			return true
		}
		j := strings.Index(value[i+2:], "$(")
		if j < 0 {
			return false
		}
		i += 2 + j
	}
	return false
}

// tokenIter is StringTokenIterator with trimming: tokens separated by any of
// delims, whitespace trimmed, empty tokens skipped.
type tokenIter struct {
	s, delims string
	next      int
}

func (it *tokenIter) token() (string, bool) {
	i := it.next
	for i < len(it.s) && (strings.IndexByte(it.delims, it.s[i]) >= 0 || cIsSpace(it.s[i])) {
		i++
	}
	it.next = i
	end := i
	for i < len(it.s) && strings.IndexByte(it.delims, it.s[i]) < 0 {
		if !cIsSpace(it.s[i]) {
			end = i
		}
		i++
	}
	if i <= it.next {
		return "", false
	}
	start := it.next
	it.next = i
	return it.s[start : end+1], true
}

func (it *tokenIter) remain() (string, bool) {
	if it.next >= len(it.s) {
		return "", false
	}
	return it.s[it.next:], true
}

// trimC trims C whitespace from both ends (trimmed_cstr).
func trimC(s string) string {
	i, j := 0, len(s)
	for i < j && cIsSpace(s[i]) {
		i++
	}
	for j > i && cIsSpace(s[j-1]) {
		j--
	}
	return s[i:j]
}

// expandMetaArgs is expand_meta_args: replace $(N), $(N?), $(N#), $(N+) and
// their :default forms in a metaknob body with the comma-separated args.
func expandMetaArgs(value, argstr string) (string, error) {
	skip := func(id int, body string) bool {
		return id != macroNormal || body == "" || !cIsDigit(body[0])
	}
	tmp := value
	for steps := 0; ; steps++ {
		if steps > maxExpandSteps || len(tmp) > maxExpandLen {
			return "", ErrMacroLoop
		}
		pos := nextConfigMacro(tmp, isMetaArgMacro, skip)
		if pos.id == macroNone {
			return tmp, nil
		}
		body := pos.body(tmp)
		index, used := cStrtoll(body)
		pend := used
		emptyCheck, numArgs := false, false
		colon := 0
		if pend < len(body) && body[pend] == '?' {
			pend++
			emptyCheck = true
		} else if pend < len(body) && (body[pend] == '#' || body[pend] == '+') {
			pend++
			numArgs = true
		}
		if pend < len(body) && body[pend] == ':' {
			colon = pend + 1
		}

		it := &tokenIter{s: argstr, delims: ","}
		buf := ""
		if index <= 0 {
			if numArgs {
				n := 0
				for _, ok := it.token(); ok; _, ok = it.token() {
					n++
				}
				buf = fmt.Sprintf("%d", n)
			} else {
				buf = argstr
			}
		} else {
			ix := int64(1)
			if numArgs {
				remain, ok := it.remain()
				for ok && ix < index {
					ix++
					it.token()
					remain, ok = it.remain()
				}
				if ok {
					buf = strings.TrimPrefix(remain, ",")
				}
				if colon != 0 && buf == "" {
					buf = body[colon:]
				}
			} else {
				tok, ok := it.token()
				for ok && ix < index {
					ix++
					tok, ok = it.token()
				}
				if ok {
					buf = tok
				} else if colon != 0 {
					buf = body[colon:]
				}
			}
		}
		tv := trimC(buf)
		if emptyCheck {
			if tv != "" {
				tv = "1"
			} else {
				tv = "0"
			}
		}
		tmp = tmp[:pos.dollar] + tv + tmp[pos.bodyEnd+1:]
	}
}

// parseConfigString is Parse_config_string: the parser for metaknob bodies.
// It differs from the file reader: lines are not continued, whitespace alone
// can be the operator, and `use ` is recognized by its prefix.
//
//nolint:gocyclo // ported as one function, as in config.cpp
func (c *Config) parseConfigString(config string, depth int) error {
	ifs := newIfStack()
	hereName, hereTag := "", ""
	var hereData strings.Builder
	errInvalid := errors.New("invalid metaknob line")

	it := &tokenIter{s: config, delims: "\n"}
	for line, ok := it.token(); ok; line, ok = it.token() {
		if line[0] == '#' || blankLine(line) {
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
		if isIf, err := c.lineIsIf(&ifs, line); isIf {
			if err != nil {
				return err
			}
			continue
		}
		if !ifs.enabled() {
			continue
		}

		ptr := 0
		isMeta := len(line) >= 4 && asciiEqualFold(line[:4], "use ")
		if isMeta {
			ptr = 4
			for ptr < len(line) && cIsSpace(line[ptr]) {
				ptr++
			}
		}
		nameStart, nameEnd := ptr, -1
		var op byte
		pop := ptr
		for ptr < len(line) {
			if cIsSpace(line[ptr]) || line[ptr] == '=' || line[ptr] == ':' {
				pop, op, nameEnd = ptr, line[ptr], ptr
				ptr++
				break
			}
			ptr++
		}
		if nameEnd < 0 {
			nameEnd = ptr
		}
		var plusSep byte
		doublePlus := 0
		isOp := func(b byte) bool { return b == '=' || b == ':' }
	scan:
		for ptr < len(line) {
			ch := line[ptr]
			switch {
			case ch == '@':
				if ptr+1 >= len(line) || line[ptr+1] != '=' {
					op = 0
					break scan
				}
				pop, op = ptr, '@'
				ptr++
			case ch == '+':
				ix := 1
				if ptr+ix < len(line) && strings.IndexByte(",;|&*", line[ptr+ix]) >= 0 {
					plusSep = line[ptr+ix]
					ix++
					doublePlus = 1
					if ptr+ix < len(line) && line[ptr+ix] == plusSep {
						ix++
						doublePlus = 2
					}
				}
				if ptr+ix >= len(line) || line[ptr+ix] != '=' {
					op = 0
					break scan
				}
				pop, op = ptr, '+'
				ptr += ix
			case isOp(ch):
				if isOp(op) {
					op = 0
					break scan
				}
				pop, op = ptr, ch
			case !cIsSpace(ch):
				break scan
			}
			ptr++
		}
		if ptr >= len(line) && !isOp(op) {
			return errInvalid
		}
		for ptr < len(line) && cIsSpace(line[ptr]) {
			ptr++
		}
		rhs := ""
		if ptr < len(line) {
			rhs = line[ptr:]
		}
		name := line[nameStart:nameEnd]

		if op == ':' {
			isErr := asciiEqualFold(name, "error")
			if isErr || asciiEqualFold(name, "warning") {
				msg, err := c.expandMacro(rhs)
				if err != nil {
					return err
				}
				if isErr {
					return fmt.Errorf("configuration error: %s", msg)
				}
				fmt.Fprintf(os.Stderr, "Configuration warning: %s\n", msg)
			}
		}
		_ = pop

		if isMeta {
			if depth >= configMaxNestingDepth {
				return errors.New("metaknob nesting too deep")
			}
			if err := c.readMetaConfig(depth+1, name, rhs); err != nil {
				return err
			}
			continue
		}
		if !isValidParamName(name) {
			return errInvalid
		}
		if op == '@' {
			hereName, hereTag = name, rhs
			hereData.Reset()
			continue
		}
		if op == '+' {
			if cur, ok := c.lookupMacro(name); ok && cur != "" {
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
				rhs = b.String()
			}
		}
		value, err := c.expandSelfMacro(rhs, name)
		if err != nil {
			return err
		}
		if err := c.insertMacro(name, value); err != nil {
			return err
		}
	}
	return nil
}
