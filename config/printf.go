package config

// printf-format support for $INT(name,fmt), $REAL(name,fmt) and
// $STRING(name,fmt): HTCondor's validatePrintfFormat (printf_format.cpp) to
// decide whether a format is usable, and a C printf emulation to apply one
// that is. HTCondor formats with the C library's snprintf, so the output has
// to be C's, not fmt's: %G trims zeros, %a has an unpadded exponent, an int
// conversion without a length modifier sees only 32 bits, and so on.

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

type pft int

const (
	pftCrash   pft = -1
	pftNone    pft = 0
	pftInt     pft = 1
	pftFloat   pft = 2
	pftChar    pft = 3
	pftString  pft = 4
	pftPointer pft = 5
	pftValue   pft = 6
	pftRaw     pft = 7
	pftTime    pft = 8
	pftDate    pft = 9
)

const printfStarWidth = -42

// printfSpec is printf_fmt_info, plus where the conversion sits in the format.
type printfSpec struct {
	letter                            byte
	typ                               pft
	width, precision                  int
	short, long, longLong, longDouble int
	alt, pad, left, space, signed     bool
	start, end                        int // the conversion is fmt[start:end], '%' included
}

func (s *printfSpec) unsafe() bool {
	return s.typ == pftCrash || s.width == printfStarWidth || s.precision == printfStarWidth
}

// parsePrintfFormat is parsePrintfFormat: find and decode the first
// conversion at or after pos. ok is false when it runs out of input first.
//
//nolint:gocyclo // ported as one function, as in printf_format.cpp
func parsePrintfFormat(f string, pos int) (spec printfSpec, next int, ok bool) {
	p := pos
	for {
		if p >= len(f) {
			return spec, p, false
		}
		for p < len(f) && f[p] != '%' {
			p++
		}
		if p >= len(f) {
			return spec, p, false
		}
		start := p
		p++
		if p >= len(f) {
			return spec, p, false
		}
		spec = printfSpec{start: start}
		for p < len(f) && strings.IndexByte("#0- +'", f[p]) >= 0 {
			switch f[p] {
			case '#':
				spec.alt = true
			case '0':
				spec.pad = true
			case '-':
				spec.left = true
			case ' ':
				spec.space = true
			case '+':
				spec.signed = true
			}
			p++
		}
		if p < len(f) && f[p] == '*' {
			spec.width = printfStarWidth
		} else if p < len(f) && cIsDigit(f[p]) {
			spec.width, p = consumeInt(f, p)
		}
		if p >= len(f) {
			return spec, p, false
		}
		spec.precision = -1
		if f[p] == '.' {
			p++
			if p >= len(f) {
				return spec, p, false
			}
			if f[p] == '*' {
				spec.precision = printfStarWidth
			} else if cIsDigit(f[p]) {
				spec.precision, p = consumeInt(f, p)
			}
		}
		if p >= len(f) {
			return spec, p, false
		}
		for p < len(f) && strings.IndexByte("hlLqjzt", f[p]) >= 0 {
			switch f[p] {
			case 'h':
				spec.short++
			case 'l':
				if spec.long > 0 {
					spec.longLong = 1
				} else {
					spec.long = 1
				}
			case 'L':
				spec.longDouble = 1
			case 'q':
				spec.longLong = 1
			}
			p++
		}
		if p >= len(f) {
			return spec, p, false
		}
		spec.letter = f[p]
		p++
		spec.end = p
		switch spec.letter {
		case 'd', 'i', 'o', 'u', 'x', 'X':
			spec.typ = pftInt
		case 'e', 'E', 'f', 'F', 'g', 'G', 'a', 'A':
			spec.typ = pftFloat
		case 'c':
			spec.typ = pftChar
		case 's':
			spec.typ = pftString
		case 'p':
			spec.typ = pftPointer
		case 'n':
			spec.typ = pftCrash
		case 'C':
			spec.typ = pftChar
			spec.long = 1
		case 'S':
			spec.typ = pftString
			spec.long = 1
		case 'V', 'v':
			spec.typ = pftValue
		case 'r', 'R':
			spec.typ = pftRaw
		case 'T':
			spec.typ = pftTime
		case 'Y':
			spec.typ = pftDate
		case '%':
			continue // a literal '%': keep looking
		default:
			spec.typ = pftNone
			return spec, p, false
		}
		return spec, p, true
	}
}

func consumeInt(f string, p int) (int, int) {
	v := 0
	for p < len(f) && cIsDigit(f[p]) {
		if v <= math.MaxInt32 {
			v = v*10 + int(f[p]-'0')
		}
		p++
	}
	return v, p
}

// validatePrintfFormat is validatePrintfFormat (without extended types):
// 1 for a usable format, 0 for none or the wrong type, -1 for an unsafe one.
func validatePrintfFormat(f string, want pft) int {
	spec, next, ok := parsePrintfFormat(f, 0)
	if !ok {
		return 0
	}
	if spec.unsafe() {
		return -1
	}
	typeOK := spec.typ == want || spec.typ == pftPointer || (want == pftInt && spec.typ == pftChar)
	if _, _, more := parsePrintfFormat(f, next); more {
		return -1
	}
	if typeOK {
		return 1
	}
	return 0
}

// glibcSprintf formats one argument (int64, float64 or string) with a format
// HTCondor validated, as glibc's snprintf does. HTCondor's validation and
// glibc's parser read some formats differently (glibc takes one length
// modifier, so in "%zzA" the second 'z' is an unknown conversion), so the
// format is walked here the way glibc walks it. It fails with
// ErrHTCondorUndefined where glibc's output depends on more than the one
// argument HTCondor passes.
//
//nolint:gocyclo // a port of glibc's spec parsing
func glibcSprintf(f string, arg any, limit int) (string, error) {
	var b strings.Builder
	positional := false // set by an unknown conversion, as in glibc
	positionalStart := 0
	argUsed := false
	for i := 0; i < len(f); i++ {
		if f[i] != '%' {
			b.WriteByte(f[i])
			continue
		}
		spec := printfSpec{precision: -1}
		j := i + 1
		zero, i18n, group := false, false, false
		// "%N$": an explicit argument number, which switches glibc to its
		// positional path. HTCondor passes one argument, number 1.
		numbered := false
		if k := j; k < len(f) && cIsDigit(f[k]) {
			for k < len(f) && cIsDigit(f[k]) {
				k++
			}
			if k < len(f) && f[k] == '$' {
				if n, _ := consumeInt(f, j); n != 1 {
					return "", fmt.Errorf("%w: printf argument %%%d$ that HTCondor does not pass", ErrHTCondorUndefined, n)
				}
				if !positional {
					positionalStart = b.Len()
				}
				numbered, positional = true, true
				j = k + 1
			}
		}
	flags:
		for ; j < len(f); j++ {
			switch f[j] {
			case '#':
				spec.alt = true
			case '\'':
				group = true
			case '+':
				spec.signed = true
			case ' ':
				spec.space = true
			case '-':
				spec.left = true
			case '0':
				zero = true
			case 'I':
				i18n = true
			default:
				break flags
			}
		}
		spec.pad = zero && !spec.left
		if j < len(f) && f[j] == '*' {
			return "", fmt.Errorf("%w: '*' in a printf format reads an argument HTCondor does not pass", ErrHTCondorUndefined)
		}
		k := j
		for j < len(f) && cIsDigit(f[j]) {
			j++
		}
		if j > k {
			spec.width, _ = consumeInt(f, k)
		}
		if j < len(f) && f[j] == '.' {
			j++
			if j < len(f) && f[j] == '*' {
				return "", fmt.Errorf("%w: '*' in a printf format reads an argument HTCondor does not pass", ErrHTCondorUndefined)
			}
			k = j
			for j < len(f) && cIsDigit(f[j]) {
				j++
			}
			spec.precision, _ = consumeInt(f, k)
		}
		if spec.width > math.MaxInt32 || spec.precision > math.MaxInt32 {
			return "", fmt.Errorf("%w: printf width or precision overflows an int", ErrHTCondorUndefined)
		}
		if j < len(f) {
			switch f[j] {
			case 'h':
				spec.short = 1
				j++
				if j < len(f) && f[j] == 'h' {
					spec.short = 2
					j++
				}
			case 'l':
				spec.long = 1
				j++
				if j < len(f) && f[j] == 'l' {
					spec.longLong = 1
					spec.longDouble = 1
					j++
				}
			case 'L', 'q':
				spec.longLong = 1
				spec.longDouble = 1
				j++
			case 'z', 'Z', 't', 'j':
				spec.long = 1
				j++
			case 'w':
				// glibc's %wN / %wfN modifier, N one of 8, 16, 32, 64.
				k := j + 1
				if k < len(f) && f[k] == 'f' {
					k++
				}
				m := k
				for m < len(f) && cIsDigit(f[m]) {
					m++
				}
				if n, _ := consumeInt(f, k); m > k && (n == 8 || n == 16 || n == 32 || n == 64) {
					spec.long = 1
					j = m
					break
				}
				// An invalid N fails the call. On the positional path
				// glibc parsed everything from the first unknown
				// conversion before printing any of it, so that part is
				// lost too.
				out := b.String()
				if positional {
					out = out[:positionalStart]
				}
				return out, nil
			}
		}
		var c byte
		if j < len(f) {
			c = f[j]
		}
		switch {
		case c == '%':
			b.WriteByte('%')
		case c != 0 && strings.IndexByte("diouxXeEfFgGaAcsSCpnmbB", c) >= 0:
			if argUsed && !numbered {
				return "", fmt.Errorf("%w: a second printf conversion reads an argument HTCondor does not pass", ErrHTCondorUndefined)
			}
			argUsed = true
			spec.letter = c
			if i18n {
				return "", fmt.Errorf("%w: printf 'I' flag (locale digits)", ErrHTCondorUndefined)
			}
			// glibc's fast path takes a single 'h' only before an integer
			// conversion; anything else moves it to the positional path.
			if spec.short == 1 && strings.IndexByte("diouxXn", c) < 0 && !positional {
				positionalStart = b.Len()
				positional = true
			}
			// A width or precision past the output HTCondor keeps changes
			// nothing in it; capping them keeps a "%999999999d" from
			// allocating a gigabyte. Beyond maxExpandLen the value is too
			// large to keep at all.
			if spec.width > limit+maxPrintfSlack || spec.precision > limit+maxPrintfSlack ||
				spec.width < 0 || spec.precision < -1 {
				if limit >= maxExpandLen {
					return "", ErrMacroLoop
				}
				spec.width = min(max(spec.width, 0), limit+maxPrintfSlack)
				spec.precision = min(spec.precision, limit+maxPrintfSlack)
			}
			out, err := glibcConvert(spec, arg)
			if err != nil {
				return "", err
			}
			b.WriteString(out)
		case c == 0 && !positional:
			return b.String(), nil // the format ended inside a spec: glibc stops here
		default:
			// printf_unknown
			if !positional {
				positionalStart = b.Len()
			}
			b.WriteByte('%')
			if spec.alt {
				b.WriteByte('#')
			}
			if group {
				b.WriteByte('\'')
			}
			if spec.signed {
				b.WriteByte('+')
			} else if spec.space {
				b.WriteByte(' ')
			}
			if spec.left {
				b.WriteByte('-')
			}
			if spec.pad {
				b.WriteByte('0')
			}
			if i18n {
				b.WriteByte('I')
			}
			if spec.width != 0 {
				b.WriteString(strconv.Itoa(spec.width))
			}
			if spec.precision != -1 {
				b.WriteByte('.')
				b.WriteString(strconv.Itoa(spec.precision))
			}
			if c != 0 {
				b.WriteByte(c)
			}
			positional = true
		}
		if c == 0 {
			break
		}
		i = j
	}
	return b.String(), nil
}

// glibcConvert is one conversion of the single argument.
func glibcConvert(s printfSpec, arg any) (string, error) {
	undefined := func() (string, error) {
		return "", fmt.Errorf("%w: printf %%%c of the value HTCondor passes", ErrHTCondorUndefined, s.letter)
	}
	switch v := arg.(type) {
	case int64:
		switch s.letter {
		case 'd', 'i', 'o', 'u', 'x', 'X', 'p':
			return formatCInt(s, v), nil
		case 'c':
			if s.long > 0 && (v < 0 || v > 127) {
				return undefined()
			}
			return formatCInt(s, v), nil
		case 'C':
			if v < 0 || v > 127 {
				return undefined()
			}
			return formatCInt(s, v), nil
		}
	case float64:
		switch s.letter {
		case 'e', 'E', 'f', 'F', 'g', 'G', 'a', 'A':
			if s.longDouble > 0 {
				return undefined()
			}
			return formatCFloat(s, v), nil
		}
	case string:
		if s.letter == 's' && s.long == 0 {
			if s.precision >= 0 && s.precision < len(v) {
				v = v[:s.precision]
			}
			return pad(s, v, false), nil
		}
	}
	return undefined()
}

// maxPrintfSlack is how far past the kept output a capped width or precision
// reaches, so that rounding at the last digit kept is still computed.
const maxPrintfSlack = 1000

// $INT and $REAL keep 55 bytes of output; $STRING keeps all of it.
func cSprintfInt(f string, v int64) (string, error)     { return glibcSprintf(f, v, 55) }
func cSprintfFloat(f string, v float64) (string, error) { return glibcSprintf(f, v, 55) }
func cSprintfString(f string, v string) (string, error) { return glibcSprintf(f, v, maxExpandLen) }

// pad applies width and the '-' flag; zero-padding is the caller's business.
func pad(s printfSpec, body string, _ bool) string {
	if s.width > len(body) {
		fill := strings.Repeat(" ", s.width-len(body))
		if s.left {
			return body + fill
		}
		return fill + body
	}
	return body
}

// padNumber pads a number made of sign prefix + digits, honoring '0'.
func padNumber(s printfSpec, prefix, digits string, zeroOK bool) string {
	n := len(prefix) + len(digits)
	if s.width > n {
		if s.left {
			return prefix + digits + strings.Repeat(" ", s.width-n)
		}
		if s.pad && zeroOK {
			return prefix + strings.Repeat("0", s.width-n) + digits
		}
		return strings.Repeat(" ", s.width-n) + prefix + digits
	}
	return prefix + digits
}

// formatCInt is one integer conversion. The narrowing conversions are the
// point: they are what va_arg does for the length modifier.
//
//nolint:gocyclo,gosec // a C conversion table; the integer narrowing is deliberate
func formatCInt(s printfSpec, v int64) string {
	switch s.letter {
	case 'c', 'C':
		return pad(s, string([]byte{byte(v)}), false)
	case 'p':
		if v == 0 {
			return pad(s, "(nil)", false)
		}
		// glibc prints a pointer as %#lx, keeping the sign flags.
		prefix := "0x"
		switch {
		case s.signed:
			prefix = "+0x"
		case s.space:
			prefix = " 0x"
		}
		digits := strconv.FormatUint(uint64(v), 16)
		if s.precision >= 0 && len(digits) < s.precision {
			digits = strings.Repeat("0", s.precision-len(digits)) + digits
		}
		return padNumber(s, prefix, digits, s.precision < 0)
	}
	// Narrow the argument the way va_arg does for the length modifier.
	wide := s.long > 0 || s.longLong > 0 || s.longDouble > 0
	signedConv := s.letter == 'd' || s.letter == 'i'
	var u uint64
	neg := false
	switch {
	case wide:
		if signedConv && v < 0 {
			neg, u = true, uint64(-v)
		} else {
			u = uint64(v)
		}
	case s.short >= 2:
		if signedConv {
			x := int8(v)
			if x < 0 {
				neg, u = true, uint64(-int64(x))
			} else {
				u = uint64(x)
			}
		} else {
			u = uint64(uint8(v))
		}
	case s.short == 1:
		if signedConv {
			x := int16(v)
			if x < 0 {
				neg, u = true, uint64(-int64(x))
			} else {
				u = uint64(x)
			}
		} else {
			u = uint64(uint16(v))
		}
	default:
		if signedConv {
			x := int32(v)
			if x < 0 {
				neg, u = true, uint64(-int64(x))
			} else {
				u = uint64(x)
			}
		} else {
			u = uint64(uint32(v))
		}
	}
	var digits string
	switch s.letter {
	case 'o':
		digits = strconv.FormatUint(u, 8)
	case 'x':
		digits = strconv.FormatUint(u, 16)
	case 'X':
		digits = strings.ToUpper(strconv.FormatUint(u, 16))
	default:
		digits = strconv.FormatUint(u, 10)
	}
	if s.precision >= 0 {
		if s.precision == 0 && u == 0 {
			digits = ""
		}
		if len(digits) < s.precision {
			digits = strings.Repeat("0", s.precision-len(digits)) + digits
		}
	}
	prefix := ""
	switch {
	case neg:
		prefix = "-"
	case signedConv && s.signed:
		prefix = "+"
	case signedConv && s.space:
		prefix = " "
	}
	if s.alt {
		switch s.letter {
		case 'o':
			if !strings.HasPrefix(digits, "0") {
				digits = "0" + digits
			}
		case 'x':
			if u != 0 {
				prefix += "0x"
			}
		case 'X':
			if u != 0 {
				prefix += "0X"
			}
		}
	}
	return padNumber(s, prefix, digits, s.precision < 0)
}

func formatCFloat(s printfSpec, v float64) string {
	if s.letter == 'p' {
		return pad(s, "(nil)", false)
	}
	upper := s.letter == 'E' || s.letter == 'F' || s.letter == 'G' || s.letter == 'A'
	prefix := ""
	switch {
	case math.Signbit(v):
		prefix = "-"
		v = -v
	case s.signed:
		prefix = "+"
	case s.space:
		prefix = " "
	}
	if math.IsInf(v, 0) || math.IsNaN(v) {
		body := "inf"
		if math.IsNaN(v) {
			body = "nan"
		}
		if upper {
			body = strings.ToUpper(body)
		}
		return padNumber(s, prefix, body, false)
	}
	prec := s.precision
	var body string
	switch s.letter | 0x20 {
	case 'f':
		if prec < 0 {
			prec = 6
		}
		body = strconv.FormatFloat(v, 'f', prec, 64)
		if s.alt && prec == 0 {
			body += "."
		}
	case 'e':
		if prec < 0 {
			prec = 6
		}
		body = strconv.FormatFloat(v, 'e', prec, 64)
		if s.alt && prec == 0 {
			body = strings.Replace(body, "e", ".e", 1)
		}
	case 'g':
		body = formatCG(v, prec, s.alt)
	case 'a':
		body = formatCA(v, prec, s.alt)
	}
	if upper {
		body = strings.ToUpper(body)
	}
	if s.letter|0x20 == 'a' && len(body) > 2 {
		// zero padding goes after the 0x
		prefix += body[:2]
		body = body[2:]
	}
	return padNumber(s, prefix, body, true)
}

// formatCG is C's %g for a non-negative finite v.
func formatCG(v float64, prec int, alt bool) string {
	if prec < 0 {
		prec = 6
	}
	if prec == 0 {
		prec = 1
	}
	exp := 0
	if v != 0 {
		e := strconv.FormatFloat(v, 'e', prec-1, 64)
		exp, _ = strconv.Atoi(e[strings.IndexByte(e, 'e')+1:])
	}
	var out string
	if prec > exp && exp >= -4 {
		out = strconv.FormatFloat(v, 'f', prec-1-exp, 64)
	} else {
		out = strconv.FormatFloat(v, 'e', prec-1, 64)
	}
	if alt {
		if !strings.Contains(out, ".") {
			if i := strings.IndexByte(out, 'e'); i >= 0 {
				out = out[:i] + "." + out[i:]
			} else {
				out += "."
			}
		}
		return out
	}
	mant, expPart := out, ""
	if i := strings.IndexByte(out, 'e'); i >= 0 {
		mant, expPart = out[:i], out[i:]
	}
	if strings.Contains(mant, ".") {
		mant = strings.TrimRight(mant, "0")
		mant = strings.TrimSuffix(mant, ".")
	}
	return mant + expPart
}

// formatCA is glibc's %a for a non-negative finite v: the leading digit is
// the implicit bit (0 for zero and subnormals), the fraction is rounded to
// prec hex digits half-to-even, and a carry makes the leading digit 2
// rather than renormalizing.
func formatCA(v float64, prec int, alt bool) string {
	bits := math.Float64bits(v)
	e := int((bits >> 52) & 0x7ff)
	m := bits & (1<<52 - 1)
	lead := uint64(1)
	exp := e - 1023
	switch {
	case v == 0:
		lead, exp = 0, 0
	case e == 0:
		lead, exp = 0, -1022
	}
	var digits string
	switch {
	case prec < 0:
		digits = strings.TrimRight(fmt.Sprintf("%013x", m), "0")
	case prec < 13:
		shift := uint(52 - 4*prec)
		keep := lead<<(4*uint(prec)) | m>>shift
		rem := m & (1<<shift - 1)
		half := uint64(1) << (shift - 1)
		if rem > half || (rem == half && keep&1 == 1) {
			keep++
		}
		lead = keep >> (4 * uint(prec))
		if prec > 0 {
			digits = fmt.Sprintf("%0*x", prec, keep&(1<<(4*uint(prec))-1))
		}
	default:
		digits = fmt.Sprintf("%013x", m) + strings.Repeat("0", prec-13)
	}
	var b strings.Builder
	b.WriteString("0x")
	b.WriteString(strconv.FormatUint(lead, 16))
	if digits != "" || alt {
		b.WriteByte('.')
		b.WriteString(digits)
	}
	b.WriteByte('p')
	if exp >= 0 {
		b.WriteByte('+')
	}
	b.WriteString(strconv.Itoa(exp))
	return b.String()
}
