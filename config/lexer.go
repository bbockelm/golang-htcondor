package config

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"unicode"
)

var keywords = map[string]int{
	"if":       IF,
	"elif":     ELIF,
	"else":     ELSE,
	"endif":    ENDIF,
	"defined":  DEFINED,
	"version":  VERSION,
	"include":  INCLUDE,
	"use":      USE,
	"true":     TRUE,
	"false":    FALSE,
	"yes":      YES,
	"no":       NO,
	"error":    ERROR,
	"warning":  WARNING,
	"ifexist":  IFEXIST,
	"command":  COMMAND,
	"into":     INTO,
	"queue":    QUEUE,
	"from":     FROM,
	"in":       IN,
	"matching": MATCHING,
}

// TokenInfo represents a token with its value and position
type TokenInfo struct {
	Token int
	Lit   string
	Line  int
	Col   int

	// Items carries the already-split members of a queue statement's
	// parenthesised item list, and is set only on an ITEMS token. The
	// split happens in the lexer because HTCondor's rules for it are
	// character-level rather than token-level: the list runs to the last
	// ')' on the line, a ')' anywhere else is an ordinary character, and
	// quotes are not special.
	Items []string
}

// Lexer tokenizes HTCondor configuration input
type Lexer struct {
	input               *bufio.Reader
	line                int
	col                 int
	ch                  rune
	nextCh              rune
	buf                 strings.Builder
	atEOF               bool
	afterUse            bool // True if the previous token was USE
	afterIfOrElif       bool // True if the previous token was IF or ELIF
	afterErrorOrWarning bool // True if the previous token was ERROR or WARNING

	// badMacroRef is set when a $(...) inside a parameter name ran to
	// the end of the line unterminated, so the token can be reported as
	// illegal on that line rather than confusing the next statement.
	badMacroRef bool

	// inInclude is true while lexing an include directive's type keywords
	// (INCLUDE, and any continuation COMMAND/IFEXIST) up to its ':'. It lets the
	// ':' know it terminates an include type, so the path/command that follows is
	// read as the rest of the line. afterIncludeColon carries that across to the
	// next token: an include path or command is unquoted in HTCondor
	// (`include command : /usr/bin/foo -a -b`), not an IDENT/STRING.
	inInclude         bool
	afterIncludeColon bool

	// stmtStart is true when the next token begins a new statement (line).
	// prevIdentAssignable is true when the immediately preceding token was a
	// statement-start plain identifier — i.e. an assignment target — so a
	// following ':' is an assignment operator ("C : val" == "C = val"), matching
	// HTCondor. Keywords (use/include/if/...) are not plain identifiers, so
	// their ':' (e.g. `include : file`) stays a COLON.
	stmtStart           bool
	prevIdentAssignable bool

	// afterPlus is true for the token right after a '+', the attribute name
	// of submit's `+Attr = expr`. HTCondor reads that name with the same
	// scan it uses for a parameter name, so it gets the same charset here;
	// see readParamName.
	afterPlus bool

	// inQueue is true from the QUEUE keyword to the end of its line. It
	// scopes the item-list handling below to queue statements, so the
	// `in`/`from` keywords keep their ordinary meaning elsewhere.
	inQueue bool
	// queueItems is set when an `in` or `from` keyword was just lexed
	// inside a queue statement, so the next token may be an item list.
	queueItems queueItemsMode
}

// queueItemsMode says which foreach keyword introduced an item list, which
// decides how the list's text is split: `in` splits every line into tokens,
// `from` takes each line whole.
type queueItemsMode int

const (
	queueItemsNone queueItemsMode = iota
	queueItemsIn
	queueItemsFrom
)

// NewLexer creates a new lexer
func NewLexer(r io.Reader) *Lexer {
	l := &Lexer{
		input:     bufio.NewReader(r),
		line:      1,
		col:       0,
		stmtStart: true, // the first token begins a statement
	}
	l.readChar()
	l.readChar() // Initialize both ch and nextCh
	return l
}

// readChar reads the next character
func (l *Lexer) readChar() {
	l.ch = l.nextCh

	if l.atEOF {
		l.nextCh = 0
		return
	}

	r, _, err := l.input.ReadRune()
	if errors.Is(err, io.EOF) {
		l.atEOF = true
		l.nextCh = 0
		return
	}

	l.nextCh = r
	l.col++

	if l.ch == '\n' {
		l.line++
		l.col = 0
	}
}

// peekChar returns the next character without advancing
func (l *Lexer) peekChar() rune {
	return l.nextCh
}

// peekNextNonWhitespace looks ahead through any run of space/tab/CR
// to find the next significant character. Used by NextToken to
// distinguish `error = value` (assignment) from `error message`
// (directive). Newline ends the lookahead — there is no
// continuation past the line.
//
// Implementation: bufio.Reader.Peek is non-consuming, so we ask for
// a generous window (capped at the buffer size) and walk it. The
// previous implementation peeked only 10 bytes, which silently
// misclassified column-aligned submit descriptions like
// `error               = file` as ERROR directives.
func (l *Lexer) peekNextNonWhitespace() rune {
	switch l.nextCh {
	case '=', ':':
		return l.nextCh
	case ' ', '\t', '\r':
		// fall through to the lookahead below
	default:
		return l.nextCh
	}

	// bufio.Reader.Peek tops out at the reader's buffer size. The
	// default size for NewLexer's bufio.NewReader is 4096 bytes,
	// which is plenty for whitespace runs in any realistic config
	// or submit file. If a caller wires a smaller buffer, Peek
	// returns ErrBufferFull along with whatever it could fit —
	// still useful, so we don't check err.
	const maxPeek = 4096
	peekBytes, _ := l.input.Peek(maxPeek)
	for _, b := range peekBytes {
		switch b {
		case ' ', '\t', '\r':
			continue
		case '\n':
			// End of line before any non-whitespace. Return the
			// newline so the caller treats the keyword as a
			// directive with empty payload, matching legacy
			// behavior for a bare `error\n` line.
			return '\n'
		default:
			return rune(b)
		}
	}
	// Whitespace all the way to EOF (or to the end of what we
	// could see). Report the immediate whitespace; caller treats
	// the keyword as a directive, which is the safe default.
	return l.nextCh
}

// skipWhitespace skips whitespace characters
func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\r' {
		l.readChar()
	}
}

// skipToEndOfLine skips to the end of the current line
func (l *Lexer) skipToEndOfLine() {
	for l.ch != '\n' && l.ch != 0 {
		l.readChar()
	}
}

// readIdentifier reads an identifier or keyword
func (l *Lexer) readIdentifier() string {
	l.buf.Reset()

	// First character (letter, underscore, or subsystem prefix with dot)
	for isIdentStart(l.ch) || l.ch == '.' {
		l.buf.WriteRune(l.ch)
		l.readChar()

		// After a dot, continue reading the identifier
		if l.buf.Len() > 0 && l.buf.String()[l.buf.Len()-1] == '.' {
			continue
		}

		// Regular identifier characters, plus any $(...) macro
		// references embedded in the name.
		for {
			if isIdentChar(l.ch) {
				l.buf.WriteRune(l.ch)
				l.readChar()
				continue
			}
			if l.ch == '$' && l.peekChar() == '(' {
				if !l.readMacroRefInto(&l.buf) {
					l.badMacroRef = true
					return l.buf.String()
				}
				continue
			}
			break
		}

		// Check for another dot (subsystem.local.param)
		if l.ch == '.' {
			continue
		}

		break
	}

	return l.buf.String()
}

// readString reads a quoted string
func (l *Lexer) readString(quote rune) string {
	l.buf.Reset()
	l.readChar() // Skip opening quote

	for l.ch != quote && l.ch != 0 && l.ch != '\n' {
		if l.ch == '\\' {
			l.readChar()
			// Handle escape sequences
			switch l.ch {
			case 'n':
				l.buf.WriteRune('\n')
			case 't':
				l.buf.WriteRune('\t')
			case '\\':
				l.buf.WriteRune('\\')
			case quote:
				l.buf.WriteRune(quote)
			default:
				l.buf.WriteRune(l.ch)
			}
		} else {
			l.buf.WriteRune(l.ch)
		}
		l.readChar()
	}

	if l.ch == quote {
		l.readChar() // Skip closing quote
	}

	return l.buf.String()
}

// readNumber reads a numeric value
func (l *Lexer) readNumber() string {
	l.buf.Reset()

	// Handle negative numbers
	if l.ch == '-' {
		l.buf.WriteRune(l.ch)
		l.readChar()
	}

	// Read digits
	for unicode.IsDigit(l.ch) {
		l.buf.WriteRune(l.ch)
		l.readChar()
	}

	// Handle decimal point
	if l.ch == '.' && unicode.IsDigit(l.peekChar()) {
		l.buf.WriteRune(l.ch)
		l.readChar()

		for unicode.IsDigit(l.ch) {
			l.buf.WriteRune(l.ch)
			l.readChar()
		}
	}

	return l.buf.String()
}

// readMacro reads a macro reference $(...)
func (l *Lexer) readMacro() string {
	l.buf.Reset()
	l.buf.WriteString("$(")
	l.readChar() // Skip $
	l.readChar() // Skip (

	depth := 1
	for depth > 0 && l.ch != 0 {
		switch {
		case l.ch == '$' && l.peekChar() == '(':
			depth++
			l.buf.WriteRune(l.ch)
			l.readChar()
			l.buf.WriteRune(l.ch)
			l.readChar()
		case l.ch == '(':
			depth++
			l.buf.WriteRune(l.ch)
			l.readChar()
		case l.ch == ')':
			depth--
			if depth > 0 {
				l.buf.WriteRune(l.ch)
			} else {
				l.buf.WriteRune(')')
			}
			l.readChar()
		default:
			l.buf.WriteRune(l.ch)
			l.readChar()
		}
	}

	return l.buf.String()
}

// readUntilNewline reads until end of line (for values), joining
// continuation lines the way HTCondor's getline_implementation does.
//
// Each PHYSICAL line is trimmed of trailing whitespace first, and only then
// is its last character tested for a backslash. So a backslash with spaces
// after it still continues the line, a run of spaces BEFORE the backslash is
// part of the value, and the next line -- trimmed of its own leading
// whitespace -- is joined straight on with nothing between the two. For
//
//	+Note = "a   \
//	   b"
//
// the value is "a   b": the three spaces survive and no separator is
// inserted. Files written with exactly one space before the backslash agree
// whichever rule is used, which is how a space-inserting version of this
// went unnoticed.
//
// A '#' is NOT a comment here: HTCondor only treats '#' as a comment at the
// start of a line, so a '#' inside a value (e.g. "K = v # note") is literal
// and kept.
func (l *Lexer) readUntilNewline() string {
	l.buf.Reset()

	// Skip leading whitespace
	for isLineSpace(l.ch) {
		l.readChar()
	}

	// lineStart is where the current physical line's text begins. Trailing
	// whitespace is only ever trimmed back to there, so an earlier line's
	// trailing spaces -- which were kept because a backslash followed them
	// -- are never revisited. The backslash test, by contrast, looks at the
	// whole buffer, exactly as getline_implementation's `end_ptr[-1]` does:
	// an empty continuation line leaves the previous line's last character
	// as the one tested.
	lineStart := 0
	for {
		for l.ch != '\n' && l.ch != 0 {
			l.buf.WriteRune(l.ch)
			l.readChar()
		}
		line := l.buf.String()
		line = line[:lineStart] + strings.TrimRight(line[lineStart:], lineSpace)
		if l.ch == 0 || !strings.HasSuffix(line, "\\") {
			// End of input continues nothing: there is no next line to
			// join on.
			return line
		}
		// Drop the backslash and join the next line on directly.
		line = line[:len(line)-1]
		l.buf.Reset()
		l.buf.WriteString(line)
		lineStart = len(line)
		l.readChar() // skip the newline
		for isLineSpace(l.ch) {
			l.readChar()
		}
	}
}

// lexQueueTail reads everything after an `in` or `from` keyword in a queue
// statement and returns it as one token, or nil when the keyword ends the
// line and ordinary lexing should take over.
//
// Parentheses are optional. HTCondor anchors the parse on the keyword and
// takes the rest of the line as the item list, splitting it on whitespace and
// commas for `in` and taking it whole as the item file's name for `from`; a
// '(' only selects the bracketed forms readQueueItemList handles. The name
// after `from` is therefore the whole trimmed remainder, quotes and embedded
// spaces included, because HTCondor never tokenizes it.
//
// A leading qualifier -- a '[' slice, or `files`/`dirs`/`any`/`table` -- is
// rejected rather than read as an item: HTCondor acts on those, and this
// parser implements none of them, so taking them for items would silently
// produce the wrong jobs. The qualifier has to be followed on the same line
// by whitespace or '(' to count as one, which is HTCondor's own rule: its
// token scan only recognizes a keyword when something terminates it, so
// `queue in files` is the single item "files".
func (l *Lexer) lexQueueTail(mode queueItemsMode) *TokenInfo {
	if l.ch == 0 || l.ch == '\n' {
		return nil
	}
	tok := &TokenInfo{Line: l.line, Col: l.col}
	if l.ch == '(' {
		tok.Lit = "("
		items, ok := l.readQueueItemList(mode)
		if !ok {
			// Ran to end of file without the closing ')'.
			tok.Token = ILLEGAL
			return tok
		}
		tok.Token = ITEMS
		tok.Items = items
		return tok
	}

	if mode == queueItemsFrom && (l.ch == '"' || l.ch == '\'') {
		// A quoted item file. HTCondor does not strip these quotes -- the
		// name it opens is `"items.txt"`, quotes and all -- but this parser
		// has always read a quoted path as a path, and it is the only way
		// callers have to name a file whose path contains a space. Left as
		// a deliberate divergence, recorded in fuzz/submit/FINDINGS.md.
		// Falling through here reaches the ordinary string lexing, escapes
		// included.
		return nil
	}

	rest := l.readUntilNewline()
	tok.Lit = rest
	if queueTailHasQualifier(rest) {
		tok.Token = ILLEGAL
		return tok
	}
	if mode == queueItemsFrom {
		// `from` never splits: the remainder names one item file.
		tok.Token = STRING
		return tok
	}
	tok.Token = ITEMS
	tok.Items = splitQueueItems(rest)
	return tok
}

// queueTailHasQualifier reports whether an unparenthesised queue tail begins
// with one of the qualifiers this parser does not implement. See lexQueueTail
// for why a qualifier at the very end of the line is not one.
func queueTailHasQualifier(rest string) bool {
	end := strings.IndexAny(rest, " \t\v\f\r(")
	if end < 0 {
		return false
	}
	word := rest[:end]
	if strings.HasPrefix(word, "[") {
		return true
	}
	switch strings.ToLower(word) {
	case "files", "dirs", "any", "table":
		return true
	}
	return false
}

// readQueueItemList consumes a queue statement's parenthesised item list and
// returns its members, already split. l.ch must be the opening '('. ok is
// false when a multi-line list ran to end of file without its closing ')'.
//
// The shape of the list is decided by the whole first line, not by matching
// parentheses: if that line's last character is ')' the list is a single-line
// one between the first '(' and that last ')', and otherwise it continues on
// following lines until one that begins with ')'. A ')' anywhere else is an
// ordinary character and ends up inside an item, so `queue in (a ) b)` is the
// three items "a", ")" and "b". A list whose body then still begins with '('
// is a multi-line list that happened to end its first line with ')'.
func (l *Lexer) readQueueItemList(mode queueItemsMode) ([]string, bool) {
	from := mode == queueItemsFrom

	first := strings.TrimRight(l.readUntilNewline(), " \t\r")
	body := first
	singleLine := false
	if len(first) >= 2 && strings.HasSuffix(first, ")") {
		body = first[1 : len(first)-1]
		singleLine = true
	}
	if strings.HasPrefix(body, "(") {
		// A second '(' means the list spans lines; the text after it is
		// still the start of the list.
		body = body[1:]
		singleLine = false
	}
	body = strings.TrimLeft(body, " \t\r")

	if singleLine {
		if from {
			// `queue from (a b)` is one item, not two: `from` never
			// splits a line.
			return []string{body}, true
		}
		return splitQueueItems(body), true
	}

	items := []string{}
	if body != "" {
		if from {
			items = append(items, body)
		} else {
			items = append(items, splitQueueItems(body)...)
		}
	}
	for {
		if l.ch == '\n' {
			l.readChar()
		}
		if l.ch == 0 {
			return nil, false // end of file before the closing ')'
		}
		line := strings.TrimSpace(l.readUntilNewline())
		switch {
		case strings.HasPrefix(line, "#"):
			// Comments inside the list are skipped, and unlike a blank
			// line they do not contribute an item.
		case strings.HasPrefix(line, ")"):
			return items, true
		case from:
			// Every line is one item, blank lines included.
			items = append(items, line)
		default:
			items = append(items, splitQueueItems(line)...)
		}
	}
}

// splitQueueItems splits one line of an `in` item list into its members.
// Commas and whitespace are both separators, runs of them collapse, and
// quotes carry no meaning: `queue in ("a b" c)` is the three items `"a`,
// `b"` and `c`.
func splitQueueItems(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', ' ', '\t', '\r', '\n':
			return true
		}
		return false
	})
}

// readHeredoc reads a heredoc value starting with @=TAG
func (l *Lexer) readHeredoc() string {
	l.buf.Reset()

	// Skip leading whitespace to get to the tag
	for l.ch == ' ' || l.ch == '\t' {
		l.readChar()
	}

	// Read the end tag
	tagBuf := strings.Builder{}
	for l.ch != '\n' && l.ch != '\r' && l.ch != 0 && l.ch != ' ' && l.ch != '\t' {
		tagBuf.WriteRune(l.ch)
		l.readChar()
	}

	endTag := tagBuf.String()
	if endTag == "" {
		// Invalid heredoc syntax, treat as empty value
		return ""
	}

	// Skip to end of line (after the opening tag)
	for l.ch != '\n' && l.ch != 0 {
		l.readChar()
	}
	if l.ch == '\n' {
		l.readChar()
	}

	// Read lines until we find @endTag on its own line
	for l.ch != 0 {
		lineBuf := strings.Builder{}

		// Read the line
		for l.ch != '\n' && l.ch != 0 {
			lineBuf.WriteRune(l.ch)
			l.readChar()
		}

		line := lineBuf.String()

		// Check if this line is just @endTag (possibly with surrounding whitespace)
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "@"+endTag {
			// Found the end tag, skip the newline and return
			if l.ch == '\n' {
				l.readChar()
			}
			// Return without the trailing newline
			result := l.buf.String()
			if len(result) > 0 && result[len(result)-1] == '\n' {
				result = result[:len(result)-1]
			}
			return result
		}

		// Not the end tag, add this line to the buffer
		l.buf.WriteString(line)
		if l.ch == '\n' {
			l.buf.WriteRune('\n')
			l.readChar()
		}
	}

	// Reached EOF without finding end tag - return what we have
	result := l.buf.String()
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}
	return result
}

// NextToken returns the next token
//
//nolint:gocyclo // Lexer naturally has high complexity due to many token types
func (l *Lexer) NextToken() *TokenInfo {
	// Special handling after ERROR or WARNING keywords - read rest of line after optional colon
	if l.afterErrorOrWarning {
		l.afterErrorOrWarning = false
		l.skipWhitespace()
		// Skip optional colon
		if l.ch == ':' {
			l.readChar()
			l.skipWhitespace()
		}
		tok := &TokenInfo{
			Line: l.line,
			Col:  l.col,
		}
		tok.Token = STRING
		tok.Lit = l.readUntilNewline()
		return tok
	}

	// Special handling after IF or ELIF keywords - read the entire rest of the line
	if l.afterIfOrElif {
		l.afterIfOrElif = false
		l.skipWhitespace()
		tok := &TokenInfo{
			Line: l.line,
			Col:  l.col,
		}
		tok.Token = IDENT // Use IDENT token type
		tok.Lit = l.readUntilNewline()
		return tok
	}

	// Special handling after USE keyword - read the entire rest of the line
	if l.afterUse {
		l.afterUse = false
		l.skipWhitespace()
		tok := &TokenInfo{
			Line: l.line,
			Col:  l.col,
		}
		tok.Token = IDENT // Use IDENT token type
		tok.Lit = l.readUntilNewline()
		return tok
	}

	// Special handling after an include directive's ':' — the file path or
	// command is unquoted and runs to end of line in HTCondor
	// (`include : /etc/condor/foo`, `include command : /usr/bin/sudo ...`), so
	// read it whole as a STRING. A quoted argument (`include : "..."`) falls
	// through to normal string lexing, preserving quote stripping.
	if l.afterIncludeColon {
		l.afterIncludeColon = false
		l.skipWhitespace()
		if l.ch != '"' && l.ch != '\'' {
			tok := &TokenInfo{
				Line: l.line,
				Col:  l.col,
			}
			tok.Token = STRING
			tok.Lit = l.readUntilNewline()
			return tok
		}
	}

	// Everything after an `in` or `from` keyword in a queue statement is the
	// item list (or, for `from`, the item file), which HTCondor reads with a
	// character scan of its own rather than handing to a grammar;
	// lexQueueTail does the same and yields one token. Only an `in` or
	// `from` with nothing after it falls through to ordinary lexing.
	if l.queueItems != queueItemsNone {
		mode := l.queueItems
		l.queueItems = queueItemsNone
		l.skipWhitespace()
		if tok := l.lexQueueTail(mode); tok != nil {
			return tok
		}
	}

	l.skipWhitespace()

	tok := &TokenInfo{
		Line: l.line,
		Col:  l.col,
	}

	// Capture and clear the per-statement flags before dispatching this token.
	// atStmtStart: is this token the first on its line? colonAssignable: was the
	// previous token a statement-start plain identifier (so ':' means assign)?
	atStmtStart := l.stmtStart
	colonAssignable := l.prevIdentAssignable
	wasInInclude := l.inInclude
	afterPlus := l.afterPlus
	l.stmtStart = false
	l.prevIdentAssignable = false
	l.inInclude = false
	l.afterPlus = false

	// The token after a '+' or '-' is a job attribute name, which HTCondor
	// reads before it knows whether the name is legal and never validates --
	// see isAttrNameChar. It is lexed here rather than in the switch below
	// so that a name starting with a quote, a digit or punctuation is still
	// read as a name, and so a name spelled like a keyword stays a name.
	if afterPlus {
		tok.Lit = l.readAttrName()
		if l.badMacroRef {
			l.badMacroRef = false
			tok.Token = ILLEGAL
			return tok
		}
		tok.Token = IDENT
		return tok
	}

	// submit's `-Attr = value` form, the counterpart of `+Attr = value`. It
	// is only a statement opener; a '-' anywhere else keeps its ordinary
	// meaning (a negative number, say).
	if atStmtStart && l.ch == '-' && isAttrNameChar(l.peekChar()) {
		tok.Token = MINUS
		tok.Lit = "-"
		l.readChar()
		l.afterPlus = true
		return tok
	}

	switch l.ch {
	case 0:
		tok.Token = EOF

	case '\n':
		l.stmtStart = true // the next token begins a new statement
		l.inQueue = false  // a queue statement does not span lines
		l.readChar()
		return l.NextToken() // Skip newlines and get next token

	case '#':
		l.skipToEndOfLine()
		tok.Token = COMMENT
		return l.NextToken() // Skip comments

	case '=':
		tok.Token = ASSIGN
		l.readChar()
		// Automatically read the value after =
		tok.Lit = l.readUntilNewline()

	case '@':
		// Check for heredoc syntax @=TAG
		if l.peekChar() == '=' {
			tok.Token = ASSIGN
			l.readChar() // Skip @
			l.readChar() // Skip =
			tok.Lit = l.readHeredoc()
		} else {
			tok.Token = ILLEGAL
			tok.Lit = string(l.ch)
			l.readChar()
		}

	case ':':
		if colonAssignable {
			// "C : value" is an assignment in HTCondor, equivalent to "C = value".
			// Read the value the same way '=' does.
			tok.Token = ASSIGN
			l.readChar()
			tok.Lit = l.readUntilNewline()
		} else {
			tok.Token = COLON
			tok.Lit = ":"
			l.readChar()
			// A ':' ending an include type introduces the (unquoted) path/command.
			if wasInInclude {
				l.afterIncludeColon = true
			}
		}

	case '(':
		tok.Token = LPAREN
		tok.Lit = "("
		l.readChar()

	case ')':
		tok.Token = RPAREN
		tok.Lit = ")"
		l.readChar()

	case '[':
		tok.Token = LBRACK
		tok.Lit = "["
		// Skip [Section] headers
		l.skipToEndOfLine()
		return l.NextToken()

	case ']':
		tok.Token = RBRACK
		tok.Lit = "]"
		l.readChar()

	case ',':
		tok.Token = COMMA
		tok.Lit = ","
		l.readChar()

	case '+':
		// `+Attribute = expr` is submit-file syntax for setting a job
		// ad attribute. Require an identifier to follow, so a stray '+'
		// is an error rather than a token.
		//
		// The check is on l.ch, which after readChar is the character
		// immediately after the '+'. Testing peekChar here instead
		// looked at the SECOND character of the name, which made
		// `+F = 1` illegal — and, because the parser has no error
		// production for it, made the whole line disappear without a
		// diagnostic.
		// The name is read with HTCondor's charset, not Go's identifier
		// rule: `+0 = 7` and `+0.5 = 7` set job attributes named "0" and
		// "0.5", which condor_submit accepts.
		tok.Lit = "+"
		l.readChar()
		if isAttrNameChar(l.ch) {
			tok.Token = PLUS
			l.afterPlus = true
		} else {
			tok.Token = ILLEGAL
		}

	case '"', '\'':
		quote := l.ch
		tok.Token = STRING
		tok.Lit = l.readString(quote)

	case '$':
		if atStmtStart && l.peekChar() == '(' {
			// A parameter NAME may start with a macro reference:
			//	$(K) = value
			// defines whatever $(K) expands to. Lexed as one IDENT so
			// the parser sees NAME ASSIGN, the same as any other
			// assignment.
			l.buf.Reset()
			ok := l.readMacroRefInto(&l.buf)
			for ok {
				if isIdentChar(l.ch) {
					l.buf.WriteRune(l.ch)
					l.readChar()
					continue
				}
				if l.ch == '$' && l.peekChar() == '(' {
					ok = l.readMacroRefInto(&l.buf)
					continue
				}
				break
			}
			tok.Lit = l.buf.String()
			if !ok {
				tok.Token = ILLEGAL
				break
			}
			tok.Token = IDENT
			l.prevIdentAssignable = true
			break
		}
		if l.peekChar() == '(' {
			tok.Token = STRING
			tok.Lit = l.readMacro()
		} else {
			tok.Token = ILLEGAL
			tok.Lit = string(l.ch)
			l.readChar()
		}

	default:
		switch {
		case isIdentStart(l.ch) || (atStmtStart && isParamNameChar(l.ch)):
			if atStmtStart {
				// A statement begins with a parameter name, which HTCondor
				// scans with a charset that allows a leading digit; see
				// readParamName.
				tok.Lit = l.readParamName()
				if tok.Lit == "" {
					// A letter that is not a parameter-name character --
					// one outside ASCII. The name is illegal and the file
					// fails, so report the character and move past it
					// rather than scanning it again forever.
					tok.Token = ILLEGAL
					tok.Lit = string(l.ch)
					l.readChar()
					return tok
				}
			} else {
				tok.Lit = l.readIdentifier()
			}
			if l.badMacroRef {
				l.badMacroRef = false
				tok.Token = ILLEGAL
				return tok
			}
			// Check if it's a keyword
			if kw, ok := keywords[strings.ToLower(tok.Lit)]; ok {
				tok.Token = kw
				// Set flags for special keyword handling
				switch kw {
				case USE:
					l.afterUse = true
				case INCLUDE:
					l.inInclude = true
				case COMMAND, IFEXIST:
					// Continuation keywords of an include type: keep the flag alive
					// so the terminating ':' still introduces the path/command.
					if wasInInclude {
						l.inInclude = true
					}
				case IF, ELIF:
					l.afterIfOrElif = true
				case QUEUE:
					l.inQueue = true
				case IN:
					if l.inQueue {
						l.queueItems = queueItemsIn
					}
				case FROM:
					if l.inQueue {
						l.queueItems = queueItemsFrom
					}
				case ERROR, WARNING:
					// Only treat as directive if followed by ':' or whitespace then message
					// If followed by '=', treat as regular identifier for assignment
					if l.peekNextNonWhitespace() != '=' {
						l.afterErrorOrWarning = true
					} else {
						// Treat as identifier, not directive
						tok.Token = IDENT
					}
				}
			} else {
				tok.Token = IDENT
				// A plain identifier at the start of a statement is an assignment
				// target: a following ':' is the assignment operator.
				if atStmtStart {
					l.prevIdentAssignable = true
				}
			}
		case unicode.IsDigit(l.ch) || (l.ch == '-' && unicode.IsDigit(l.peekChar())):
			tok.Token = NUMBER
			tok.Lit = l.readNumber()
		default:
			tok.Token = ILLEGAL
			tok.Lit = string(l.ch)
			l.readChar()
		}
	}

	return tok
}

// ReadValue reads everything after = as a value (including macros)
func (l *Lexer) ReadValue() string {
	return l.readUntilNewline()
}

// lineSpace is every character HTCondor's reader treats as whitespace inside a
// line. getline_implementation trims a line with isspace(), so a config or
// submit file written on Windows loses its carriage return before the line is
// ever split into name and value; trimming only " \t" left it on the end of
// the value, which is how `executable = /bin/sleep\r\n` produced a Cmd of
// "/bin/sleep\r". '\n' is not in the set because it terminates the value.
const lineSpace = " \t\r\v\f"

// isLineSpace is lineSpace as a predicate.
func isLineSpace(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\v' || ch == '\f'
}

// isIdentStart returns true if the rune can start an identifier
func isIdentStart(ch rune) bool {
	return unicode.IsLetter(ch) || ch == '_'
}

// isParamNameChar reports whether ch may appear in a parameter name, matching
// condor_isidchar() in config.cpp: alphanumerics plus '_', '.' and '/'.
//
// The charset is ASCII, deliberately: condor_isidchar() compares against
// 'a'..'z', 'A'..'Z' and '0'..'9', so a name with a letter outside ASCII --
// `café = 1` -- fails is_valid_param_name() and HTCondor rejects the whole
// file. Reading it with unicode.IsLetter instead made such a file parse here
// and define a macro nothing else would ever see. A job ATTRIBUTE name is a
// different question: `+café = 1` is accepted, because the '+' form skips
// that check entirely (isAttrNameChar).
func isParamNameChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '/'
}

// isAttrNameChar reports whether ch can appear in a `+Attr`/`-Attr` job
// attribute name.
//
// HTCondor scans a name as the run of characters before the first whitespace
// or operator ('=' or ':'), and for the '+' and '-' forms it never checks
// what it scanned against is_valid_param_name() -- it just prefixes "MY." and
// stores it. So `+a-b = 7` makes an attribute literally named a-b, where the
// same name without the '+' fails the file.
func isAttrNameChar(ch rune) bool {
	switch ch {
	case 0, '\n', '=', ':':
		return false
	}
	return !isLineSpace(ch)
}

// readAttrName reads a `+Attr`/`-Attr` job attribute name.
func (l *Lexer) readAttrName() string {
	l.buf.Reset()
	for isAttrNameChar(l.ch) {
		l.buf.WriteRune(l.ch)
		l.readChar()
	}
	return l.buf.String()
}

// readParamName reads the name at the start of a statement.
//
// HTCondor scans the name as the run of characters before the first whitespace
// or operator and then checks it against is_valid_param_name(), whose charset
// is condor_isidchar()'s. There is no number token in the config or submit
// language: `0 = x` defines a macro named "0" and `a/b = 1` one named "a/b",
// both of which condor_submit accepts.
//
// Lexing those as NUMBER and ILLEGAL made the assignment vanish, and with it
// every statement after it: the grammar has no error production, so the parse
// stops, and a default reduction has usually already stored the statements
// seen so far, so Parse returned a truncated file with no error at all.
//
// A $(...) macro reference may appear in the name, for the same reason
// readIdentifier accepts one.
func (l *Lexer) readParamName() string {
	l.buf.Reset()
	for {
		if isParamNameChar(l.ch) {
			l.buf.WriteRune(l.ch)
			l.readChar()
			continue
		}
		if l.ch == '$' && l.peekChar() == '(' {
			if !l.readMacroRefInto(&l.buf) {
				l.badMacroRef = true
				break
			}
			continue
		}
		break
	}
	return l.buf.String()
}

// readMacroRefInto copies a $(...) macro reference into buf, brackets
// included, tracking nesting so $(FOO$(BAR)) is taken whole.
//
// A parameter NAME may contain one: HTCondor expands the left-hand side
// before storing, which is how the shipped metaknobs define per-argument
// parameters --
//
//	CLASSAD_USER_MAPFILE_$(1) = $(2)
//
// from $FEATURE.ScheddUsermapFile, reached through
// `use FEATURE : AssignAccountingGroup`. Without this the name lexed as
// IDENT followed by a separate STRING and the parse failed with
// "unexpected STRING, expecting ASSIGN", taking the whole config file
// with it.
func (l *Lexer) readMacroRefInto(buf *strings.Builder) bool {
	// '$'
	buf.WriteRune(l.ch)
	l.readChar()
	// '('
	buf.WriteRune(l.ch)
	l.readChar()

	depth := 1
	for depth > 0 && l.ch != 0 {
		// A macro reference does not span lines; bail rather than
		// swallow the rest of the file on an unbalanced '('. Reporting
		// it here keeps the error on the offending line instead of
		// surfacing as a confusing complaint about the next one.
		if l.ch == '\n' {
			return false
		}
		if l.ch == '$' && l.peekChar() == '(' {
			depth++
			buf.WriteRune(l.ch)
			l.readChar()
			buf.WriteRune(l.ch)
			l.readChar()
			continue
		}
		if l.ch == ')' {
			depth--
		}
		buf.WriteRune(l.ch)
		l.readChar()
	}
	return depth == 0
}

// isIdentChar returns true if the rune can be in an identifier
func isIdentChar(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_'
}
