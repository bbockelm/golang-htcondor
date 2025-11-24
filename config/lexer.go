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
}

// NewLexer creates a new lexer
func NewLexer(r io.Reader) *Lexer {
	l := &Lexer{
		input: bufio.NewReader(r),
		line:  1,
		col:   0,
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

// peekNextNonWhitespace looks ahead to find the next non-whitespace character
// We need to properly look ahead through whitespace to determine if it's '=' or ':'
func (l *Lexer) peekNextNonWhitespace() rune {
	// Save current position in the buffer
	savedCh := l.ch
	savedNextCh := l.nextCh
	savedCol := l.col
	savedLine := l.line

	// Temporarily advance through whitespace
	tempCh := l.nextCh
	for tempCh == ' ' || tempCh == '\t' || tempCh == '\r' {
		// We can't easily advance through buffered reader, so we peek
		// The simplest solution: peek one char ahead
		if l.nextCh == ' ' || l.nextCh == '\t' || l.nextCh == '\r' {
			// We have whitespace next - we need to look further
			// This is tricky without modifying state
			// Let's use a different strategy: mark the buffer position
			// and try to peek ahead
			break
		}
		tempCh = 0
	}

	// If nextCh is '=', return it immediately
	if l.nextCh == '=' {
		return '='
	}

	// If nextCh is ':', return it immediately
	if l.nextCh == ':' {
		return ':'
	}

	// If nextCh is whitespace, we need a more sophisticated check
	// For now, use buffered reader's Peek capability
	if l.nextCh == ' ' || l.nextCh == '\t' || l.nextCh == '\r' {
		// Peek ahead in the buffer
		if peekBytes, err := l.input.Peek(10); err == nil {
			// Look through peeked bytes for first non-whitespace
			for _, b := range peekBytes {
				if b != ' ' && b != '\t' && b != '\r' {
					return rune(b)
				}
			}
		}
	}

	// Restore state (though we didn't actually modify it)
	_ = savedCh
	_ = savedNextCh
	_ = savedCol
	_ = savedLine

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

		// Regular identifier characters
		for isIdentChar(l.ch) {
			l.buf.WriteRune(l.ch)
			l.readChar()
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

// readUntilNewline reads until end of line (for values)
func (l *Lexer) readUntilNewline() string {
	l.buf.Reset()

	// Skip leading whitespace
	for l.ch == ' ' || l.ch == '\t' {
		l.readChar()
	}

	// Read until newline, handling line continuation
	for l.ch != '\n' && l.ch != 0 && l.ch != '#' {
		switch {
		case l.ch == '\\' && l.peekChar() == '\n':
			// Trim trailing whitespace before the backslash
			s := l.buf.String()
			l.buf.Reset()
			l.buf.WriteString(strings.TrimRight(s, " \t"))
			l.buf.WriteRune(' ')
			l.readChar() // Skip backslash
			l.readChar() // Skip newline
			// Skip leading whitespace on next line
			for l.ch == ' ' || l.ch == '\t' {
				l.readChar()
			}
		case l.ch == '\\' && l.peekChar() == '\r':
			// Handle Windows line endings
			// Trim trailing whitespace before the backslash
			s := l.buf.String()
			l.buf.Reset()
			l.buf.WriteString(strings.TrimRight(s, " \t"))
			l.buf.WriteRune(' ')
			l.readChar() // Skip backslash
			l.readChar() // Skip \r
			if l.ch == '\n' {
				l.readChar() // Skip \n
			}
			for l.ch == ' ' || l.ch == '\t' {
				l.readChar()
			}
		default:
			l.buf.WriteRune(l.ch)
			l.readChar()
		}
	}

	return strings.TrimRight(l.buf.String(), " \t")
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

	l.skipWhitespace()

	tok := &TokenInfo{
		Line: l.line,
		Col:  l.col,
	}

	switch l.ch {
	case 0:
		tok.Token = EOF

	case '\n':
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
		tok.Token = COLON
		tok.Lit = ":"
		l.readChar()

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
		// Check if followed by an identifier (for +Attribute syntax)
		if isIdentStart(l.peekChar()) {
			tok.Token = PLUS
			tok.Lit = "+"
			l.readChar()
		} else {
			tok.Token = ILLEGAL
			tok.Lit = string(l.ch)
			l.readChar()
		}

	case '"', '\'':
		quote := l.ch
		tok.Token = STRING
		tok.Lit = l.readString(quote)

	case '$':
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
		case isIdentStart(l.ch):
			tok.Lit = l.readIdentifier()
			// Check if it's a keyword
			if kw, ok := keywords[strings.ToLower(tok.Lit)]; ok {
				tok.Token = kw
				// Set flags for special keyword handling
				switch kw {
				case USE:
					l.afterUse = true
				case IF, ELIF:
					l.afterIfOrElif = true
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

// isIdentStart returns true if the rune can start an identifier
func isIdentStart(ch rune) bool {
	return unicode.IsLetter(ch) || ch == '_'
}

// isIdentChar returns true if the rune can be in an identifier
func isIdentChar(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_'
}
