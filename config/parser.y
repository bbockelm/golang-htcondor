%{
package config

import (
	"fmt"
	"strings"
)

// Statement represents a parsed configuration statement
type Statement interface {
	statement()
}

// Assignment represents a variable assignment
type Assignment struct {
	Name        string
	Value       string
	ClassAdExpr bool // True if this is a +Attribute = expr (ClassAd expression)
}

func (a *Assignment) statement() {}

// IncludeDirective represents an include statement
type IncludeDirective struct {
	Path string
	Type string // "include", "include_command", "include_ifexist"
}

func (i *IncludeDirective) statement() {}

// Conditional represents an if/elif/else/endif block
type Conditional struct {
	Condition   string
	ThenBlock   []Statement
	ElseIfBlock []ElseIf
	ElseBlock   []Statement
}

func (c *Conditional) statement() {}

// ElseIf represents an elif clause
type ElseIf struct {
	Condition string
	Block     []Statement
}

// UseDirective represents a use ROLE statement
type UseDirective struct {
	Role string
}

func (u *UseDirective) statement() {}

// ErrorDirective represents an error directive
type ErrorDirective struct {
	Message string
}

func (e *ErrorDirective) statement() {}

// WarningDirective represents a warning directive
type WarningDirective struct {
	Message string
}

func (w *WarningDirective) statement() {}

// QueueStatement represents a queue statement in submit files
type QueueStatement struct {
	Count    int      // Number of jobs to queue (0 means 1)
	VarNames []string // Variable names for iteration
	Items    []string // Items to iterate over (for "from" or "in" clauses)
	File     string   // Filename for "from" clause
	Slice    string   // Slice specification like [1:10]
}

func (q *QueueStatement) statement() {}

%}

// Token definitions
%union {
	str        string
	stmts      []Statement
	stmt       Statement
	elseifs    []ElseIf
	elseif     ElseIf
	intval     int
	strlist    []string
}

%token <str> IDENT STRING NUMBER ASSIGN
%token <str> IF ELIF ELSE ENDIF DEFINED VERSION
%token <str> INCLUDE USE TRUE FALSE YES NO ERROR WARNING IFEXIST COMMAND INTO
%token <str> QUEUE FROM IN MATCHING
%token COLON LPAREN RPAREN LBRACK RBRACK COMMA PLUS
%token EOF ILLEGAL COMMENT

%type <stmts> config_file statement_list
%type <stmt> statement assignment include_directive conditional use_directive error_directive warning_directive queue_statement
%type <elseifs> elif_clauses
%type <elseif> elif_clause
%type <str> condition include_type identifier path_or_command
%type <intval> queue_count
%type <strlist> var_list item_list item_list_items

%%

config_file:
	statement_list
	{
		yylex.(*parser).result = $1
	}

statement_list:
	/* empty */
	{
		$$ = []Statement{}
	}
	| statement_list statement
	{
		$$ = append($1, $2)
	}

statement:
	assignment
	{
		$$ = $1
	}
	| include_directive
	{
		$$ = $1
	}
	| conditional
	{
		$$ = $1
	}
	| use_directive
	{
		$$ = $1
	}
	| error_directive
	{
		$$ = $1
	}
	| warning_directive
	{
		$$ = $1
	}
	| queue_statement
	{
		$$ = $1
	}

assignment:
	identifier ASSIGN
	{
		// The value is stored in $2 (ASSIGN token's Lit field)
		$$ = &Assignment{
			Name:  $1,
			Value: $2,
		}
	}
	| PLUS identifier ASSIGN
	{
		// +Attribute = expr - ClassAd expression to be integrated into job
		// Strip the + prefix and mark as ClassAd expression
		$$ = &Assignment{
			Name:        $2,
			Value:       $3,
			ClassAdExpr: true,
		}
	}

identifier:
	IDENT
	{
		$$ = $1
	}
	| IF      { $$ = $1 }
	| ELIF    { $$ = $1 }
	| ELSE    { $$ = $1 }
	| ENDIF   { $$ = $1 }
	| DEFINED { $$ = $1 }
	| VERSION { $$ = $1 }
	| INCLUDE { $$ = $1 }
	| USE     { $$ = $1 }
	| TRUE    { $$ = $1 }
	| FALSE   { $$ = $1 }
	| YES     { $$ = $1 }
	| NO      { $$ = $1 }
	| ERROR   { $$ = $1 }
	| WARNING { $$ = $1 }
	| IFEXIST { $$ = $1 }
	| COMMAND { $$ = $1 }
	| INTO    { $$ = $1 }

include_directive:
	include_type STRING
	{
		$$ = &IncludeDirective{
			Type: $1,
			Path: $2,
		}
	}
	| include_type IDENT
	{
		$$ = &IncludeDirective{
			Type: $1,
			Path: $2,
		}
	}
	| include_type COLON path_or_command
	{
		// Check if path ends with | to determine if it's a command
		path := $3
		inclType := $1
		if len(path) > 0 && path[len(path)-1] == '|' {
			// Remove trailing | and mark as command
			path = strings.TrimSpace(path[:len(path)-1])
			if inclType == "include" {
				inclType = "include_command"
			} else if inclType == "include_ifexist" {
				inclType = "include_ifexist_command"
			}
		}
		$$ = &IncludeDirective{
			Type: inclType,
			Path: path,
		}
	}

path_or_command:
	STRING
	{
		$$ = $1
	}
	| IDENT
	{
		$$ = $1
	}

include_type:
	INCLUDE
	{
		$$ = "include"
	}
	| INCLUDE COMMAND
	{
		$$ = "include_command"
	}
	| INCLUDE IFEXIST
	{
		$$ = "include_ifexist"
	}

conditional:
	IF condition statement_list elif_clauses ELSE statement_list ENDIF
	{
		$$ = &Conditional{
			Condition:   $2,
			ThenBlock:   $3,
			ElseIfBlock: $4,
			ElseBlock:   $6,
		}
	}
	| IF condition statement_list elif_clauses ENDIF
	{
		$$ = &Conditional{
			Condition:   $2,
			ThenBlock:   $3,
			ElseIfBlock: $4,
			ElseBlock:   nil,
		}
	}
	| IF condition statement_list ELSE statement_list ENDIF
	{
		$$ = &Conditional{
			Condition:   $2,
			ThenBlock:   $3,
			ElseIfBlock: nil,
			ElseBlock:   $5,
		}
	}
	| IF condition statement_list ENDIF
	{
		$$ = &Conditional{
			Condition:   $2,
			ThenBlock:   $3,
			ElseIfBlock: nil,
			ElseBlock:   nil,
		}
	}

elif_clauses:
	elif_clause
	{
		$$ = []ElseIf{$1}
	}
	| elif_clauses elif_clause
	{
		$$ = append($1, $2)
	}

elif_clause:
	ELIF condition statement_list
	{
		$$ = ElseIf{
			Condition: $2,
			Block:     $3,
		}
	}

condition:
	DEFINED LPAREN IDENT RPAREN
	{
		$$ = fmt.Sprintf("defined(%s)", $3)
	}
	| VERSION IDENT STRING
	{
		$$ = fmt.Sprintf("version %s %s", $2, $3)
	}
	| IDENT
	{
		$$ = $1
	}

use_directive:
	USE IDENT
	{
		$$ = &UseDirective{
			Role: $2,
		}
	}

error_directive:
	ERROR STRING
	{
		$$ = &ErrorDirective{
			Message: $2,
		}
	}

warning_directive:
	WARNING STRING
	{
		$$ = &WarningDirective{
			Message: $2,
		}
	}

queue_statement:
	QUEUE
	{
		// Simple "queue" with default count of 1
		$$ = &QueueStatement{
			Count: 1,
		}
	}
	| QUEUE queue_count
	{
		// "queue N" - queue N jobs
		$$ = &QueueStatement{
			Count: $2,
		}
	}
	| QUEUE var_list FROM IDENT
	{
		// "queue var1, var2 from file"
		$$ = &QueueStatement{
			Count:    0, // Determined by file
			VarNames: $2,
			File:     $4,
		}
	}
	| QUEUE var_list FROM STRING
	{
		// "queue var1, var2 from file" (with quoted path)
		$$ = &QueueStatement{
			Count:    0, // Determined by file
			VarNames: $2,
			File:     $4,
		}
	}
	| QUEUE queue_count var_list FROM IDENT
	{
		// "queue N var1, var2 from file"
		$$ = &QueueStatement{
			Count:    $2,
			VarNames: $3,
			File:     $5,
		}
	}
	| QUEUE queue_count var_list FROM STRING
	{
		// "queue N var1, var2 from file" (with quoted path)
		$$ = &QueueStatement{
			Count:    $2,
			VarNames: $3,
			File:     $5,
		}
	}
	| QUEUE var_list IN item_list
	{
		// "queue var in (item1, item2, item3)"
		$$ = &QueueStatement{
			Count:    0, // Determined by item count
			VarNames: $2,
			Items:    $4,
		}
	}
	| QUEUE queue_count var_list IN item_list
	{
		// "queue N var in (item1, item2)"
		$$ = &QueueStatement{
			Count:    $2,
			VarNames: $3,
			Items:    $5,
		}
	}
	| QUEUE MATCHING IDENT
	{
		// "queue matching pattern"
		$$ = &QueueStatement{
			Count: 0, // Determined by matches
			File:  $3, // Pattern stored in File field
		}
	}
	| QUEUE MATCHING STRING
	{
		// "queue matching pattern" (with quoted pattern)
		$$ = &QueueStatement{
			Count: 0, // Determined by matches
			File:  $3, // Pattern stored in File field
		}
	}
	| QUEUE queue_count MATCHING IDENT
	{
		// "queue N matching pattern"
		$$ = &QueueStatement{
			Count: $2,
			File:  $4, // Pattern stored in File field
		}
	}
	| QUEUE queue_count MATCHING STRING
	{
		// "queue N matching pattern" (with quoted pattern)
		$$ = &QueueStatement{
			Count: $2,
			File:  $4, // Pattern stored in File field
		}
	}

queue_count:
	NUMBER
	{
		// Convert string number to int
		var count int
		fmt.Sscanf($1, "%d", &count)
		$$ = count
	}

var_list:
	IDENT
	{
		$$ = []string{$1}
	}
	| var_list COMMA IDENT
	{
		$$ = append($1, $3)
	}

item_list:
	LPAREN RPAREN
	{
		$$ = []string{}
	}
	| LPAREN item_list_items RPAREN
	{
		$$ = $2
	}

item_list_items:
	IDENT
	{
		$$ = []string{$1}
	}
	| STRING
	{
		$$ = []string{$1}
	}
	| item_list_items COMMA IDENT
	{
		$$ = append($1, $3)
	}
	| item_list_items COMMA STRING
	{
		$$ = append($1, $3)
	}

%%

// parser holds the state for the parser
type parser struct {
	lexer  *Lexer
	result []Statement
	errors []error
}

// Lex is required by the goyacc-generated parser
func (p *parser) Lex(lval *yySymType) int {
	tok := p.lexer.NextToken()

	// Set the string value for tokens that have literal values
	switch tok.Token {
	case IDENT, STRING, NUMBER, ASSIGN:
		lval.str = tok.Lit
	}

	return int(tok.Token)
}

// Error is required by the goyacc-generated parser
func (p *parser) Error(s string) {
	p.errors = append(p.errors, fmt.Errorf("parse error: %s", s))
}

// Parse parses the input and returns the list of statements
func Parse(lexer *Lexer) ([]Statement, error) {
	p := &parser{
		lexer:  lexer,
		result: nil,
		errors: nil,
	}

	yyParse(p)

	// If we got results (even empty), return them if there were no critical errors
	// This allows graceful handling of minor syntax issues and empty input
	if p.result != nil {
		return p.result, nil
	}

	// If we have explicit errors, return the first one
	if len(p.errors) > 0 {
		return nil, p.errors[0]
	}

	// No result and no errors - return empty list for empty input
	return []Statement{}, nil
}
