package config

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// executeStatements executes a list of parsed statements
func (c *Config) executeStatements(stmts []Statement) error {
	for _, stmt := range stmts {
		if err := c.executeStatement(stmt); err != nil {
			return err
		}
	}
	return nil
}

// ExecuteStatements is the public version of executeStatements
func (c *Config) ExecuteStatements(stmts []Statement) error {
	return c.executeStatements(stmts)
}

// executeStatement executes a single statement
func (c *Config) executeStatement(stmt Statement) error {
	switch s := stmt.(type) {
	case *Assignment:
		return c.executeAssignment(s)
	case *Conditional:
		return c.executeConditional(s)
	case *IncludeDirective:
		return c.executeInclude(s)
	case *UseDirective:
		return c.executeUse(s)
	case *ErrorDirective:
		return c.executeError(s)
	case *WarningDirective:
		return c.executeWarning(s)
	default:
		return fmt.Errorf("unknown statement type: %T", stmt)
	}
}

// executeAssignment executes a variable assignment
func (c *Config) executeAssignment(a *Assignment) error {
	value := a.Value

	// If we're in a metaknob, expand parameters before storing
	// This is necessary because metaknob parameters ($(1), $(2), etc.)
	// are deleted after the metaknob template finishes executing
	if c.inMetaknob {
		var err error
		value, err = c.expandMacrosWithFunctions(value)
		if err != nil {
			return fmt.Errorf("error expanding value in metaknob: %w", err)
		}
	}

	// Use Set() which handles self-references and stores unexpanded values
	// This preserves lazy evaluation semantics (except in metaknobs)
	c.Set(a.Name, value)
	return nil
}

// executeConditional executes an if/elif/else/endif block
func (c *Config) executeConditional(cond *Conditional) error {
	// Expand macros in condition before evaluation
	expandedCondition, err := c.expandMacrosWithFunctions(cond.Condition)
	if err != nil {
		return fmt.Errorf("error expanding condition %q: %w", cond.Condition, err)
	}

	result, err := c.evaluateCondition(expandedCondition)
	if err != nil {
		return fmt.Errorf("error evaluating condition %q: %w", cond.Condition, err)
	}

	if result {
		// Execute the then block
		return c.executeStatements(cond.ThenBlock)
	}

	// Try elif blocks
	for _, elif := range cond.ElseIfBlock {
		// Expand macros in elif condition
		expandedElifCondition, err := c.expandMacrosWithFunctions(elif.Condition)
		if err != nil {
			return fmt.Errorf("error expanding elif condition %q: %w", elif.Condition, err)
		}

		result, err := c.evaluateCondition(expandedElifCondition)
		if err != nil {
			return fmt.Errorf("error evaluating elif condition %q: %w", elif.Condition, err)
		}

		if result {
			return c.executeStatements(elif.Block)
		}
	}

	// Execute else block if present
	if cond.ElseBlock != nil {
		return c.executeStatements(cond.ElseBlock)
	}

	return nil
}

// executeInclude executes an include directive
func (c *Config) executeInclude(inc *IncludeDirective) error {
	// Expand macros in the path
	path, err := c.expandMacrosWithFunctions(inc.Path)
	if err != nil {
		return fmt.Errorf("error expanding include path %q: %w", inc.Path, err)
	}

	switch inc.Type {
	case "include":
		return c.includeFile(path, false)
	case "include_ifexist":
		return c.includeFile(path, true)
	case "include_command":
		return c.includeCommand(path)
	case "include_ifexist_command":
		// Try to execute command, but don't fail if it errors
		if err := c.includeCommand(path); err != nil {
			// Silently ignore error for ifexist variant
			return nil
		}
		return nil
	default:
		return fmt.Errorf("unknown include type: %s", inc.Type)
	}
}

// includeFile includes a configuration file or glob pattern
func (c *Config) includeFile(path string, optional bool) error {
	// Check for glob patterns
	if strings.ContainsAny(path, "*?[]") {
		matches, err := filepath.Glob(path)
		if err != nil {
			if optional {
				return nil
			}
			return fmt.Errorf("error globbing %q: %w", path, err)
		}

		if len(matches) == 0 && !optional {
			return fmt.Errorf("no files match pattern: %s", path)
		}

		// Include all matching files
		for _, match := range matches {
			if err := c.includeFile(match, optional); err != nil {
				return err
			}
		}
		return nil
	}

	// Check for circular includes
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	if c.includedFiles[absPath] {
		return fmt.Errorf("circular include detected: %s", path)
	}

	// Open the file
	//nolint:gosec // G304: Config path comes from validated config directive
	f, err := os.Open(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("error opening %q: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close file: %w", cerr)
		}
	}()

	// Mark as included
	c.includedFiles[absPath] = true
	defer delete(c.includedFiles, absPath)

	// Parse and execute the file
	return c.parseAndExecute(f)
}

// includeCommand executes a command and includes its output
func (c *Config) includeCommand(command string) error {
	// Execute the command
	//nolint:gosec // G204: command comes from trusted config include_command directives
	cmd := exec.CommandContext(context.Background(), "sh", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("error executing command %q: %w", command, err)
	}

	// Parse the output as configuration
	return c.parseAndExecute(strings.NewReader(string(output)))
}

// parseAndExecute parses and executes configuration from a reader
func (c *Config) parseAndExecute(r io.Reader) error {
	lex := NewLexer(r)
	stmts, err := Parse(lex)
	if err != nil {
		return err
	}

	// If no statements were parsed, that's okay (empty config)
	if len(stmts) == 0 {
		return nil
	}

	return c.executeStatements(stmts)
}

// executeUse executes a use directive (role-based configuration)
func (c *Config) executeUse(use *UseDirective) error {
	// Parse the use directive: "FEATURE : NAME" or "POLICY : NAME(args)"
	// The Role field contains the full string after "use"

	// First, expand any macros in the role string
	roleStr, _ := c.expandMacrosWithFunctions(use.Role) // Parse: TYPE : NAME or TYPE : NAME(args)
	parts := strings.SplitN(roleStr, ":", 2)
	if len(parts) != 2 {
		// Old-style "use ROLE" - just set the ROLE variable
		c.values["ROLE"] = roleStr
		return nil
	}

	roleType := strings.TrimSpace(parts[0])
	roleSpec := strings.TrimSpace(parts[1])

	// Extract name and parameters from roleSpec
	// e.g., "NAME" or "NAME(arg1, arg2, arg3)"
	var roleName string
	var params []string

	if idx := strings.Index(roleSpec, "("); idx >= 0 {
		roleName = strings.TrimSpace(roleSpec[:idx])
		// Extract parameters
		endIdx := strings.LastIndex(roleSpec, ")")
		if endIdx < 0 {
			return fmt.Errorf("use directive: mismatched parentheses in %q", roleSpec)
		}
		paramStr := roleSpec[idx+1 : endIdx]
		if paramStr != "" {
			// Split by commas, but be careful with nested function calls
			params = splitParams(paramStr)
		}
	} else {
		roleName = roleSpec
	}

	// Look up the metaknob: $TYPE.NAME
	// Use raw value access to avoid premature macro expansion
	metaknobKey := fmt.Sprintf("$%s.%s", strings.ToUpper(roleType), roleName)
	metaknobValue, ok := c.values[metaknobKey]
	if !ok {
		// Not found - this might be OK for some use cases
		// Just set ROLE variable for compatibility
		c.values["ROLE"] = roleStr
		return nil
	}

	// Now we need to execute the metaknob template
	// First, set up numbered parameter variables $(1), $(2), etc.
	oldParams := make(map[string]string)
	for i, param := range params {
		paramNum := fmt.Sprintf("%d", i+1)
		oldVal, hadOld := c.values[paramNum]
		if hadOld {
			oldParams[paramNum] = oldVal
		}
		// Expand macros in the parameter value before storing
		expandedParam, _ := c.expandMacrosWithFunctions(param)
		c.values[paramNum] = expandedParam
	}

	// Also set "1+", "2+", etc. for the $(1+) syntax (remaining params)
	// But we need to handle this in expandMacrosWithFunctions

	// Parse and execute the metaknob template as if it were a config file
	lex := NewLexer(strings.NewReader(metaknobValue))
	stmts, err := Parse(lex)
	if err != nil {
		return fmt.Errorf("use directive: failed to parse metaknob %s: %w", metaknobKey, err)
	}

	// Set flag to expand parameters during assignment
	c.inMetaknob = true
	defer func() { c.inMetaknob = false }()

	// Execute the statements from the metaknob
	for _, stmt := range stmts {
		if err := c.executeStatement(stmt); err != nil {
			return fmt.Errorf("use directive: error executing metaknob %s: %w", metaknobKey, err)
		}
	}

	// Restore old parameter values
	for paramNum, oldVal := range oldParams {
		c.values[paramNum] = oldVal
	}
	// Clean up new parameter values that didn't exist before
	for i := range params {
		paramNum := fmt.Sprintf("%d", i+1)
		if _, hadOld := oldParams[paramNum]; !hadOld {
			delete(c.values, paramNum)
		}
	}

	return nil
}

// splitParams splits a parameter list by commas, respecting nested parentheses
func splitParams(paramStr string) []string {
	var params []string
	var current strings.Builder
	depth := 0

	for _, ch := range paramStr {
		switch ch {
		case '(':
			depth++
			current.WriteRune(ch)
		case ')':
			depth--
			current.WriteRune(ch)
		case ',':
			if depth == 0 {
				params = append(params, strings.TrimSpace(current.String()))
				current.Reset()
			} else {
				current.WriteRune(ch)
			}
		default:
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		params = append(params, strings.TrimSpace(current.String()))
	}

	return params
}

// executeError executes an error directive
func (c *Config) executeError(e *ErrorDirective) error {
	// Expand macros in the error message
	msg, _ := c.expandMacrosWithFunctions(e.Message)
	return fmt.Errorf("configuration error: %s", msg)
}

// executeWarning executes a warning directive
func (c *Config) executeWarning(w *WarningDirective) error {
	// Expand macros in the warning message
	msg, _ := c.expandMacrosWithFunctions(w.Message)
	fmt.Fprintf(os.Stderr, "Configuration warning: %s\n", msg)
	return nil
}
