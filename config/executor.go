package config

import (
	"context"
	"fmt"
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

// CustomAttrPrefix is the canonical spelling for a submit-file
// assignment that sets a job ad attribute rather than a submit command.
//
// HTCondor accepts two syntaxes for it — `+Foo = expr` and
// `MY.Foo = expr` — and they mean the same thing. Parsing stores both
// under this prefix so everything downstream has one spelling to look
// for. (It lives here rather than beside Assignment because parser.go
// is generated from parser.y and regeneration would drop it.)
const CustomAttrPrefix = "MY."

// executeAssignment executes a variable assignment
func (c *Config) executeAssignment(a *Assignment) error {
	value := a.Value

	// The NAME may itself contain a macro reference, which HTCondor
	// expands before storing:
	//
	//	CLASSAD_USER_MAPFILE_$(1) = $(2)
	//
	// Unlike the value, a name is never lazy -- it decides which
	// parameter is being defined, so it has to resolve now, while any
	// metaknob arguments are still in scope.
	name := a.Name
	if strings.Contains(name, "$(") {
		expanded, err := c.expandMacrosWithFunctions(name)
		if err != nil {
			return fmt.Errorf("error expanding parameter name %q: %w", name, err)
		}
		name = strings.TrimSpace(expanded)
		if name == "" {
			return fmt.Errorf("parameter name %q expanded to nothing", a.Name)
		}
	}

	// A `+Foo = <expr>` assignment defines MY.Foo, not Foo. Applied
	// after name expansion so the two compose: `+$(TAG)_LIMIT = 4`
	// expands the name first and then takes the prefix.
	if a.ClassAdExpr {
		name = CustomAttrPrefix + name
	}

	// Set expands references to the name itself and stores the rest
	// unexpanded, for lazy evaluation.
	c.Set(name, value)
	return nil
}

// AssignedName returns the macro name an assignment actually defines.
//
// For `+Foo = <expr>` — a submit file asking for job ad attribute Foo —
// that is MY.Foo, HTCondor's other spelling for the same thing. The
// parser strips the '+' and records the intent in a flag, which left
// the assignment indistinguishable from a submit command called Foo;
// every consumer that asks "what did this file define?" has to apply
// the same rule, or they disagree about the macro namespace:
//
//   - the executor stores it under that name (after expanding any
//     macro reference in the name itself), so $(MY.Foo) expands as
//     condor_submit expands it and the submit builder has a prefix to
//     find;
//   - SubmitFile.assignedNames uses it to decide which SUBMIT COMMANDS
//     the file set. `+Max_Transfer_Input_Mb = 5` must not mark the
//     submit command max_transfer_input_mb as assigned, or its
//     param_info default is read as if the user had written it — the
//     leak documented at submitCommand, which a schedd that protects
//     the attribute rejects outright;
//   - the MCP submit linter uses it to know which $(...) references
//     resolve, so it neither warns about a live $(MY.Foo) nor stays
//     quiet about a $(Foo) that expands to nothing.
func AssignedName(a *Assignment) string {
	if a == nil {
		return ""
	}
	if a.ClassAdExpr {
		return CustomAttrPrefix + a.Name
	}
	return a.Name
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
	// Every form of include reads a file or runs a command on the host
	// doing the parsing, so all of them are off when the text being
	// parsed is not this host's own configuration.
	if c.options.NoLocalAccess {
		return fmt.Errorf("%q directives are not allowed here: this text is parsed without access to the local host", inc.Type)
	}

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

// executeUse executes a use directive from a parsed statement list (the
// submit-file path; config files go through parseMacros). Role is the text
// after "use", e.g. "FEATURE : GPUs".
func (c *Config) executeUse(use *UseDirective) error {
	category, rhs, ok := strings.Cut(use.Role, ":")
	category = strings.TrimSpace(category)
	if !ok || metaknobCategory(category) == nil {
		// Not a known metaknob: record the role, as this path always has.
		c.values["ROLE"] = use.Role
		return nil
	}
	expanded, err := c.expandMacro(category)
	if err != nil {
		return err
	}
	return c.readMetaConfig(1, expanded, strings.TrimLeft(rhs, " \t"))
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
