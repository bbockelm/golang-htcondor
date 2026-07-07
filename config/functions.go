package config

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/PelicanPlatform/classad/classad"
)

// evaluateFunctionMacro evaluates function-style macros like $ENV(VAR)
func (c *Config) evaluateFunctionMacro(funcCall string) (string, error) {
	// Parse function name and arguments
	if !strings.Contains(funcCall, "(") {
		return "", fmt.Errorf("invalid function call: %s", funcCall)
	}

	lparen := strings.Index(funcCall, "(")
	funcName := strings.ToUpper(funcCall[:lparen])

	// Extract arguments (everything between parentheses)
	if !strings.HasSuffix(funcCall, ")") {
		return "", fmt.Errorf("invalid function call: missing closing paren")
	}
	argsStr := funcCall[lparen+1 : len(funcCall)-1]

	// Expand macros in the arguments first
	expandedArgs, err := c.expandMacrosWithFunctions(argsStr)
	if err != nil {
		return "", err
	}

	switch funcName {
	case "ENV":
		return c.evalENV(expandedArgs)
	case "INT":
		return c.evalINT(expandedArgs)
	case "STRING":
		return c.evalSTRING(expandedArgs)
	case "RANDOM_INTEGER":
		return c.evalRANDOM_INTEGER(expandedArgs)
	case "RANDOM_CHOICE":
		return c.evalRANDOM_CHOICE(expandedArgs)
	case "CHOICE":
		return c.evalCHOICE(expandedArgs)
	case "SUBSTR":
		return c.evalSUBSTR(expandedArgs)
	case "REAL":
		return c.evalREAL(expandedArgs)
	case "EVAL":
		return c.evalEVAL(expandedArgs)
	case "DIRNAME":
		return c.evalDIRNAME(expandedArgs)
	case "BASENAME":
		return c.evalBASENAME(expandedArgs)
	default:
		// Check if it's a filename manipulation function like $Fpd(...)
		if len(funcName) > 1 && funcName[0] == 'F' {
			return c.evalFilenameFunc(funcName[1:], expandedArgs)
		}
		return "", fmt.Errorf("unknown function: %s", funcName)
	}
}

// evalENV returns an environment variable value
func (c *Config) evalENV(args string) (string, error) {
	varName := strings.TrimSpace(args)
	if varName == "" {
		return "", fmt.Errorf("ENV requires variable name")
	}
	return os.Getenv(varName), nil
}

// evalINT converts a value to an integer
func (c *Config) evalINT(args string) (string, error) {
	value := strings.TrimSpace(args)
	if value == "" {
		return "0", nil
	}

	// Try to parse as float first (to handle "3.14" -> "3")
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return "", fmt.Errorf("INT: cannot convert %q to integer", value)
	}

	return fmt.Sprintf("%d", int64(f)), nil
}

// evalSTRING converts a value to a string (essentially a no-op but validates)
func (c *Config) evalSTRING(args string) (string, error) {
	return args, nil
}

// evalRANDOM_INTEGER generates a random integer
//
//nolint:revive // Function name matches HTCondor macro convention
func (c *Config) evalRANDOM_INTEGER(args string) (string, error) {
	parts := strings.Split(args, ",")
	if len(parts) < 2 || len(parts) > 3 {
		return "", fmt.Errorf("RANDOM_INTEGER requires 2 or 3 arguments (min, max [, step])")
	}

	minVal, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("RANDOM_INTEGER: invalid min value")
	}

	maxVal, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("RANDOM_INTEGER: invalid max value")
	}

	step := int64(1)
	if len(parts) == 3 {
		step, err = strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil {
			return "", fmt.Errorf("RANDOM_INTEGER: invalid step value")
		}
	}

	if step <= 0 {
		return "", fmt.Errorf("RANDOM_INTEGER: step must be positive")
	}

	if minVal > maxVal {
		return "", fmt.Errorf("RANDOM_INTEGER: min must be <= max")
	}

	// Calculate number of possible values
	numValues := (maxVal-minVal)/step + 1

	// Generate random value
	//nolint:gosec // G404: Non-cryptographic random is appropriate for config macros
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomIndex := r.Int63n(numValues)
	result := minVal + (randomIndex * step)

	return fmt.Sprintf("%d", result), nil
}

// evalSUBSTR extracts a substring
func (c *Config) evalSUBSTR(args string) (string, error) {
	parts := strings.SplitN(args, ",", 3)
	if len(parts) < 2 {
		return "", fmt.Errorf("SUBSTR requires at least 2 arguments (string, start [, length])")
	}

	str := strings.TrimSpace(parts[0])

	start, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return "", fmt.Errorf("SUBSTR: invalid start index")
	}

	if start < 0 || start > len(str) {
		return "", nil // Return empty string if out of bounds
	}

	if len(parts) == 2 {
		// No length specified, return from start to end
		return str[start:], nil
	}

	length, err := strconv.Atoi(strings.TrimSpace(parts[2]))
	if err != nil {
		return "", fmt.Errorf("SUBSTR: invalid length")
	}

	end := start + length
	if end > len(str) {
		end = len(str)
	}

	return str[start:end], nil
}

// evalREAL converts a value to a real number
func (c *Config) evalREAL(args string) (string, error) {
	value := strings.TrimSpace(args)
	if value == "" {
		return "0.0", nil
	}

	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return "", fmt.Errorf("REAL: cannot convert %q to real number", value)
	}

	return fmt.Sprintf("%g", f), nil
}

// expandMacrosWithFunctions expands both regular and function macros
//
//nolint:gocyclo // Complex function required for HTCondor macro expansion
func (c *Config) expandMacrosWithFunctions(value string) (string, error) {
	result := value
	maxDepth := 100
	depth := 0

	for depth < maxDepth {
		changed := false

		// First, look for function macros: $FUNC(...)
		dollarIdx := strings.Index(result, "$")

		if dollarIdx != -1 {
			// Check if this is a function macro or regular macro
			if dollarIdx+1 < len(result) && result[dollarIdx+1] == '(' {
				// This is a regular macro $(VAR)
				// Find the matching closing paren
				parenDepth := 1
				endIdx := -1
				for i := dollarIdx + 2; i < len(result); i++ {
					if result[i] == '(' {
						parenDepth++
					} else if result[i] == ')' {
						parenDepth--
						if parenDepth == 0 {
							endIdx = i
							break
						}
					}
				}

				if endIdx == -1 {
					return "", fmt.Errorf("unmatched parentheses in macro expansion")
				}

				macroContent := result[dollarIdx+2 : endIdx]

				// Check if this is a function call (contains '(' after name)
				// But not if it starts with '$' (that's a nested macro like $($(1)))
				// Also not if it contains ':' before '(' (that's a default value like $(VAR:$(DEFAULT)))
				colonIdx := strings.Index(macroContent, ":")
				parenIdx := strings.Index(macroContent, "(")

				isFunctionMacro := parenIdx != -1 &&
					!strings.HasPrefix(macroContent, "$") &&
					(colonIdx == -1 || parenIdx < colonIdx)

				if isFunctionMacro {
					// This is a function macro inside $()
					replacement, err := c.evaluateFunctionMacro(macroContent)
					if err != nil {
						return "", err
					}
					result = result[:dollarIdx] + replacement + result[endIdx+1:]
					changed = true
				} else {
					// Regular variable expansion
					varName := macroContent

					// First, recursively expand the macro content if it contains macros
					if strings.Contains(varName, "$") {
						expanded, err := c.expandMacrosWithFunctions(varName)
						if err != nil {
							return "", err
						}
						varName = expanded
					}

					defaultVal := ""

					// Handle default values VAR:default
					if colonIdx := strings.Index(varName, ":"); colonIdx != -1 {
						defaultVal = varName[colonIdx+1:]
						varName = varName[:colonIdx]
						// Expand the default value itself (for nested macros like $(VAR:$(DEFAULT)))
						expandedDefault, err := c.expandMacrosWithFunctions(defaultVal)
						if err != nil {
							return "", err
						}
						defaultVal = expandedDefault
					}

					// Handle metaknob parameter special syntax
					// $(0), $(0?), $(0#), $(1), $(1?), $(1+), etc.
					if len(varName) > 0 && varName[0] >= '0' && varName[0] <= '9' {
						replacement := c.expandMetaknobParam(varName)
						result = result[:dollarIdx] + replacement + result[endIdx+1:]
						changed = true
						continue
					}

					// $(DOLLAR) is a predefined macro expanding to a literal '$'.
					// HTCondor handles it in expand_macro itself, independent of
					// the defaults table, so it resolves even in a defaults-free
					// parse.
					if strings.EqualFold(varName, "DOLLAR") {
						result = result[:dollarIdx] + "$" + result[endIdx+1:]
						changed = true
						continue
					}

					// Check for circular reference
					if c.evaluating[varName] {
						return result, fmt.Errorf("circular reference detected: %s", varName)
					}

					c.evaluating[varName] = true
					replacement, ok := c.values[varName]
					if !ok {
						replacement = defaultVal
					}
					delete(c.evaluating, varName)

					result = result[:dollarIdx] + replacement + result[endIdx+1:]
					changed = true
				}
			} else if dollarIdx+1 < len(result) && isIdentStart(rune(result[dollarIdx+1])) {
				// This might be a function macro $FUNC(...)
				// Find the function name
				nameEnd := dollarIdx + 1
				for nameEnd < len(result) && (unicode.IsLetter(rune(result[nameEnd])) || result[nameEnd] == '_') {
					nameEnd++
				}

				if nameEnd < len(result) && result[nameEnd] == '(' {
					// This is a function macro
					// Find the matching closing paren
					parenDepth := 1
					endIdx := -1
					for i := nameEnd + 1; i < len(result); i++ {
						if result[i] == '(' {
							parenDepth++
						} else if result[i] == ')' {
							parenDepth--
							if parenDepth == 0 {
								endIdx = i
								break
							}
						}
					}

					if endIdx == -1 {
						return "", fmt.Errorf("unmatched parentheses in function macro")
					}

					funcCall := result[dollarIdx+1 : endIdx+1]
					replacement, err := c.evaluateFunctionMacro(funcCall)
					if err != nil {
						return "", err
					}
					result = result[:dollarIdx] + replacement + result[endIdx+1:]
					changed = true
				}
			}
		}

		depth++

		// If nothing changed, we're done
		if !changed {
			break
		}
	}

	if depth >= maxDepth {
		return "", fmt.Errorf("macro expansion depth exceeded")
	}

	return result, nil
}

// evalEVAL evaluates a ClassAd expression and returns the result
// $EVAL(item-to-convert) expands, evaluates, and returns a classad unparsed version
// of item-to-convert. The resulting value is formatted using the equivalent of
// the "%v" format specifier - if it is a string it is printed without quotes,
// otherwise it is unparsed as a classad value.
func (c *Config) evalEVAL(args string) (string, error) {
	// The argument should already be expanded (expandedArgs)
	exprStr := strings.TrimSpace(args)
	if exprStr == "" {
		return "", fmt.Errorf("EVAL requires an expression argument")
	}

	// Create a ClassAd context with current config values
	ad := classad.New()
	for key, val := range c.values {
		// Skip internal parameters (numbered params for metaknobs)
		if len(key) == 1 && key[0] >= '0' && key[0] <= '9' {
			continue
		}
		// Try to parse the value as an expression, otherwise treat as string
		if expr, err := classad.ParseExpr(val); err == nil {
			ad.InsertExpr(key, expr)
		} else {
			_ = ad.Set(key, val)
		}
	}

	// Parse the expression to evaluate
	expr, err := classad.ParseExpr(exprStr)
	if err != nil {
		return "", fmt.Errorf("EVAL: failed to parse expression %q: %w", exprStr, err)
	}

	// Evaluate the expression
	result := expr.Eval(ad)

	// Format the result based on its type
	// For strings, return without quotes (like %v format)
	// For other types, use ClassAd unparsed format
	switch {
	case result.IsUndefined():
		return "undefined", nil
	case result.IsError():
		return "error", nil
	case result.IsString():
		// Return string value without quotes
		strVal, _ := result.StringValue()
		return strVal, nil
	case result.IsInteger():
		intVal, _ := result.IntValue()
		return fmt.Sprintf("%d", intVal), nil
	case result.IsReal():
		realVal, _ := result.RealValue()
		return fmt.Sprintf("%g", realVal), nil
	case result.IsBool():
		boolVal, _ := result.BoolValue()
		if boolVal {
			return "true", nil
		}
		return "false", nil
	case result.IsList():
		// Lists should be unparsed as ClassAd list literals
		return result.String(), nil
	case result.IsClassAd():
		// ClassAds should be unparsed as ClassAd records
		return result.String(), nil
	default:
		// Fallback to string representation
		return result.String(), nil
	}
}

// evalRANDOM_CHOICE randomly selects one item from the provided list
//
//nolint:revive // Function name matches HTCondor's RANDOM_CHOICE macro
func (c *Config) evalRANDOM_CHOICE(args string) (string, error) {
	if args == "" {
		return "", fmt.Errorf("RANDOM_CHOICE requires at least one argument")
	}

	parts := splitArgs(args)
	if len(parts) == 0 {
		return "", fmt.Errorf("RANDOM_CHOICE requires at least one argument")
	}

	//nolint:gosec // G404: Non-cryptographic random is appropriate for config macros
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomIndex := r.Intn(len(parts))
	return parts[randomIndex], nil
}

// evalCHOICE selects an item from a list by index
func (c *Config) evalCHOICE(args string) (string, error) {
	parts := splitArgs(args)
	if len(parts) < 2 {
		return "", fmt.Errorf("CHOICE requires at least 2 arguments (index, item1 [, item2, ...])")
	}

	index, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", fmt.Errorf("CHOICE: invalid index value")
	}

	// The first argument is the index, remaining are the choices
	choices := parts[1:]

	if index < 0 || index >= len(choices) {
		return "", fmt.Errorf("CHOICE: index %d out of bounds (0-%d)", index, len(choices)-1)
	}

	return choices[index], nil
}

// evalDIRNAME returns the directory portion of a path (same as $Fp)
func (c *Config) evalDIRNAME(args string) (string, error) {
	return c.evalFilenameFunc("p", args)
}

// evalBASENAME returns the filename without the path
func (c *Config) evalBASENAME(args string) (string, error) {
	parts := splitArgs(args)
	if len(parts) == 0 || parts[0] == "" {
		return "", fmt.Errorf("BASENAME requires a filename argument")
	}

	filename := strings.TrimSpace(parts[0])
	base := filepath.Base(filename)

	// If a suffix is provided, remove it
	if len(parts) >= 2 {
		suffix := strings.TrimSpace(parts[1])
		base = strings.TrimSuffix(base, suffix)
	} else {
		// No suffix provided, behave like $Fnx (remove extension)
		ext := filepath.Ext(base)
		if ext != "" {
			base = base[:len(base)-len(ext)]
		}
		base += ext // Add back extension if present (Fnx includes extension)
	}

	return base, nil
}

// evalFilenameFunc handles the $F[fpduwnxbqa] family of filename manipulation functions
//
//nolint:gocyclo // Complex function required for filename manipulation options
func (c *Config) evalFilenameFunc(options string, args string) (string, error) {
	filename := strings.TrimSpace(args)
	if filename == "" {
		return "", fmt.Errorf("filename function requires a filename argument")
	}

	// Parse options (case-insensitive)
	options = strings.ToLower(options)
	var (
		fullPath     bool // f - convert relative path to full path
		dirPath      bool // p - entire directory portion with trailing slash
		lastDir      bool // d - last directory portion with trailing slash
		unixSlash    bool // u - use Unix-style slashes
		windowsSlash bool // w - use Windows-style backslashes
		baseName     bool // n - filename without extension
		extension    bool // x - file extension with period
		noTrailing   bool // b - omit trailing slash (with d) or period (with x)
		quote        bool // q - enclose in quotes
		singleQuote  bool // a - with q, use single quotes
	)

	for _, opt := range options {
		switch opt {
		case 'f':
			fullPath = true
		case 'p':
			dirPath = true
		case 'd':
			lastDir = true
		case 'u':
			unixSlash = true
		case 'w':
			windowsSlash = true
		case 'n':
			baseName = true
		case 'x':
			extension = true
		case 'b':
			noTrailing = true
		case 'q':
			quote = true
		case 'a':
			singleQuote = true
		default:
			return "", fmt.Errorf("unknown filename function option: %c", opt)
		}
	}

	result := filename

	// f - Convert relative to full path
	if fullPath {
		if !filepath.IsAbs(result) {
			// Note: This only makes sense in submit file context
			// For now, just make it absolute relative to current directory
			if absPath, err := filepath.Abs(result); err == nil {
				result = absPath
			}
		}
	}

	// p - Directory portion with trailing slash
	if dirPath {
		dir := filepath.Dir(result)
		if dir == "." {
			dir = ""
		}
		result = dir
		if result != "" && !strings.HasSuffix(result, string(filepath.Separator)) {
			result += string(filepath.Separator)
		}
	}

	// d - Last directory portion with trailing slash
	if lastDir {
		dir := filepath.Dir(result)
		if dir != "." && dir != "" {
			result = filepath.Base(dir)
			if !noTrailing {
				result += string(filepath.Separator)
			}
		} else {
			result = ""
		}
	}

	// n and x together means base name with extension
	// n alone means base name without extension
	// x alone means extension only
	switch {
	case baseName && extension:
		// Both n and x: return basename with extension (like $Fnx)
		result = filepath.Base(result)
	case baseName:
		// n - Filename without extension
		base := filepath.Base(result)
		ext := filepath.Ext(base)
		if ext != "" {
			result = base[:len(base)-len(ext)]
		} else {
			result = base
		}
	case extension:
		// x - File extension with period
		ext := filepath.Ext(filepath.Base(result))
		if noTrailing && strings.HasPrefix(ext, ".") {
			ext = ext[1:] // Remove leading period
		}
		result = ext
	}

	// u - Unix-style slashes (apply before quotes)
	if unixSlash {
		result = filepath.ToSlash(result)
	}

	// w - Windows-style backslashes (apply before quotes)
	if windowsSlash {
		result = filepath.FromSlash(result)
	}

	// q - Quote the result
	if quote {
		if singleQuote {
			result = "'" + result + "'"
		} else {
			result = "\"" + result + "\""
		}
	}

	return result, nil
}

// splitArgs splits a comma-separated argument list, respecting nested function calls
func splitArgs(args string) []string {
	var result []string
	var current strings.Builder
	parenDepth := 0

	for i := 0; i < len(args); i++ {
		ch := args[i]
		switch ch {
		case '(':
			parenDepth++
			current.WriteByte(ch)
		case ')':
			parenDepth--
			current.WriteByte(ch)
		case ',':
			if parenDepth == 0 {
				result = append(result, strings.TrimSpace(current.String()))
				current.Reset()
			} else {
				current.WriteByte(ch)
			}
		default:
			current.WriteByte(ch)
		}
	}

	// Add the last argument
	if current.Len() > 0 {
		result = append(result, strings.TrimSpace(current.String()))
	}

	return result
}
