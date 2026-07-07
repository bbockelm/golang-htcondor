package config

import (
	"fmt"
	"strconv"
	"strings"
)

// evaluateCondition evaluates a conditional expression
func (c *Config) evaluateCondition(condition string) (bool, error) {
	condition = strings.TrimSpace(condition)

	// In HTCondor-compat mode, reject the compound logical operators: an
	// HTCondor `if` accepts only a bare boolean, `defined X`, or
	// `version <op> x` — no && / ||. (Version conditions never contain these,
	// so this is safe to check up front.)
	if c.options.HTCondorCompat && (strings.Contains(condition, "&&") || strings.Contains(condition, "||")) {
		return false, fmt.Errorf("if-condition %q: HTCondor does not support && / || (Go extension; enable it by leaving HTCondorCompat off)", condition)
	}

	// Handle logical operators first (before checking for specific patterns)
	// This allows compound expressions like "defined(FOO) && defined(BAR)"
	if strings.Contains(condition, "&&") {
		parts := strings.SplitN(condition, "&&", 2)
		left, err := c.evaluateCondition(strings.TrimSpace(parts[0]))
		if err != nil {
			return false, err
		}
		if !left {
			return false, nil // Short circuit
		}
		return c.evaluateCondition(strings.TrimSpace(parts[1]))
	}

	if strings.Contains(condition, "||") {
		parts := strings.SplitN(condition, "||", 2)
		left, err := c.evaluateCondition(strings.TrimSpace(parts[0]))
		if err != nil {
			return false, err
		}
		if left {
			return true, nil // Short circuit
		}
		return c.evaluateCondition(strings.TrimSpace(parts[1]))
	}

	// Handle negation
	if strings.HasPrefix(condition, "!") {
		result, err := c.evaluateCondition(strings.TrimSpace(condition[1:]))
		return !result, err
	}

	// Handle defined(VAR) checks - both "defined(VAR)" and "defined VAR"
	if strings.HasPrefix(condition, "defined(") && strings.HasSuffix(condition, ")") {
		varName := condition[8 : len(condition)-1]
		varName = strings.TrimSpace(varName)
		_, ok := c.values[varName]
		return ok, nil
	}

	// Handle "defined VAR" syntax (without parentheses)
	if strings.HasPrefix(condition, "defined ") {
		varName := strings.TrimSpace(condition[8:])
		_, ok := c.values[varName]
		return ok, nil
	}

	// Handle version comparisons: "version >= 8.9.0"
	if strings.HasPrefix(condition, "version ") {
		return c.evaluateVersionCondition(condition[8:])
	}

	// Handle boolean expressions and variable references
	// Simple case: just a variable name that should evaluate to true/false/yes/no/1/0
	value, ok := c.values[condition]
	if ok {
		return c.isTruthy(value), nil
	}

	// In HTCondor-compat mode, reject relational/equality comparisons: they are
	// a Go extension. (`version <op> x` was already consumed above, so any
	// operator reaching here is a bare comparison HTCondor would reject.)
	if c.options.HTCondorCompat {
		for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
			if strings.Contains(condition, op) {
				return false, fmt.Errorf("if-condition %q: HTCondor does not support the %q comparison (Go extension; enable it by leaving HTCondorCompat off)", condition, op)
			}
		}
	}

	// Handle comparison operators
	if strings.Contains(condition, "==") {
		parts := strings.SplitN(condition, "==", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])
		leftVal, _ := c.expandMacrosWithFunctions(left)
		rightVal, _ := c.expandMacrosWithFunctions(right)
		return leftVal == rightVal, nil
	}

	if strings.Contains(condition, "!=") {
		parts := strings.SplitN(condition, "!=", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])
		leftVal, _ := c.expandMacrosWithFunctions(left)
		rightVal, _ := c.expandMacrosWithFunctions(right)
		return leftVal != rightVal, nil
	}

	// Handle numeric comparisons
	for _, op := range []string{">=", "<=", ">", "<"} {
		if strings.Contains(condition, op) {
			parts := strings.SplitN(condition, op, 2)
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			return c.evaluateNumericComparison(left, op, right)
		}
	}

	// Default: try to evaluate as truthy
	expanded, _ := c.expandMacrosWithFunctions(condition)
	return c.isTruthy(expanded), nil
}

// evaluateVersionCondition evaluates version comparison like ">= 8.9.0"
func (c *Config) evaluateVersionCondition(condition string) (bool, error) {
	condition = strings.TrimSpace(condition)

	// Parse operator and version
	var op, versionStr string
	for _, operator := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if strings.HasPrefix(condition, operator) {
			op = operator
			versionStr = strings.TrimSpace(condition[len(operator):])
			break
		}
	}

	if op == "" {
		return false, fmt.Errorf("invalid version condition: %s", condition)
	}

	// Get current HTCondor version (default to a reasonable version for testing)
	currentVersion := c.values["CONDOR_VERSION"]
	if currentVersion == "" {
		currentVersion = "9.0.0" // Default for testing
	}

	// Compare versions
	cmp := compareVersions(currentVersion, versionStr)

	switch op {
	case ">=":
		return cmp >= 0, nil
	case "<=":
		return cmp <= 0, nil
	case ">":
		return cmp > 0, nil
	case "<":
		return cmp < 0, nil
	case "==":
		return cmp == 0, nil
	case "!=":
		return cmp != 0, nil
	}

	return false, fmt.Errorf("unknown operator: %s", op)
}

// compareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	// Extract just the version number (strip any prefix like "$CondorVersion: ")
	v1 = extractVersionNumber(v1)
	v2 = extractVersionNumber(v2)

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int

		if i < len(parts1) {
			n1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			n2, _ = strconv.Atoi(parts2[i])
		}

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	return 0
}

// extractVersionNumber extracts version number from strings like "$CondorVersion: 9.0.0"
func extractVersionNumber(version string) string {
	// If it contains ":", extract the part after it
	if idx := strings.Index(version, ":"); idx != -1 {
		version = version[idx+1:]
	}

	// Trim whitespace and any trailing text
	version = strings.TrimSpace(version)
	parts := strings.Fields(version)
	if len(parts) > 0 {
		return parts[0]
	}

	return version
}

// evaluateNumericComparison evaluates numeric comparison
func (c *Config) evaluateNumericComparison(left, op, right string) (bool, error) {
	leftVal, err := c.expandMacrosWithFunctions(left)
	if err != nil {
		return false, err
	}

	rightVal, err := c.expandMacrosWithFunctions(right)
	if err != nil {
		return false, err
	}

	leftNum, err1 := strconv.ParseFloat(leftVal, 64)
	rightNum, err2 := strconv.ParseFloat(rightVal, 64)

	if err1 != nil || err2 != nil {
		// Fall back to string comparison
		switch op {
		case ">":
			return leftVal > rightVal, nil
		case "<":
			return leftVal < rightVal, nil
		case ">=":
			return leftVal >= rightVal, nil
		case "<=":
			return leftVal <= rightVal, nil
		}
	}

	switch op {
	case ">":
		return leftNum > rightNum, nil
	case "<":
		return leftNum < rightNum, nil
	case ">=":
		return leftNum >= rightNum, nil
	case "<=":
		return leftNum <= rightNum, nil
	}

	return false, fmt.Errorf("unknown operator: %s", op)
}

// isTruthy determines if a value should be considered true
func (c *Config) isTruthy(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "true", "yes", "1", "on":
		return true
	case "false", "no", "0", "off", "":
		return false
	default:
		// Non-empty string is truthy
		return value != ""
	}
}
