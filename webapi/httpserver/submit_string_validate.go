package httpserver

import (
	"fmt"
	"regexp"
)

// gpuFieldShortPattern allows the small set of characters seen in
// well-formed gpus_minimum_capability / gpus_minimum_runtime /
// cuda_version values: digits, dot, comma, equals, space, colon,
// underscore, hyphen, plus. This explicitly forbids newline, the
// HTCondor submit-file line continuation backslash, and `+`-prefixed
// custom-attribute syntax — all of which would let an attacker
// inject extra submit directives.
var gpuFieldShortPattern = regexp.MustCompile(`^[A-Za-z0-9_.+:= -]*$`)

// gpuFieldExpressionPattern is for fields like require_gpus that
// take a ClassAd boolean expression. We allow the same characters
// plus parentheses, comparison operators, and the boolean operators
// `&&` / `||`. Newline is still forbidden — that's the actual
// injection vector. Identifiers in HTCondor attribute names are
// alphanumerics + underscore only.
var gpuFieldExpressionPattern = regexp.MustCompile(`^[A-Za-z0-9_.+:= ()<>!&|"-]*$`)

// validateGPUSubmitString rejects values that would inject extra
// submit-file directives when concatenated into resourceRequestLines
// via fmt.Fprintf. The whitelist approach is intentional: we'd
// rather refuse a quirky value the user could rephrase than try to
// exhaustively blacklist newline-flavored injection variants.
//
// allowExpression should be true for fields that accept a ClassAd
// expression (parentheses + boolean operators), false for plain
// identifier-like values.
func validateGPUSubmitString(field, value string, allowExpression bool) error {
	if value == "" {
		return nil
	}
	if len(value) > 256 {
		return fmt.Errorf("%s is too long (max 256 chars)", field)
	}
	pattern := gpuFieldShortPattern
	if allowExpression {
		pattern = gpuFieldExpressionPattern
	}
	if !pattern.MatchString(value) {
		return fmt.Errorf("%s contains disallowed characters; only the small subset used by HTCondor GPU directives is accepted", field)
	}
	return nil
}

// validateGPUSubmitFields runs validateGPUSubmitString on the four
// LLM/UI-supplied GPU fields. Used by both
// InteractiveCreateTerminalRequest.validate and
// JupyterCreateRequest.validate so the two paths agree on policy.
func validateGPUSubmitFields(gpusMinCapability, gpusMinRuntime, cudaVersion, requireGpus string) error {
	if err := validateGPUSubmitString("gpus_minimum_capability", gpusMinCapability, false); err != nil {
		return err
	}
	if err := validateGPUSubmitString("gpus_minimum_runtime", gpusMinRuntime, false); err != nil {
		return err
	}
	if err := validateGPUSubmitString("cuda_version", cudaVersion, false); err != nil {
		return err
	}
	if err := validateGPUSubmitString("require_gpus", requireGpus, true); err != nil {
		return err
	}
	return nil
}
