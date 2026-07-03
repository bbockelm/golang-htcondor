// Package fuzzconfig holds the differential fuzz harness comparing the native
// Go config parser (github.com/bbockelm/golang-htcondor/config) against
// HTCondor's reference C++ parser (libcondor_utils, via the oracle subpackage).
//
// Scope (mode #1): a PURE parse+expand differential. Both engines parse the
// same source with no param_info.in defaults (Go: ConfigOptions{SkipDefaults},
// C++: a fresh MACRO_SET with a NULL defaults table). A small, fixed reference
// environment (RefEnv) is prepended to every input so realistic sources that
// lean on $(MINUTE), $(FULL_HOSTNAME), etc. still resolve identically on both
// sides. Nothing in RefEnv is special-cased by expand_macro, so both engines
// treat it as ordinary macros.
package fuzzconfig

import (
	"sort"
	"strings"

	"github.com/bbockelm/golang-htcondor/config"
)

// RefEnv is the fixed reference environment prepended to every fuzz input. It
// stands in for the deterministic builtins HTCondor would otherwise inject at
// config() time (time constants) or detect from the host (FULL_HOSTNAME,
// DETECTED_*), using fixed values so the differential stays reproducible. It is
// fed to BOTH engines verbatim, so its keys appear identically on both sides.
const RefEnv = "SECOND = 1\n" +
	"MINUTE = 60\n" +
	"HOUR = 3600\n" +
	"DAY = 86400\n" +
	"WEEK = 604800\n" +
	"FULL_HOSTNAME = fuzz.example.com\n" +
	"HOSTNAME = fuzz\n" +
	"IP_ADDRESS = 127.0.0.1\n" +
	"TILDE = /var/lib/condor\n" +
	"DETECTED_CPUS = 8\n" +
	"DETECTED_CORES = 8\n" +
	"DETECTED_PHYSICAL_CPUS = 4\n" +
	"DETECTED_MEMORY = 16384\n"

// Result is the outcome of parsing a config source. It mirrors oracle.Result so
// the two engines are compared field-for-field.
type Result struct {
	Parsed bool   // false when the parser rejected the input
	Table  string // canonical "KEY\x1Fvalue\n" lines (only when Parsed)
}

// Prelude returns the full source handed to both engines: the reference
// environment followed by the fuzz input.
func Prelude(input string) string {
	return RefEnv + input
}

// refEnvKeys is the set of (uppercased) keys defined by RefEnv. The differential
// compares only what the fuzz input defines, so these scaffolding keys are
// stripped from both engines' output. (A caveat: an input that *redefines* a
// RefEnv key is not compared on that key — an acceptable, rare coverage gap.
// It also sidesteps HTCondor's "value equals built-in default" store elision,
// which drops e.g. MINUTE=60/HOUR=3600 from the C++ table but not the Go one.)
var refEnvKeys = func() map[string]bool {
	m := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimRight(RefEnv, "\n"), "\n") {
		if i := strings.IndexByte(line, '='); i > 0 {
			m[strings.ToUpper(strings.TrimSpace(line[:i]))] = true
		}
	}
	return m
}()

// StripRefEnv removes the reference-environment keys from a canonical table.
func StripRefEnv(canonTable string) string {
	if canonTable == "" {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(canonTable, "\n"), "\n") {
		key := line
		if sep := strings.IndexByte(line, 0x1f); sep >= 0 {
			key = line[:sep]
		}
		if refEnvKeys[key] {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// GoParseExpand parses text with the native Go engine (no defaults) and returns
// the canonical expanded table. text is expected to already include RefEnv (see
// Prelude); pass the identical string to oracle.ParseExpand.
func GoParseExpand(text string) Result {
	c, err := config.NewFromReaderWithOptions(strings.NewReader(text), config.ConfigOptions{SkipDefaults: true})
	if err != nil {
		return Result{Parsed: false}
	}
	keys := c.Keys()
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v, _ := c.Get(k)
		b.WriteString(k)
		b.WriteByte(0x1f)
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return Result{Parsed: true, Table: b.String()}
}
