package htcondor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// envV1Delimiter is env_delimiter in condor_utils/env.cpp: the character a V1
// environment string is split on, on anything that is not Windows.
const envV1Delimiter = ';'

// envPermittedDelimiters is is_permitted_delim(): a V1 environment string may
// announce its own delimiter by starting with one of these, which is how a
// value containing a semicolon is written.
const envPermittedDelimiters = "!#$%&*+,-/:;<>?@^`|~\x1f"

// setEnvironment stores the job's environment, mirroring
// SubmitHash::SetEnvironment and the Env class it leans on.
//
// The submit value and the job attribute are different encodings, and the
// parser's job is to convert between them rather than to pass text through:
//
//   - the submit file writes V1 (`A=1;B=2`, delimiter auto-detected) or V2
//     (the whole list in double quotes, `"A=1 B=2"`, with single quotes
//     around anything containing a space);
//   - the ad carries Environment in V2 RAW -- no surrounding double quotes,
//     each entry quoted per CHARACTER by append_arg, so `A=x y` is stored as
//     `A=x' 'y` -- or Env in V1 raw, with an EnvDelim naming the delimiter.
//
// Which attribute is written is a preference, not a capability: condor_submit
// writes V2 unless the submitter used the `env` keyword with a V1 value, and
// then it writes both Env and EnvDelim. Everything in between -- sorting the
// variables by name, collapsing a repeated name to its last value, rejecting
// an entry with no `=` -- falls out of Env's std::map and is reproduced here
// because the resulting STRING is what the starter reads.
func (sf *SubmitFile) setEnvironment(ad *classad.ClassAd) error {
	env1, hasEnv1 := sf.submitCommandAlt("environment", "env")
	env2, hasEnv2 := sf.submitCommand("environment2")
	if hasEnv1 && hasEnv2 && !parseBool(sf.submitParam("allow_environment_v1", ""), false) {
		return fmt.Errorf("if you wish to specify both environment and environment2, " +
			"you must also specify allow_environment_v1 = true")
	}

	// The `env` spelling with a non-V2 value is the one way to ask for the
	// V1 attribute; `environment` always produces V2.
	preferV1 := false
	if hasEnv1 && !hasEnv2 {
		if v, ok := sf.submitCommand("env"); ok && !isV2QuotedArgs(v) {
			preferV1 = true
		}
	}

	var (
		vars map[string]string
		err  error
	)
	switch {
	case hasEnv2:
		vars, err = parseEnvV2Quoted(env2)
	case hasEnv1:
		vars, err = parseEnvV1RawOrV2Quoted(env1)
	default:
		vars = map[string]string{}
	}
	if err != nil {
		return fmt.Errorf("%w\nThe environment you specified was: %q", err, firstNonEmpty(env2, env1))
	}

	if preferV1 {
		_ = ad.Set("Env", envV1Raw(vars))
		_ = ad.Set("EnvDelim", string(envV1Delimiter))
		return nil
	}
	// Written even when there is nothing in it: an absent Environment is
	// undefined to everything that reads the job, where an empty one says
	// the job runs with no environment of its own.
	_ = ad.Set("Environment", envV2Raw(vars))
	return nil
}

// parseEnvV1RawOrV2Quoted is Env::MergeFromV1RawOrV2Quoted: the V2 form is
// recognised by its surrounding double quotes, and anything else is V1.
func parseEnvV1RawOrV2Quoted(value string) (map[string]string, error) {
	if isV2QuotedArgs(value) {
		return parseEnvV2Quoted(value)
	}
	return parseEnvV1AutoDelim(value)
}

// parseEnvV2Quoted is Env::MergeFromV2Quoted: unquote the list, then split it
// the way a V2 argument list is split.
func parseEnvV2Quoted(value string) (map[string]string, error) {
	entries, err := parseArgsV2Quoted(value)
	if err != nil {
		return nil, err
	}
	return envVarsFrom(entries)
}

// parseEnvV1AutoDelim is Env::MergeFromV1AutoDelim: the delimiter is `;`
// unless the string starts with another permitted one, in which case that
// character is the delimiter and is not part of the first entry. A newline
// always ends an entry as well, and leading whitespace is dropped.
func parseEnvV1AutoDelim(value string) (map[string]string, error) {
	delim := byte(envV1Delimiter)
	if value != "" && strings.IndexByte(envPermittedDelimiters, value[0]) >= 0 {
		delim = value[0]
		value = value[1:]
	}
	var entries []string
	for _, entry := range strings.FieldsFunc(value, func(r rune) bool {
		return r == rune(delim) || r == '\n'
	}) {
		entry = strings.TrimLeft(entry, " \t\n\r")
		if entry != "" {
			entries = append(entries, entry)
		}
	}
	return envVarsFrom(entries)
}

// envVarsFrom is Env::SetEnvWithErrorMessage over a list of entries: each one
// is NAME=VALUE, a repeated name keeps its last value, and an entry with no
// `=` is an error -- condor_submit refuses the submit file over it rather
// than guessing what was meant.
func envVarsFrom(entries []string) (map[string]string, error) {
	vars := make(map[string]string, len(entries))
	for _, entry := range entries {
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" {
			return nil, fmt.Errorf("%q is not a valid environment assignment (it has no NAME=VALUE)", entry)
		}
		vars[name] = value
	}
	return vars, nil
}

// envV2Raw is Env::getDelimitedStringV2Raw: the variables, sorted by name,
// rendered NAME=VALUE and joined the way a V2 argument list is joined.
//
// The sort is not cosmetic. C++ holds the variables in a std::map, so the
// attribute it writes is in name order whatever order the submit file used,
// and a job ad built here has to produce the same STRING for the same submit
// file -- anything comparing the two reads the text, not the set.
func envV2Raw(vars map[string]string) string {
	return joinArgsV2(envEntries(vars))
}

// envV1Raw is Env::getDelimitedStringV1Raw: the same entries joined with the
// V1 delimiter.
func envV1Raw(vars map[string]string) string {
	return strings.Join(envEntries(vars), string(envV1Delimiter))
}

func envEntries(vars map[string]string) []string {
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]string, 0, len(names))
	for _, name := range names {
		entries = append(entries, name+"="+vars[name])
	}
	return entries
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
