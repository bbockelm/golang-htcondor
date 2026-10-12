package utilization

import (
	"strings"
)

// Program is the program a job runs, for naming its workflow.
//
// basename(Cmd) is the obvious answer and often the wrong one. A
// container-universe job may leave Cmd empty and put the whole command in
// its arguments ("python3 runner.py --circuit ..."), and a job whose Cmd
// is /bin/bash, python3 or apptainer runs whatever script follows -- so
// every one of a user's `bash script.sh` jobs, whatever the script, would
// be one workflow called "bash". The program is therefore the first
// thing on the command line that is not an interpreter or a wrapper: the
// script an interpreter runs, the command a wrapper starts, the image an
// `apptainer run` runs. An interpreter with nothing to run -- `python -c
// ...` -- is the interpreter.
//
// args is the job's Arguments (new syntax) or Args (old syntax); the
// tokenizer understands both quoting styles well enough to find a
// program name.
func Program(cmd, args string) string {
	tokens := splitArgs(args)
	if cmd != "" {
		tokens = append([]string{cmd}, tokens...)
	}
	// Cloned: the tokens are substrings of args, and a Job keeping its
	// program name should not keep the whole command line with it.
	return strings.Clone(programOf(tokens, 0))
}

// programOf walks a command line from its first word. depth bounds the
// recursion through `bash -c "..."` and wrappers of wrappers.
func programOf(tokens []string, depth int) string {
	if len(tokens) == 0 || depth > 4 {
		return ""
	}
	name := base(tokens[0])
	rest := tokens[1:]
	switch {
	case name == "env":
		return envProgram(rest, depth)
	case name == "time" || name == "nice" || name == "nohup" || name == "exec" || name == "stdbuf" || name == "taskset":
		return wrapperProgram(name, rest, depth)
	case name == "timeout":
		return timeoutProgram(rest, depth)
	case isShell(name):
		return shellProgram(name, rest, depth)
	case isPython(name):
		return scriptAfterFlags(rest, name, map[string]bool{"-W": true, "-X": true, "-Q": true},
			map[string]bool{"-c": true}, "-m")
	case name == "Rscript":
		return scriptAfterFlags(rest, name, nil, map[string]bool{"-e": true}, "")
	case name == "R":
		return rProgram(rest)
	case name == "perl" || name == "ruby" || name == "julia" || name == "node" || name == "nodejs":
		return scriptAfterFlags(rest, name, map[string]bool{"-I": true, "-r": true, "--project": true},
			map[string]bool{"-e": true, "-E": true, "--eval": true}, "")
	case name == "java":
		return javaProgram(rest)
	case name == "apptainer" || name == "singularity":
		return containerProgram(rest, name, depth)
	}
	return name
}

// envProgram reads env [-i] [-u NAME] [NAME=value ...] command.
func envProgram(rest []string, depth int) string {
	for len(rest) > 0 {
		t := rest[0]
		switch {
		case t == "-u" || t == "--unset" || t == "-C" || t == "--chdir" || t == "-S" || t == "--split-string":
			rest = skip(rest, 2)
		case strings.HasPrefix(t, "-") || strings.Contains(t, "="):
			rest = rest[1:]
		default:
			return orName(programOf(rest, depth+1), "env")
		}
	}
	return "env"
}

// wrapperProgram reads time, nice, nohup, exec, stdbuf and taskset, which
// run the command after their own flags.
func wrapperProgram(name string, rest []string, depth int) string {
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		if name == "nice" && rest[0] == "-n" {
			rest = rest[1:]
		}
		rest = rest[1:]
	}
	if name == "taskset" && len(rest) > 0 {
		rest = rest[1:] // the CPU mask
	}
	return orName(programOf(rest, depth+1), name)
}

// timeoutProgram reads timeout [flags] DURATION command.
func timeoutProgram(rest []string, depth int) string {
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		if rest[0] == "-s" || rest[0] == "--signal" || rest[0] == "-k" || rest[0] == "--kill-after" {
			rest = rest[1:]
		}
		rest = rest[1:]
	}
	return orName(programOf(skip(rest, 1), depth+1), "timeout")
}

// shellProgram reads a shell's script, or the program of its -c string.
func shellProgram(name string, rest []string, depth int) string {
	for i := 0; i < len(rest); i++ {
		t := rest[i]
		if t == "-c" {
			if i+1 < len(rest) {
				return orName(scriptProgram(splitArgs(rest[i+1]), depth+1), name)
			}
			return name
		}
		if strings.HasPrefix(t, "-") || strings.HasPrefix(t, "+") {
			if t == "-o" || t == "+o" {
				i++
			}
			continue
		}
		return base(t)
	}
	return name
}

// rProgram reads R -f script, R --file=script and R CMD BATCH script.
func rProgram(rest []string) string {
	for i := 0; i < len(rest); i++ {
		t := rest[i]
		switch {
		case t == "-f" && i+1 < len(rest):
			return base(rest[i+1])
		case strings.HasPrefix(t, "--file="):
			return base(strings.TrimPrefix(t, "--file="))
		case t == "CMD" && i+1 < len(rest) && rest[i+1] == "BATCH":
			for _, a := range rest[i+2:] {
				if !strings.HasPrefix(a, "-") {
					return base(a)
				}
			}
			return "R"
		}
	}
	return "R"
}

// javaProgram reads java -jar X.jar, or the main class after the options.
func javaProgram(rest []string) string {
	for i := 0; i < len(rest); i++ {
		t := rest[i]
		switch {
		case t == "-jar" && i+1 < len(rest):
			return base(rest[i+1])
		case t == "-cp" || t == "-classpath" || t == "--class-path" || t == "--module-path" || t == "-p":
			i++
		case strings.HasPrefix(t, "-"):
		default:
			return t // the main class
		}
	}
	return "java"
}

// scriptProgram is the program of a shell command string: the first
// command in it that is not setup -- changing directory, setting the
// environment, loading modules -- since `cd /work && ./analyze` runs
// analyze.
func scriptProgram(tokens []string, depth int) string {
	var segment []string
	flush := func() string {
		defer func() { segment = segment[:0] }()
		if len(segment) == 0 || shellSetup[base(segment[0])] || strings.Contains(segment[0], "=") {
			return ""
		}
		return programOf(segment, depth)
	}
	for _, t := range tokens {
		end := false
		for _, sep := range []string{"&&", "||", ";", "|"} {
			if t == sep {
				end = true
				break
			}
		}
		if end {
			if p := flush(); p != "" {
				return p
			}
			continue
		}
		if trimmed := strings.TrimSuffix(t, ";"); trimmed != t {
			segment = append(segment, trimmed)
			if p := flush(); p != "" {
				return p
			}
			continue
		}
		segment = append(segment, t)
	}
	return flush()
}

// shellSetup are commands a job script runs before its program.
var shellSetup = map[string]bool{
	"cd": true, "export": true, "set": true, "unset": true, "ulimit": true, "umask": true,
	"source": true, ".": true, "module": true, "ml": true, "echo": true, "mkdir": true,
	"true": true, "shopt": true, "trap": true, "conda": true, "hostname": true, "date": true,
}

// containerProgram reads `apptainer exec|run [flags] <image> [command...]`.
func containerProgram(rest []string, name string, depth int) string {
	if len(rest) == 0 {
		return name
	}
	sub := rest[0]
	rest = rest[1:]
	if sub != "exec" && sub != "run" {
		return name
	}
	argFlags := map[string]bool{
		"-B": true, "--bind": true, "--mount": true, "-H": true, "--home": true, "--pwd": true,
		"-W": true, "--workdir": true, "--overlay": true, "-o": true, "--env": true, "--env-file": true,
		"-S": true, "--scratch": true, "--security": true, "--app": true, "--network": true,
		"--network-args": true, "--hostname": true, "--add-caps": true, "--drop-caps": true,
	}
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		flag := rest[0]
		rest = rest[1:]
		if argFlags[flag] && !strings.Contains(flag, "=") {
			rest = skip(rest, 1)
		}
	}
	if len(rest) == 0 {
		return name
	}
	image := base(rest[0])
	if sub == "run" || len(rest) == 1 {
		return image
	}
	return orName(programOf(rest[1:], depth+1), image)
}

// scriptAfterFlags is an interpreter's script: the first argument that is
// not a flag. withArg are flags that consume the next argument; inline
// are flags that run code given on the command line, which leaves the
// interpreter as the program; module, when set, names the flag that
// runs a module, which is then the program.
func scriptAfterFlags(rest []string, name string, withArg, inline map[string]bool, module string) string {
	for i := 0; i < len(rest); i++ {
		t := rest[i]
		switch {
		case module != "" && t == module && i+1 < len(rest):
			return rest[i+1]
		case inline[t]:
			return name
		case withArg[t]:
			i++
		case strings.HasPrefix(t, "-"):
		default:
			return base(t)
		}
	}
	return name
}

func isShell(name string) bool {
	switch name {
	case "bash", "sh", "zsh", "dash", "ksh", "tcsh", "csh":
		return true
	}
	return false
}

// isPython matches python, python3, python3.11, pythonw.
func isPython(name string) bool {
	if !strings.HasPrefix(name, "python") {
		return false
	}
	return strings.Trim(name[len("python"):], "0123456789.w") == ""
}

func base(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func skip(s []string, n int) []string {
	if n >= len(s) {
		return nil
	}
	return s[n:]
}

func orName(p, name string) string {
	if p == "" {
		return name
	}
	return p
}

// splitArgs splits a command line into words, honoring single and double
// quotes and backslash escapes. HTCondor's new argument syntax wraps the
// whole string in double quotes and quotes words with single quotes
// (doubling a quote to escape it); the old syntax escapes double quotes
// with a backslash. Both come apart into the right words here, which is
// all naming a program needs.
func splitArgs(s string) []string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' && !strings.Contains(s[1:len(s)-1], `"`) {
		s = s[1 : len(s)-1]
	}
	// A word with no quoting or escapes in it is a substring of s; only
	// the others are copied out, through buf.
	var out []string
	var buf []byte
	start := -1 // where the current word began, or -1 between words
	plain := true
	var quote byte
	unplain := func(i int) {
		if plain {
			buf = append(buf[:0], s[start:i]...)
			plain = false
		}
	}
	end := func(i int) {
		if plain {
			out = append(out, s[start:i])
		} else {
			out = append(out, string(buf))
		}
		start, plain = -1, true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				if quote == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					buf = append(buf, '\'')
					i++
					continue
				}
				quote = 0
				continue
			}
			if c == '\\' && quote == '"' && i+1 < len(s) {
				i++
				c = s[i]
			}
			buf = append(buf, c)
		case c == '\'' || c == '"':
			if start < 0 {
				start = i
			}
			unplain(i)
			quote = c
		case c == '\\' && i+1 < len(s):
			if start < 0 {
				start = i
			}
			unplain(i)
			i++
			buf = append(buf, s[i])
		case c == ' ' || c == '\t' || c == '\n':
			if start >= 0 {
				end(i)
			}
		default:
			if start < 0 {
				start = i
			}
			if !plain {
				buf = append(buf, c)
			}
		}
	}
	if start >= 0 {
		end(len(s))
	}
	return out
}
