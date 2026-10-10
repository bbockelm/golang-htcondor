package fuzzconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGoSideNeverRunsInclude pins the guard that keeps a fuzz input from
// making the Go engine read a host file or run a command: GoParseExpand
// parses with ConfigOptions{NoInclude: true}, so every include form is a
// parse error and nothing runs. It needs no oracle.
func TestGoSideNeverRunsInclude(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	for _, in := range []string{
		"include command : touch " + marker + "\n",
		"include ifexist command : touch " + marker + "\n",
		"include : touch " + marker + " |\n",
		"if true\ninclude command : touch " + marker + "\nendif\n",
		"@include output : touch " + marker + "\n",
	} {
		res := GoParseExpand(Prelude(in))
		if res.Parsed {
			t.Errorf("%q parsed; want the include refused", in)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%q ran the include command", in)
		}
	}
}
