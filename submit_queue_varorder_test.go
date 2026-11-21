package htcondor

import (
	"strings"
	"testing"
)

// argsOf submits src once and returns each proc's Args, so a test can state
// what a queue statement produced as one value.
func argsOf(t *testing.T, src string) []string {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	res, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("submit %q: %v", src, err)
	}
	out := make([]string, 0, len(res.ProcAds))
	for _, ad := range res.ProcAds {
		expr, ok := ad.Lookup("Args")
		if !ok {
			out = append(out, "<no Args>")
			continue
		}
		out = append(out, expr.String())
	}
	return out
}

// TestLoopVariablesBindInTheOrderDeclared pins that the queue statement's
// variables take their columns left to right, including when two of them name
// the same macro.
//
// Submit macro names are case-insensitive, so `queue x,X in ...` names ONE
// macro twice: `X` takes the second column and `$(x)` reads it. The values
// used to reach the macro table through a map, which keeps the two spellings
// apart and has no order, so the surviving value was whichever the runtime
// happened to set last -- the same submit file produced different job ads from
// one run to the next. The repeat count is what makes this test meaningful;
// one parse passed about four times in five while the bug was live.
//
// Measured against SubmitHash.
func TestLoopVariablesBindInTheOrderDeclared(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{{
		name: "the second name takes the missing second column",
		src:  "arguments = $(x) E(y)\nqueue x,X in 001880202",
		want: []string{`"E(y)"`},
	}, {
		name: "declared twice, one column per item",
		src:  "arguments = [$(x)]\nqueue x,X in (\na b\nc d\n)",
		want: []string{`"[]"`, `"[]"`, `"[]"`, `"[]"`},
	}, {
		name: "declared twice, the other way round",
		src:  "arguments = [$(x)]\nqueue X,x in (\na b\nc d\n)",
		want: []string{`"[]"`, `"[]"`, `"[]"`, `"[]"`},
	}, {
		name: "three names, one macro named twice",
		src:  "arguments = [$(x)|$(y)]\nqueue x,y,X in (\na b c\n)",
		want: []string{`"[|]"`, `"[|]"`, `"[|]"`},
	}, {
		name: "distinct names keep their own columns",
		src:  "arguments = [$(x)|$(y)]\nqueue x,y in (a b, c d)",
		want: []string{`"[a|]"`, `"[b|]"`, `"[c|]"`, `"[d|]"`},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "executable = /bin/sleep\n" + c.src + "\n"
			want := strings.Join(c.want, "|")
			for i := 0; i < 50; i++ {
				if got := strings.Join(argsOf(t, src), "|"); got != want {
					t.Fatalf("parse %d of %q gave %s, want %s", i, c.src, got, want)
				}
			}
		})
	}
}
