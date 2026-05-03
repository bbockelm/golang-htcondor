package matchanalyzer

import (
	"reflect"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/parser"
)

// parseExpr is a test helper: parses a bare expression string into an
// ast.Expr by wrapping it in a single-attribute ClassAd. This is the same
// trick the production lookupRequirements uses; centralizing it here keeps
// every test from open-coding the ParseExpr → ast.Expr extraction dance.
func parseExpr(t *testing.T, s string) ast.Expr {
	t.Helper()
	node, err := parser.Parse("[__t__ = " + s + "]")
	if err != nil {
		t.Fatalf("parse(%q): %v", s, err)
	}
	ad, ok := node.(*ast.ClassAd)
	if !ok || len(ad.Attributes) != 1 {
		t.Fatalf("parse(%q): unexpected node shape: %T", s, node)
	}
	return ad.Attributes[0].Value
}

func TestShallowAndDecomposerSplitsTopLevelAnd(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantSources []string // expected predicate.Source values, in order
	}{
		{
			name:        "no AND — single predicate",
			input:       `Arch == "Linux"`,
			wantSources: []string{`(Arch == "Linux")`},
		},
		{
			name:  "two-way AND",
			input: `Arch == "Linux" && OpSys == "LINUX"`,
			wantSources: []string{
				`(Arch == "Linux")`,
				`(OpSys == "LINUX")`,
			},
		},
		{
			name:  "three-way AND associativity-insensitive",
			input: `(A && B) && C`,
			wantSources: []string{
				"A",
				"B",
				"C",
			},
		},
		{
			name:        "OR is NOT split — top-level || stays one predicate",
			input:       `A || B`,
			wantSources: []string{`(A || B)`},
		},
		{
			name:        "AND nested inside OR is NOT split — preserves boolean structure",
			input:       `A || (B && C)`,
			wantSources: []string{`(A || (B && C))`},
		},
	}

	d := ShallowAndDecomposer{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expr := parseExpr(t, tc.input)
			preds, err := d.Decompose(expr)
			if err != nil {
				t.Fatalf("Decompose: %v", err)
			}
			got := make([]string, len(preds))
			for i, p := range preds {
				got[i] = p.Source
			}
			if !reflect.DeepEqual(got, tc.wantSources) {
				t.Errorf("predicates:\n  got  = %q\n  want = %q", got, tc.wantSources)
			}
		})
	}
}

func TestShallowAndDecomposerEmptyExpression(t *testing.T) {
	// Nil input is the "no Requirements set" case. We want a single
	// trivially-true predicate — vacuous but non-empty so callers don't
	// need to special-case the zero result.
	preds, err := ShallowAndDecomposer{}.Decompose(nil)
	if err != nil {
		t.Fatalf("Decompose(nil): %v", err)
	}
	if len(preds) != 1 {
		t.Fatalf("expected 1 predicate, got %d", len(preds))
	}
	if _, ok := preds[0].Expr.(*ast.BooleanLiteral); !ok {
		t.Errorf("nil decomposition should yield BooleanLiteral, got %T", preds[0].Expr)
	}
}

func TestCollectSlotAttrRefs(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want []string
	}{
		{
			name: "bare reference",
			expr: `Arch == "Linux"`,
			want: []string{"Arch"},
		},
		{
			name: "TARGET reference plus bare ref — both included (conservative projection)",
			expr: `RequestCpus <= TARGET.Cpus`,
			want: []string{"Cpus", "RequestCpus"},
		},
		{
			name: "MY reference is excluded — points at job not slot",
			expr: `MY.RequestMemory <= TARGET.Memory`,
			want: []string{"Memory"},
		},
		{
			name: "multiple distinct refs are sorted",
			expr: `Arch == "Linux" && OpSys == "LINUX" && Memory >= 1024`,
			want: []string{"Arch", "Memory", "OpSys"},
		},
		{
			name: "duplicate references collapsed",
			expr: `Memory >= 1024 && Memory < 8192`,
			want: []string{"Memory"},
		},
		{
			name: "function arguments traversed",
			expr: `regexp("foo", Name)`,
			want: []string{"Name"},
		},
		{
			name: "string literal contributes nothing",
			expr: `"static string" == "another"`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := collectSlotAttrRefs(parseExpr(t, tc.expr))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUnionStrings(t *testing.T) {
	got := unionStrings(
		[]string{"c", "a"},
		[]string{"b", "a"},
		nil,
		[]string{"c"},
	)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if got := unionStrings(); got != nil {
		t.Errorf("union of nothing should be nil, got %v", got)
	}
}

// TestDecomposerInterfaceIsExtensible is a compile-time assertion that
// arbitrary types satisfying Decomposer are interchangeable with
// ShallowAndDecomposer at the API surface. It exists to lock in the
// "shallow today, deeper later" architectural choice — if a future change
// inadvertently bakes ShallowAndDecomposer into a function signature, this
// test stops compiling.
func TestDecomposerInterfaceIsExtensible(t *testing.T) {
	// Compile-time assertion: both implementations satisfy Decomposer.
	// The unused first assignment exists purely to make the "two
	// independent implementations" point — it would be silently
	// elidable, so we tag it as such for the linter.
	_ = Decomposer(ShallowAndDecomposer{})
	var d Decomposer = constDecomposer{}
	preds, err := d.Decompose(parseExpr(t, "true"))
	if err != nil || len(preds) == 0 {
		t.Fatalf("constDecomposer: preds=%v err=%v", preds, err)
	}
	if !strings.Contains(preds[0].Source, "stub") {
		t.Errorf("expected stub source, got %q", preds[0].Source)
	}
}

// constDecomposer is a tiny alternate Decomposer implementation used only
// in TestDecomposerInterfaceIsExtensible to prove the interface is open.
type constDecomposer struct{}

func (constDecomposer) Decompose(_ ast.Expr) ([]Predicate, error) {
	return []Predicate{{Source: "stub", Expr: &ast.BooleanLiteral{Value: true}}}, nil
}
