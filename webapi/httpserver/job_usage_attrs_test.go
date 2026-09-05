package httpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestMemoryUsageReachesTheClientAsANumber is the reported bug: the job page
// showed "-" for memory on a job that had plainly used some.
//
// The schedd stores MemoryUsage as an expression over ResidentSetSize, and a
// ClassAd carrying an expression serialises to the literal string
// "/Expr(((ResidentSetSize + 1023) / 1024))/". Every client then has to
// implement a ClassAd evaluator to read a memory figure, and the Web UI --
// which reasonably just calls Number() -- got NaN and rendered a dash.
func TestMemoryUsageReachesTheClientAsANumber(t *testing.T) {
	ad, err := classad.Parse(`[
		MemoryUsage = ((ResidentSetSize + 1023) / 1024);
		ResidentSetSize = 75000;
		ResidentSetSize_RAW = 64380
	]`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Before: the wire carries the expression.
	before, err := json.Marshal(ad)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(before), "/Expr(") {
		t.Fatalf("expected the unevaluated form to contain an expression, got %s", before)
	}

	evaluateUsageAttrs(ad)

	after, err := json.Marshal(ad)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(after), "/Expr(") {
		t.Errorf("an expression survived evaluation: %s", after)
	}

	var got map[string]any
	if err := json.Unmarshal(after, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// (75000 + 1023) / 1024 == 74 under ClassAd integer division.
	n, ok := got["MemoryUsage"].(float64)
	if !ok {
		t.Fatalf("MemoryUsage is %T (%v), want a JSON number", got["MemoryUsage"], got["MemoryUsage"])
	}
	if n != 74 {
		t.Errorf("MemoryUsage = %v, want 74", n)
	}
}

func TestEvaluateUsageAttrs(t *testing.T) {
	t.Run("a literal is left alone", func(t *testing.T) {
		ad, _ := classad.Parse(`[MemoryUsage = 512; DiskUsage = 1024]`)
		evaluateUsageAttrs(ad)
		if v, ok := ad.EvaluateAttrInt("MemoryUsage"); !ok || v != 512 {
			t.Errorf("MemoryUsage = %d (ok=%v), want 512", v, ok)
		}
		if v, ok := ad.EvaluateAttrInt("DiskUsage"); !ok || v != 1024 {
			t.Errorf("DiskUsage = %d (ok=%v), want 1024", v, ok)
		}
	})

	t.Run("an unevaluable expression is left visible", func(t *testing.T) {
		// The realistic cause is a projection that omitted the attribute
		// the expression refers to. Emitting a number here would be
		// inventing one; leaving the expression says what is missing.
		ad, _ := classad.Parse(`[MemoryUsage = ((ResidentSetSize + 1023) / 1024)]`)
		evaluateUsageAttrs(ad)
		b, _ := json.Marshal(ad)
		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		v, _ := got["MemoryUsage"].(string)
		if !strings.HasPrefix(v, "/Expr(") {
			t.Errorf("expected the expression to survive, got %#v", got["MemoryUsage"])
		}
	})

	t.Run("reals keep their fraction", func(t *testing.T) {
		ad, _ := classad.Parse(`[CpusUsage = (1.5 + 0.25)]`)
		evaluateUsageAttrs(ad)
		v, ok := ad.EvaluateAttrReal("CpusUsage")
		if !ok || v != 1.75 {
			t.Errorf("CpusUsage = %v (ok=%v), want 1.75", v, ok)
		}
		b, _ := json.Marshal(ad)
		if strings.Contains(string(b), "/Expr(") {
			t.Errorf("real expression not evaluated: %s", b)
		}
	})

	t.Run("policy expressions are untouched", func(t *testing.T) {
		// The allowlist exists so that expressions describing RULES stay
		// expressions. Collapsing Requirements to whatever it evaluates to
		// right now would destroy what an operator reads the raw ad for.
		ad, _ := classad.Parse(`[
			Requirements = (Memory > 1024);
			PeriodicRemove = (JobStatus == 5);
			Memory = 2048;
			MemoryUsage = ((ResidentSetSize + 1023) / 1024);
			ResidentSetSize = 2048
		]`)
		evaluateUsageAttrs(ad)
		b, _ := json.Marshal(ad)
		// Assert on decoded values, not the raw bytes: JSON escapes the
		// leading slash, so a substring match for `"/Expr(` silently never
		// matches and the check passes for the wrong reason.
		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, keep := range []string{"Requirements", "PeriodicRemove"} {
			v, _ := got[keep].(string)
			if !strings.HasPrefix(v, "/Expr(") {
				t.Errorf("%s should still be an expression, got %#v", keep, got[keep])
			}
		}
		// (2048 + 1023) / 1024 == 2 under integer division.
		if n, ok := got["MemoryUsage"].(float64); !ok || n != 2 {
			t.Errorf("MemoryUsage = %#v, want the number 2", got["MemoryUsage"])
		}
	})

	t.Run("a missing attribute is not invented", func(t *testing.T) {
		ad, _ := classad.Parse(`[ClusterId = 1]`)
		evaluateUsageAttrs(ad)
		if _, ok := ad.Lookup("MemoryUsage"); ok {
			t.Errorf("evaluateUsageAttrs added MemoryUsage to an ad that had none")
		}
	})

	t.Run("nil ad does not panic", func(*testing.T) {
		evaluateUsageAttrs(nil)
	})
}
