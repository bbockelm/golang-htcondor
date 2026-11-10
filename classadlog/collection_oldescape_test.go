package classadlog

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestSetAttributeKeepsOldClassAdEscapes is the regression for corrupted job_queue.log
// attributes: a TransferInput value whose filename contains an escaped comma and space (so it
// does not split the transfer list) is old-ClassAd text, where a backslash is a backslash.
// Reading it as new ClassAd interprets the escapes away and the filename silently becomes two
// transfer-list entries; the old-ClassAd parse keeps the value as the schedd wrote it.
func TestSetAttributeKeepsOldClassAdEscapes(t *testing.T) {
	val := `"osdf:///chtc/staging/c/ckoch5/tests/space-comma/testing\,\ more"`
	const kept = `osdf:///chtc/staging/c/ckoch5/tests/space-comma/testing\,\ more`

	// Strict parsing accepts this value and answers a DIFFERENT string: it reads \, and \
	// as escapes and drops the backslashes. That is the corruption, so pin it here rather
	// than assume it -- it is the whole reason SetAttribute does not use this parser.
	strict, err := classad.ParseExpr(val)
	if err != nil {
		t.Fatalf("strict ParseExpr: %v", err)
	}
	loose, err := strict.Eval(classad.New()).StringValue()
	if err != nil {
		t.Fatalf("strict parse did not evaluate to a string: %v", err)
	}
	if loose == kept {
		t.Fatal("precondition: strict parsing no longer changes the value, so this test proves nothing")
	}

	c := NewCollection()
	if err := c.SetAttribute("1.0", "TransferInput", val); err != nil {
		t.Fatalf("SetAttribute rejected a valid old-ClassAd value: %v", err)
	}
	ad := c.Get("1.0")
	if ad == nil {
		t.Fatal("ad was not created")
	}
	s, ok := ad.EvaluateAttrString("TransferInput")
	if !ok {
		t.Fatal("TransferInput not retrievable after SetAttribute")
	}
	if s != kept {
		t.Errorf("TransferInput = %q, want %q (strict parsing would give %q)", s, kept, loose)
	}
}
