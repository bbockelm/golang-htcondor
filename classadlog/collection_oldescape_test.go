package classadlog

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestSetAttributeKeepsOldClassAdEscapes is the regression for dropped job_queue.log
// attributes: a TransferInput value whose filename contains an escaped comma and space (so it
// does not split the transfer list) is old-ClassAd text. Strict ParseExpr rejects the escapes
// and SetAttribute would drop the whole attribute; the old-ClassAd (lenient) parse preserves it.
func TestSetAttributeKeepsOldClassAdEscapes(t *testing.T) {
	val := `"osdf:///chtc/staging/c/ckoch5/tests/space-comma/testing\,\ more"`

	// Precondition: strict parsing rejects it, which is why the old default dropped it.
	if _, err := classad.ParseExpr(val); err == nil {
		t.Fatal("precondition: strict ParseExpr should reject the unknown escapes")
	}

	c := NewCollection()
	if err := c.SetAttribute("1.0", "TransferInput", val); err != nil {
		t.Fatalf("SetAttribute dropped a valid old-ClassAd value: %v", err)
	}
	ad := c.Get("1.0")
	if ad == nil {
		t.Fatal("ad was not created")
	}
	s, ok := ad.EvaluateAttrString("TransferInput")
	if !ok {
		t.Fatal("TransferInput not retrievable after SetAttribute")
	}
	if !strings.Contains(s, "space-comma") {
		t.Errorf("value not preserved: %q", s)
	}
}
