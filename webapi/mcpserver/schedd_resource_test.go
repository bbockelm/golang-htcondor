package mcpserver

import (
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestScheddAdConstraintNamesThisServersSchedd: the status resource asked the
// collector for every schedd in the pool and returned ads[0], so on a pool with
// more than one access point it described somebody else's machine as though it
// were the one this server submits to.
func TestScheddAdConstraintNamesThisServersSchedd(t *testing.T) {
	c, err := scheddAdConstraint(htcondor.NewSchedd("ap2001.chtc.wisc.edu", "<10.0.0.1:9618?sock=schedd>"))
	if err != nil {
		t.Fatalf("constraint: %v", err)
	}
	if c != `Name == "ap2001.chtc.wisc.edu"` {
		t.Errorf("constraint = %q, want it to name this schedd", c)
	}
	// The failure mode being fixed: anything that matches the whole pool.
	if strings.Contains(c, "true") {
		t.Errorf("constraint matches every schedd in the pool: %q", c)
	}
}

// TestScheddAdConstraintFallsBackToAddress covers a schedd discovered by
// address, with no name to match on.
func TestScheddAdConstraintFallsBackToAddress(t *testing.T) {
	c, err := scheddAdConstraint(htcondor.NewSchedd("", "<10.0.0.1:9618?sock=schedd>"))
	if err != nil {
		t.Fatalf("constraint: %v", err)
	}
	if c != `MyAddress == "<10.0.0.1:9618?sock=schedd>"` {
		t.Errorf("constraint = %q, want it to name the address being dialled", c)
	}
}

// TestScheddAdConstraintRefusesToGuess: with nothing to identify the schedd,
// saying so beats describing an arbitrary one, since the caller cannot tell
// which they were given.
func TestScheddAdConstraintRefusesToGuess(t *testing.T) {
	if _, err := scheddAdConstraint(htcondor.NewSchedd("", "")); err == nil {
		t.Error("an unidentifiable schedd produced a constraint anyway")
	}
	if _, err := scheddAdConstraint(nil); err == nil {
		t.Error("a nil schedd produced a constraint anyway")
	}
}

func TestQuoteClassAdString(t *testing.T) {
	if got := quoteClassAdString(`ap2001`); got != `"ap2001"` {
		t.Errorf("got %s", got)
	}
	if got := quoteClassAdString(`we"ird`); got != `"we\"ird"` {
		t.Errorf("got %s", got)
	}
}
