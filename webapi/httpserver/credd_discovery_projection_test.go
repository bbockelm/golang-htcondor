package httpserver

import "testing"

// The lookup reads CredDIpAddr off the schedd ad, so the query has to ask
// for it. Nil options do not mean "the whole ad": they select the
// collector's default projection, which does not carry it -- and the
// symptom is not an error but "the schedd ad carries no CredDIpAddr"
// reported against a schedd that advertises it.
func TestCreddQueryProjectionIncludesTheAddressAttribute(t *testing.T) {
	var found bool
	for _, attr := range creddQueryProjection() {
		if attr == creddAddressAttr {
			found = true
		}
	}
	if !found {
		t.Errorf("%s missing from %v; the lookup can only fail", creddAddressAttr, creddQueryProjection())
	}
}
