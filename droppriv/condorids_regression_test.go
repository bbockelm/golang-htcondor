package droppriv

import "testing"

// TestParseIDPairDotFormat pins HTCondor's dot-separated CONDOR_IDS format
// ("<uid>.<gid>"), the regression that let a misconfigured drop silently keep root.
func TestParseIDPairDotFormat(t *testing.T) {
	id, err := parseIDPair("999.987")
	if err != nil {
		t.Fatalf("dot format must parse: %v", err)
	}
	if id.UID != 999 || id.GID != 987 {
		t.Fatalf("got %+v, want uid=999 gid=987", id)
	}
	// The old colon form is not HTCondor's format and must be rejected, not
	// silently mis-parsed into a nil/zero identity.
	if _, err := parseIDPair("999:987"); err == nil {
		t.Fatal("colon format must be rejected")
	}
}

// TestStartRefusesToStayRoot verifies the safety net: an enabled drop whose target
// resolved to root must fail rather than "succeed" while still privileged.
// (Only meaningful when the test itself runs as root; otherwise dropPrivileges to
// a non-root target changes euid and the guard is not the code path under test.)
func TestStartRefusesToStayRoot(t *testing.T) {
	m := &Manager{enabled: true, defaultIdentity: Identity{UID: 0, GID: 0}}
	err := m.Start()
	// Running as root: the drop to uid0 is a no-op and the guard must fire.
	// Running as non-root: dropPrivileges to uid0 fails first. Either way, Start
	// must NOT return nil (which would mean "successfully running as root").
	if err == nil {
		t.Fatal("Start must never succeed while leaving the process as root")
	}
}
