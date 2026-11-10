package httpserver

import "testing"

// BUG REPRO (fails on afc4bf19): the SSH approval screen's workspace
// create strips the domain (ownerFromActor) before the session manager's
// UserFor runs, so a browser identity in another UID domain gets a
// session placed -- and submitted -- as alice@d on alice's assigned AP.
// REST and MCP refuse the same identity with 403
// (TestMultiAPInteractiveRESTRefusesAForeignDomain,
// TestMultiAPInteractiveRefusesAForeignDomain).
func TestMultiAPSSHApprovalRefusesAForeignDomain(t *testing.T) {
	s := newInteractiveServer(t, "USER alice@d "+ap2+"\n", nil)
	before := s.aps.counts()
	_, _, err := s.srv.sshConsentCreateSession(s.callerCtx(t), "alice@other.example", "work", InteractiveCreateTerminalRequest{})
	if err == nil {
		t.Error("a workspace was created for alice@other.example")
	}
	reachedNone(t, "an approval's workspace for alice@other.example", before, s.aps.counts())
}
