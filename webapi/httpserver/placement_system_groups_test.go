package httpserver

import (
	"slices"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/idmap"
)

// withSystemGroups makes s read group membership from the system, served
// by a stub that knows the accounts in byUser.
func withSystemGroups(t *testing.T, s *onboardingServer, uidDomain string, byUser map[string][]string) *recordingGroups {
	t.Helper()
	rec := &recordingGroups{byUser: byUser}
	if s.localIdentity == nil {
		s.localIdentity = newLocalIdentity(nil, []string{groupSourceSystem}, "", time.Minute, false, testLogger(t))
	}
	s.localIdentity.groups = rec
	s.uidDomain = uidDomain
	s.webuiAdminGroups = newGroupSet("condor-admins")
	return rec
}

// With groups read from the system, a placementd account's groups are the
// system's for its local part, never the provider's groups claim: a
// provider that can assert the admin group's name must not make the
// account an administrator.
func TestPlacementdSessionTakesSystemGroups(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity, "groups": []string{"condor-admins"}})
	mapWith(s, idmap.StrategyPlacementd)
	rec := withSystemGroups(t, s, "ap.example", map[string][]string{"alice": {"ap-users"}})

	sid, sd := sessionOf(t, s, s.ssoCallback(t, "/jobs"))
	if !sd.IsPlacementd() || sd.Username != aliceAcct {
		t.Fatalf("session = %+v", sd)
	}
	if !slices.Equal(sd.Groups, []string{"ap-users"}) {
		t.Errorf("session groups = %v, want the system's [ap-users]", sd.Groups)
	}
	if s.webuiAdminGroups.allows(sd.Groups) {
		t.Error("the provider's groups claim made a placementd account an administrator")
	}
	if !slices.Contains(rec.asked, "alice") {
		t.Errorf("groups were read for %v, want the account's local part", rec.asked)
	}
	resp, _ := s.meThrottled(t, testSessionCookie(sid))
	if resp.IsAdmin || slices.Contains(resp.Groups, "condor-admins") {
		t.Errorf("/api/v1/auth/me = is_admin %v groups %v", resp.IsAdmin, resp.Groups)
	}
}

// An account outside UID_DOMAIN has no system groups: it gets none, and
// the system is not asked about a same-named local account.
func TestPlacementdSessionOutsideUIDDomainHasNoGroups(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity, "groups": []string{"condor-admins"}})
	mapWith(s, idmap.StrategyPlacementd)
	rec := withSystemGroups(t, s, "other.example", map[string][]string{"alice": {"condor-admins"}})

	sid, sd := sessionOf(t, s, s.ssoCallback(t, "/jobs"))
	if !sd.IsPlacementd() || sd.Username != aliceAcct {
		t.Fatalf("session = %+v", sd)
	}
	if len(sd.Groups) != 0 {
		t.Errorf("session groups = %v, want none", sd.Groups)
	}
	if len(rec.asked) != 0 {
		t.Errorf("the system was asked about %v", rec.asked)
	}
	if resp, _ := s.meThrottled(t, testSessionCookie(sid)); resp.IsAdmin {
		t.Error("/api/v1/auth/me reports an administrator")
	}
}

// A placement-only session upgraded after onboarding follows the same
// rule: the groups it stored from the provider do not carry over.
func TestPlacementSessionUpgradeTakesSystemGroups(t *testing.T) {
	s, c := newbieServer(t, map[string]any{"sub": newbieSubject, "eppn": newbieIdentity, "groups": []string{"condor-admins"}})
	withSystemGroups(t, s, "ap.example", map[string][]string{"physnewbie": {"physics"}})
	s.onboard()
	resp, _ := s.me(t, c)
	if resp.PlacementOnly || resp.Username != newbieAcct {
		t.Fatalf("not upgraded: %+v", resp)
	}
	if resp.IsAdmin || !slices.Equal(resp.Groups, []string{"physics"}) {
		t.Errorf("upgraded session: is_admin %v groups %v, want false [physics]", resp.IsAdmin, resp.Groups)
	}
}
