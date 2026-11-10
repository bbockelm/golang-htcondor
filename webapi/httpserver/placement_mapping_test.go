package httpserver

import (
	"context"
	"errors"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/idmap"
)

// The account an identity signs in as comes from the placementd's map, never
// from PLACEMENT_QUERY_USERS' ApUserId: that is the subject of the identity's
// newest unexpired token, which keeps naming the old account after the
// identity is re-pointed.

// tokenAcct is the account the token log names for aliceIdentity.
const tokenAcct = "old@ap.example"

// directoryServer is a placementd with the directory commands whose token
// log still names tokenAcct for aliceIdentity, which the map points at
// aliceAcct.
func directoryServer(t *testing.T) *onboardingServer {
	t.Helper()
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	s.fake.apiVersion = htcondor.PlacementdAPIVersionDirectory
	s.fake.users[0].APUserID = tokenAcct
	s.fake.identities = []htcondor.PlacementIdentity{{
		Identity:       aliceIdentity,
		Account:        aliceAcct,
		Authorizations: []string{"READ", "WRITE", "INSTRUCTOR"},
		Projects:       []string{"ProjA", "ProjB"},
		DefaultProject: "ProjB",
	}}
	mapWith(s, idmap.StrategyPlacementd)
	return s
}

// legacyServer is a placementd without the directory commands that reports
// the map's account as MappedAccount beside the token-derived ApUserId.
func legacyServer(t *testing.T) *onboardingServer {
	t.Helper()
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	s.fake.users[0].APUserID = tokenAcct
	s.fake.users[0].MappedAccount = aliceAcct
	mapWith(s, idmap.StrategyPlacementd)
	return s
}

// staleSession makes the session's account due for a re-read.
func staleSession(t *testing.T, s *onboardingServer, sid string) *SessionData {
	t.Helper()
	sd := s.sessionStore.Get(sid)
	info := *sd.Placement
	info.CheckedAt = time.Now().Add(-placementRevalidateEvery - time.Second)
	if err := s.sessionStore.UpdatePlacement(sid, &info, sd.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	return s.sessionStore.Get(sid)
}

// assertMapsToAliceAcct signs in, revalidates and refreshes, and expects
// the map's account every time.
func assertMapsToAliceAcct(t *testing.T, s *onboardingServer, project string) string {
	t.Helper()
	sid, sd := sessionOf(t, s, s.ssoCallback(t, "/"))
	if !sd.IsPlacementd() || sd.Username != aliceAcct || sd.Placement.Account != aliceAcct {
		t.Fatalf("signed in as %q (placementd %v), want the mapped %q", sd.Username, sd.IsPlacementd(), aliceAcct)
	}
	if sd.Placement.Project != project {
		t.Errorf("project = %q, want %q", sd.Placement.Project, project)
	}

	sd = staleSession(t, s, sid)
	token, subject, err := s.mintPlacementSessionToken(context.Background(), sid, sd)
	if err != nil {
		t.Fatalf("revalidation of a session whose mapping did not change: %v", err)
	}
	if subject != aliceAcct || mintedClaims(t, token)["sub"] != aliceAcct {
		t.Errorf("revalidated subject = %q", subject)
	}

	ctx := context.Background()
	if reason, err := s.reauthorizePlacementIdentity(ctx, aliceIdentity, aliceAcct); err != nil || reason != "" {
		t.Errorf("refresh of the mapped account: %q %v", reason, err)
	}
	if reason, err := s.reauthorizePlacementIdentity(ctx, aliceIdentity, ""); err != nil || reason != "" {
		t.Errorf("refresh of a grant bound to the identity: %q %v", reason, err)
	}
	return sid
}

// assertRepointEnds expects a session and a grant on aliceAcct to end once
// change has re-pointed or removed the identity, even though the token log
// still names aliceAcct.
func assertRepointEnds(t *testing.T, s *onboardingServer, sid string, change func()) {
	t.Helper()
	s.fake.users[0].APUserID = aliceAcct
	change()
	sd := staleSession(t, s, sid)
	if _, _, err := s.mintPlacementSessionToken(context.Background(), sid, sd); !errors.Is(err, errPlacementSessionEnded) {
		t.Errorf("revalidation after the change = %v, want the session ended", err)
	}
	if s.sessionStore.Get(sid) != nil {
		t.Error("the session survived the change")
	}
	if reason, err := s.reauthorizePlacementIdentity(context.Background(), aliceIdentity, aliceAcct); err != nil || reason == "" {
		t.Errorf("refresh after the change kept the grant: %q %v", reason, err)
	}
}

func TestPlacementdMappingIgnoresTokenAccount(t *testing.T) {
	assertMapsToAliceAcct(t, directoryServer(t), "ProjB")
}

func TestPlacementdMappingChangeEndsSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*onboardingServer)
	}{
		{"re-pointed", func(s *onboardingServer) { s.fake.identities[0].Account = "x@ap.example" }},
		{"removed", func(s *onboardingServer) { s.fake.identities = nil }},
		{"expired", func(s *onboardingServer) {
			s.fake.identities[0].Expired = true
			s.fake.identities[0].ExpiresAt = time.Now().Add(-time.Minute)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := directoryServer(t)
			// The token log agrees with the map until the change.
			s.fake.users[0].APUserID = aliceAcct
			sid := assertMapsToAliceAcct(t, s, "ProjB")
			assertRepointEnds(t, s, sid, func() { tc.change(s) })
		})
	}
}

func TestPlacementdLegacyMappingPrefersMappedAccount(t *testing.T) {
	assertMapsToAliceAcct(t, legacyServer(t), "ProjA")
}

func TestPlacementdLegacyMappingChangeEndsSession(t *testing.T) {
	s := legacyServer(t)
	s.fake.users[0].APUserID = aliceAcct
	sid := assertMapsToAliceAcct(t, s, "ProjA")
	assertRepointEnds(t, s, sid, func() { s.fake.users[0].MappedAccount = "x@ap.example" })
}
