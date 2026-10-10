package authz

import (
	"slices"
	"testing"
)

// cxxPunchedHoles are the IpVerify::PunchHole calls the C++ daemons make for
// each standard hole set, less the CLIENT holes, and the levels IpVerify then
// grants (each call plus the levels it implies, aImpliedNext in
// condor_perms.cpp).
var cxxPunchedHoles = []struct {
	set     HoleSet
	source  string
	id      string
	punched []Perm
	granted []Perm
}{
	{
		set: FamilySessionHoles(), source: "daemon_core.cpp:9421-9427", id: "condor@family",
		punched: []Perm{PermAdministrator, PermDaemon, PermAdvertiseMaster, PermAdvertiseSchedd, PermAdvertiseStartd, PermNegotiator},
		granted: []Perm{PermAdministrator, PermDaemon, PermAdvertiseMaster, PermAdvertiseSchedd, PermAdvertiseStartd, PermNegotiator, PermWrite, PermRead},
	},
	{
		set: ParentSessionHoles(), source: "daemon_core.cpp:9364-9366", id: "condor@parent",
		punched: []Perm{PermAdministrator, PermDaemon},
		granted: []Perm{PermAdministrator, PermDaemon, PermWrite, PermRead},
	},
	{
		set: RemoteAdminHoles(), source: "daemon_core.cpp:11647", id: "collector-side@matchsession",
		punched: []Perm{PermAdministrator},
		granted: []Perm{PermAdministrator, PermWrite, PermRead},
	},
	{
		set: StartdMatchSessionHoles(), source: "startd_main.cpp:711-712", id: "submit-side@matchsession",
		punched: []Perm{PermDaemon},
		granted: []Perm{PermDaemon, PermWrite, PermRead},
	},
	{
		set: ScheddMatchSessionHoles(), source: "schedd.cpp:17338-17339", id: "negotiator-side@matchsession",
		punched: []Perm{PermNegotiator},
		granted: []Perm{PermNegotiator, PermRead},
	},
}

// TestHoleSetsMatchCxx: each standard set punches exactly the holes the C++
// daemon does, and a Policy with only those holes open grants the identity
// exactly the levels IpVerify does: every listed level, and no other.
func TestHoleSetsMatchCxx(t *testing.T) {
	everyone := mapConfig{"SEC_ENABLE_REMOTE_ADMINISTRATION": "TRUE"}
	for _, tc := range cxxPunchedHoles {
		t.Run(tc.set.Name, func(t *testing.T) {
			var punched []Perm
			for _, h := range tc.set.Holes {
				if h.ID != tc.id {
					t.Errorf("hole %s opened to %q, want %q (%s)", h.Perm, h.ID, tc.id, tc.source)
				}
				punched = append(punched, h.Perm)
			}
			if !slices.Equal(punched, tc.punched) {
				t.Errorf("punched %v, want %v (%s)", punched, tc.punched, tc.source)
			}

			// With no ALLOW_ settings, and with DENY_<level> = * for every
			// level (so no level is reached through one it implies), only a
			// hole grants anything.
			denyAll := mapConfig{}
			for _, perm := range allPerms {
				denyAll["DENY_"+string(perm)] = "*"
			}
			for _, cfg := range []mapConfig{{}, denyAll} {
				p := newTestPolicy(t, cfg, nil, nil)
				p.Holes().Apply([]HoleSet{tc.set}, everyone)
				for _, perm := range allPerms {
					want := slices.Contains(tc.granted, perm)
					if got := p.Verify(perm, ip("10.0.0.1"), tc.id); got != want {
						t.Errorf("%d DENY_ settings: Verify(%s, %s) = %v, want %v (%s)", len(cfg), perm, tc.id, got, want, tc.source)
					}
					if p.Verify(perm, ip("10.0.0.1"), "condor@pool") {
						t.Errorf("%d DENY_ settings: Verify(%s, condor@pool) = true through %s's holes", len(cfg), perm, tc.id)
					}
				}
			}
		})
	}
}

// TestDaemonCoreHoles: every daemon gets the family and parent sessions'
// holes, and the remote-administration one only when enabled.
func TestDaemonCoreHoles(t *testing.T) {
	p := newTestPolicy(t, mapConfig{}, nil, nil)
	p.Holes().Apply(DaemonCoreHoles(), mapConfig{})
	for _, id := range []string{FamilyFQU, ParentFQU} {
		if !p.Verify(PermAdministrator, ip("10.0.0.1"), id) {
			t.Errorf("%s not granted ADMINISTRATOR by DaemonCoreHoles", id)
		}
	}
	if p.Verify(PermAdministrator, ip("10.0.0.1"), CollectorSideMatchSessionFQU) {
		t.Error("remote administration open with SEC_ENABLE_REMOTE_ADMINISTRATION unset")
	}
}

// TestHoleBeatsDeny: a hole grants its level before DENY_ is consulted, both
// against a deny list naming the identity and against DENY_<perm> = *.
func TestHoleBeatsDeny(t *testing.T) {
	for _, cfg := range []mapConfig{
		{"ALLOW_ADMINISTRATOR": "admin@pool", "DENY_ADMINISTRATOR": "condor@*", "DENY_READ": "condor@*"},
		{"ALLOW_ADMINISTRATOR": "*", "DENY_ADMINISTRATOR": "*", "DENY_READ": "*"},
	} {
		p := newTestPolicy(t, cfg, nil, nil)
		p.PunchHole(PermAdministrator, FamilyFQU)
		for _, perm := range []Perm{PermAdministrator, PermWrite, PermRead} {
			if !p.Verify(perm, ip("10.0.0.1"), FamilyFQU) {
				t.Errorf("%v: condor@family refused %s through its hole", cfg, perm)
			}
		}
		if p.Verify(PermAdministrator, ip("10.0.0.1"), "condor@pool") {
			t.Errorf("%v: condor@pool granted ADMINISTRATOR", cfg)
		}
	}
}

// TestHoleIdentityExact: a hole matches its identity exactly, as C++ looks
// it up in a std::map; "user/ip" matches that identity from that address
// only, and a bare IP any identity from it.
func TestHoleIdentityExact(t *testing.T) {
	p := newTestPolicy(t, mapConfig{}, nil, nil)
	p.PunchHole(PermDaemon, FamilyFQU)
	p.PunchHole(PermDaemon, "startd@pool/10.0.0.5")
	p.PunchHole(PermDaemon, "10.0.0.9")

	cases := []struct {
		user string
		addr string
		want bool
	}{
		{"condor@family", "10.0.0.1", true},
		{"Condor@Family", "10.0.0.1", false},
		{"condor@family.example", "10.0.0.1", false},
		{"condor@famil", "10.0.0.1", false},
		{"condor", "10.0.0.1", false},
		{"", "10.0.0.1", false},
		{"startd@pool", "10.0.0.5", true},
		{"startd@pool", "10.0.0.6", false},
		{"other@pool", "10.0.0.5", false},
		{"anyone@pool", "10.0.0.9", true},
		{"", "10.0.0.9", true},
	}
	for _, tc := range cases {
		if got := p.Verify(PermDaemon, ip(tc.addr), tc.user); got != tc.want {
			t.Errorf("Verify(DAEMON, %s, %q) = %v, want %v", tc.addr, tc.user, got, tc.want)
		}
	}
}

// TestHolesCounted: a hole stays open until it has been filled as often as
// it was punched, and filling it closes the levels it implied.
func TestHolesCounted(t *testing.T) {
	p := newTestPolicy(t, mapConfig{}, nil, nil)
	const id = "startd@pool/10.0.0.5"
	p.PunchHole(PermDaemon, id)
	p.PunchHole(PermDaemon, id)
	if !p.FillHole(PermDaemon, id) {
		t.Fatal("FillHole of an open hole = false")
	}
	if !p.Verify(PermRead, ip("10.0.0.5"), "startd@pool") {
		t.Fatal("hole punched twice closed by one fill")
	}
	if !p.FillHole(PermDaemon, id) {
		t.Fatal("second FillHole = false")
	}
	for _, perm := range []Perm{PermDaemon, PermWrite, PermRead} {
		if p.Verify(perm, ip("10.0.0.5"), "startd@pool") {
			t.Errorf("%s still open after the hole was filled", perm)
		}
	}
	if p.FillHole(PermDaemon, id) {
		t.Error("FillHole of a closed hole = true")
	}
}

// TestHolesApplyFollowsKnob: Apply opens a gated set while its knob is on
// and closes it when the knob goes off, and applying the same state twice
// does not punch twice.
func TestHolesApplyFollowsKnob(t *testing.T) {
	p := newTestPolicy(t, mapConfig{}, nil, nil)
	sets := []HoleSet{StartdMatchSessionHoles()}
	open := func() bool { return p.Verify(PermDaemon, ip("10.0.0.1"), SubmitSideMatchSessionFQU) }

	p.Holes().Apply(sets, mapConfig{})
	p.Holes().Apply(sets, mapConfig{})
	if !open() {
		t.Fatal("match-session hole closed with SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION unset (default true)")
	}
	p.Holes().Apply(sets, mapConfig{"SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION": "FALSE"})
	if open() {
		t.Fatal("match-session hole open with SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION false")
	}
	p.Holes().Apply(sets, mapConfig{"SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION": "TRUE"})
	if !open() {
		t.Fatal("match-session hole closed after SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION was turned back on")
	}
}

// TestHolesSharedAcrossPolicies: a Policy rebuilt with SetHoles keeps the
// holes punched into its predecessor, as C++ holes survive a reconfig.
func TestHolesSharedAcrossPolicies(t *testing.T) {
	old := newTestPolicy(t, mapConfig{}, nil, nil)
	old.PunchHole(PermRead, "startd@pool/10.0.0.5")
	p := newTestPolicy(t, mapConfig{}, nil, nil)
	if p.Verify(PermRead, ip("10.0.0.5"), "startd@pool") {
		t.Fatal("a new Policy shares holes it was not given")
	}
	p.SetHoles(old.Holes())
	if !p.Verify(PermRead, ip("10.0.0.5"), "startd@pool") {
		t.Error("rebuilt Policy lost the hole")
	}
}

// TestPolicyKnobs: Knobs names the setting that supplies each table,
// through the subsystem variant and the fallback chain.
func TestPolicyKnobs(t *testing.T) {
	p := newTestPolicy(t, mapConfig{
		"ALLOW_DAEMON_CCB": "a@pool",
		"ALLOW_DEFAULT":    "b@pool",
		"DENY_READ":        "c@pool",
	}, nil, nil)
	cases := []struct {
		perm        Perm
		allow, deny string
	}{
		{PermAdvertiseStartd, "ALLOW_DAEMON_CCB", ""},
		{PermDaemon, "ALLOW_DAEMON_CCB", ""},
		{PermRead, "ALLOW_DEFAULT", "DENY_READ"},
		{PermAdministrator, "ALLOW_DEFAULT", ""},
	}
	for _, tc := range cases {
		if a, d := p.Knobs(tc.perm); a != tc.allow || d != tc.deny {
			t.Errorf("Knobs(%s) = %q, %q; want %q, %q", tc.perm, a, d, tc.allow, tc.deny)
		}
	}
	if a, d := newTestPolicy(t, mapConfig{}, nil, nil).Knobs(PermRead); a != "" || d != "" {
		t.Errorf("Knobs(READ) with nothing set = %q, %q; want empty", a, d)
	}
}

func TestSameUser(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"alice@example.org", "alice@example.org", true},
		{"alice@Example.ORG", "alice@example.org", true},
		{"Alice@example.org", "alice@example.org", false},
		{"alice@example.org", "alice@example.org.evil", false},
		{"alice", "alice@example.org", false},
		{"alice", "alice", true},
		{"alice@", "alice", false},
		{"bob@example.org", "alice@example.org", false},
	}
	for _, tc := range cases {
		if got := SameUser(tc.a, tc.b); got != tc.want {
			t.Errorf("SameUser(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := SameUser(tc.b, tc.a); got != tc.want {
			t.Errorf("SameUser(%q, %q) = %v, want %v", tc.b, tc.a, got, tc.want)
		}
	}
}
