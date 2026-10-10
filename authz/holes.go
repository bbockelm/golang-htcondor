package authz

import (
	"net"
	"sync"
)

// Identities of the sessions C++ DaemonCore punches authorization holes for
// (src/condor_io/authentication.cpp).
const (
	// FamilyFQU is the identity of condor_master's family session, which every
	// daemon of one master shares (CONDOR_FAMILY_FQU).
	FamilyFQU = "condor@family"
	// ParentFQU is the identity of the session a daemon inherits from the
	// condor_master that started it (CONDOR_PARENT_FQU).
	ParentFQU = "condor@parent"
	// SubmitSideMatchSessionFQU is the identity of a claim session on the
	// execute side, i.e. the schedd or shadow that holds the claim.
	SubmitSideMatchSessionFQU = "submit-side@matchsession"
	// NegotiatorSideMatchSessionFQU is the identity of the negotiator's
	// session with a schedd.
	NegotiatorSideMatchSessionFQU = "negotiator-side@matchsession"
	// CollectorSideMatchSessionFQU is the identity of a remote-administration
	// session obtained through the collector.
	CollectorSideMatchSessionFQU = "collector-side@matchsession"
)

// Hole is one IpVerify::PunchHole call: Perm opened to ID whatever
// ALLOW_<Perm>/DENY_<Perm> say. ID is a full user@domain, "user@domain/ip",
// or a bare IP address, each matched exactly.
type Hole struct {
	Perm Perm
	ID   string
}

// HoleSet is a group of holes a C++ daemon punches together, optionally only
// while a boolean configuration knob is on. The holes are listed as C++ punches
// them; Holes.Punch adds the levels each one implies.
type HoleSet struct {
	// Name identifies the set, so Holes.Apply can tell whether it is open.
	Name  string
	Holes []Hole
	// Knob, if set, is the boolean knob that opens the set; KnobDefault is
	// its value when unset.
	Knob        string
	KnobDefault bool
}

// Enabled reports whether s should be open under cfg.
func (s HoleSet) Enabled(cfg ConfigGetter) bool {
	if s.Knob == "" {
		return true
	}
	return configBool(cfg, s.Knob, s.KnobDefault)
}

// The standard hole sets. C++ also punches a CLIENT hole for each of these
// identities; CLIENT authorizes the peer of an outgoing connection, which a
// Policy does not decide, so the sets leave it out.

// FamilySessionHoles are the levels DaemonCore grants condor_master's family
// session (DaemonCore::Inherit, daemon_core.cpp), while SEC_USE_FAMILY_SESSION
// is on: ADMINISTRATOR, DAEMON, the ADVERTISE_* levels and NEGOTIATOR, and
// so WRITE and READ.
func FamilySessionHoles() HoleSet {
	return HoleSet{
		Name: "family session",
		Holes: []Hole{
			{PermAdministrator, FamilyFQU},
			{PermDaemon, FamilyFQU},
			{PermAdvertiseMaster, FamilyFQU},
			{PermAdvertiseSchedd, FamilyFQU},
			{PermAdvertiseStartd, FamilyFQU},
			{PermNegotiator, FamilyFQU},
		},
		Knob:        "SEC_USE_FAMILY_SESSION",
		KnobDefault: true,
	}
}

// ParentSessionHoles are the levels DaemonCore grants the session a daemon
// inherits from its condor_master (DaemonCore::Inherit, daemon_core.cpp):
// ADMINISTRATOR and DAEMON, and so WRITE and READ.
func ParentSessionHoles() HoleSet {
	return HoleSet{
		Name: "parent session",
		Holes: []Hole{
			{PermAdministrator, ParentFQU},
			{PermDaemon, ParentFQU},
		},
	}
}

// RemoteAdminHoles is the level DaemonCore grants a remote-administration
// session while SEC_ENABLE_REMOTE_ADMINISTRATION is on
// (DaemonCore::SetRemoteAdmin, daemon_core.cpp): ADMINISTRATOR, and so WRITE
// and READ.
func RemoteAdminHoles() HoleSet {
	return HoleSet{
		Name:        "remote administration",
		Holes:       []Hole{{PermAdministrator, CollectorSideMatchSessionFQU}},
		Knob:        "SEC_ENABLE_REMOTE_ADMINISTRATION",
		KnobDefault: false,
	}
}

// DaemonCoreHoles are the sets every C++ DaemonCore daemon punches: the
// family, parent and remote-administration sessions.
func DaemonCoreHoles() []HoleSet {
	return []HoleSet{FamilySessionHoles(), ParentSessionHoles(), RemoteAdminHoles()}
}

// StartdMatchSessionHoles is the level the startd grants the claim sessions it
// mints while SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION is on (init_params,
// startd_main.cpp): DAEMON, and so WRITE and READ.
func StartdMatchSessionHoles() HoleSet {
	return HoleSet{
		Name:        "startd match session",
		Holes:       []Hole{{PermDaemon, SubmitSideMatchSessionFQU}},
		Knob:        "SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION",
		KnobDefault: true,
	}
}

// ScheddMatchSessionHoles is the level the schedd grants the negotiator's
// session while SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION is on
// (Scheduler::reconfig, schedd.cpp): NEGOTIATOR, and so READ.
func ScheddMatchSessionHoles() HoleSet {
	return HoleSet{
		Name:        "schedd match session",
		Holes:       []Hole{{PermNegotiator, NegotiatorSideMatchSessionFQU}},
		Knob:        "SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION",
		KnobDefault: true,
	}
}

// Holes is the set of authorization holes a Policy consults before its
// ALLOW_/DENY_ tables, a port of IpVerify's PunchedHoleArray. Each hole is
// counted, so it stays open until it has been filled as often as it was
// punched. Holes outlive a Policy: share one across the Policies a daemon
// rebuilds on reconfig (Policy.SetHoles), as C++ holes persist across a
// reconfig. Safe for concurrent use.
type Holes struct {
	mu    sync.RWMutex
	table map[Perm]map[string]int
	open  map[string]bool // HoleSet.Name -> open, for Apply
}

// NewHoles returns an empty set of holes.
func NewHoles() *Holes {
	return &Holes{table: make(map[Perm]map[string]int), open: make(map[string]bool)}
}

// Punch opens perm, and every level it implies, to id (IpVerify::PunchHole).
func (h *Holes) Punch(perm Perm, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.punchLocked(perm, id)
}

func (h *Holes) punchLocked(perm Perm, id string) {
	for p, ok := perm, true; ok; p, ok = impliedNext[p] {
		if h.table[p] == nil {
			h.table[p] = make(map[string]int)
		}
		h.table[p][id]++
	}
}

// Fill closes one opening of perm, and of every level it implies, to id
// (IpVerify::FillHole). It reports whether perm was open to id.
func (h *Holes) Fill(perm Perm, id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fillLocked(perm, id)
}

func (h *Holes) fillLocked(perm Perm, id string) bool {
	if h.table[perm][id] == 0 {
		return false
	}
	for p, ok := perm, true; ok; p, ok = impliedNext[p] {
		if n := h.table[p][id]; n > 1 {
			h.table[p][id] = n - 1
		} else {
			delete(h.table[p], id)
		}
	}
	return true
}

// Apply opens each set that is enabled under cfg and closes each that is
// not, punching or filling its holes only when that changes, as the C++
// daemons do on every reconfig.
func (h *Holes) Apply(sets []HoleSet, cfg ConfigGetter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range sets {
		want := s.Enabled(cfg)
		if h.open[s.Name] == want {
			continue
		}
		for _, hole := range s.Holes {
			if want {
				h.punchLocked(hole.Perm, hole.ID)
			} else {
				h.fillLocked(hole.Perm, hole.ID)
			}
		}
		h.open[s.Name] = want
	}
}

// Allows reports whether perm is open to user connecting from addr: to the
// identity itself, to "user/ip", or to the bare ip, each matched exactly, as
// IpVerify::Verify looks them up. user "" (the wildcard user) matches only
// the bare ip.
func (h *Holes) Allows(perm Perm, addr net.IP, user string) bool {
	if h == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	ids := h.table[perm]
	if len(ids) == 0 {
		return false
	}
	ipStr := ""
	if addr != nil {
		ipStr = addr.String()
	}
	if user != "" {
		if ids[user] > 0 {
			return true
		}
		if ipStr != "" && ids[user+"/"+ipStr] > 0 {
			return true
		}
	}
	return ipStr != "" && ids[ipStr] > 0
}
