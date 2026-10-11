package authz

// Perm is an HTCondor authorization level. The names match the ALLOW_<PERM> /
// DENY_<PERM> configuration knobs.
type Perm string

// Permission levels, named to match the ALLOW_<PERM>/DENY_<PERM> config knobs.
const (
	PermAllow           Perm = "ALLOW" // special: always allowed
	PermRead            Perm = "READ"
	PermWrite           Perm = "WRITE"
	PermNegotiator      Perm = "NEGOTIATOR"
	PermAdministrator   Perm = "ADMINISTRATOR"
	PermConfig          Perm = "CONFIG"
	PermDaemon          Perm = "DAEMON"
	PermDefault         Perm = "DEFAULT" // catch-all in the config-fallback chain
	PermAdvertiseStartd Perm = "ADVERTISE_STARTD"
	PermAdvertiseSchedd Perm = "ADVERTISE_SCHEDD"
	PermAdvertiseMaster Perm = "ADVERTISE_MASTER"
)

// configNext is the modern (recommended_v90) config-fallback chain from
// DCpermissionHierarchy::aConfigNext: when a setting for perm is not set, look
// up the next perm's, terminating at DEFAULT. ADVERTISE_* fall back to DAEMON
// first. A perm absent from this map (ALLOW, CLIENT) falls back to DEFAULT.
var configNext = map[Perm]Perm{
	PermRead:            PermDefault,
	PermWrite:           PermDefault,
	PermNegotiator:      PermDefault,
	PermAdministrator:   PermDefault,
	PermConfig:          PermDefault,
	PermDaemon:          PermDefault,
	PermAdvertiseStartd: PermDaemon,
	PermAdvertiseSchedd: PermDaemon,
	PermAdvertiseMaster: PermDaemon,
	// PermDefault terminates the chain (no entry).
}

// configNextLegacy is where DCpermissionHierarchy::aConfigNextLegacy, the
// order before recommended_v90 security, differs from configNext: DAEMON
// falls back to WRITE before DEFAULT. LEGACY_ALLOW_SEMANTICS (which use
// SECURITY:HOST_BASED sets) selects it.
var configNextLegacy = map[Perm]Perm{
	PermDaemon: PermWrite,
}

// impliedNext is DCpermissionHierarchy::aImpliedNext: the next-lower permission a
// granted permission implies (granting DAEMON implies WRITE implies READ, etc.).
var impliedNext = map[Perm]Perm{
	PermWrite:           PermRead,
	PermNegotiator:      PermRead,
	PermAdministrator:   PermWrite,
	PermConfig:          PermRead,
	PermDaemon:          PermWrite,
	PermAdvertiseStartd: PermRead,
	PermAdvertiseSchedd: PermRead,
	PermAdvertiseMaster: PermRead,
}

// directlyImpliedBy returns the permissions that directly imply perm (the
// reverse of impliedNext) — i.e. holding any of them grants perm. Verify
// recurses into these when a request does not match perm's own tables.
func directlyImpliedBy(perm Perm) []Perm {
	var out []Perm
	for q, p := range impliedNext {
		if p == perm {
			out = append(out, q)
		}
	}
	return out
}

// ConfigChain returns perm followed by the levels whose settings it falls
// back to, ending at DEFAULT: DCpermissionHierarchy::nextConfig, as
// SecMan::getSecSetting walks it to resolve SEC_<perm>_*, ALLOW_<perm> and
// DENY_<perm>. legacy selects the order LEGACY_ALLOW_SEMANTICS restores.
func ConfigChain(perm Perm, legacy bool) []Perm {
	chain := []Perm{perm}
	for perm != PermDefault {
		next, ok := configNext[perm]
		if l, lok := configNextLegacy[perm]; legacy && lok {
			next, ok = l, true
		}
		if !ok {
			next = PermDefault
		}
		chain = append(chain, next)
		perm = next
	}
	return chain
}
