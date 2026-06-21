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
// DCpermissionHierarchy::aConfigNext: when ALLOW_<perm>/DENY_<perm> is not set,
// look up the next perm's config, terminating at DEFAULT. ADVERTISE_* fall back
// to DAEMON first. A perm absent from this map terminates immediately.
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

// configChain returns perm followed by its config-fallback chain (perm,
// configNext[perm], ..., DEFAULT), used to resolve ALLOW_<perm>/DENY_<perm>.
func configChain(perm Perm) []Perm {
	chain := []Perm{perm}
	seen := map[Perm]bool{perm: true}
	for {
		next, ok := configNext[perm]
		if !ok || seen[next] {
			break
		}
		chain = append(chain, next)
		seen[next] = true
		perm = next
	}
	return chain
}
