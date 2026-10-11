package htcondor

import (
	"fmt"
	"slices"
	"testing"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/config"
)

// cppPerms is the DCpermission enum (condor_perms.h) in order, and
// cppConfigNext and cppConfigNextLegacy are DCpermissionHierarchy's
// aConfigNext and aConfigNextLegacy tables (condor_perms.cpp), copied entry
// by entry; cppLastPerm is LAST_PERM.
var cppPerms = []string{
	"ALLOW", "READ", "WRITE", "NEGOTIATOR", "ADMINISTRATOR", "CONFIG", "DAEMON",
	"SOAP", "DEFAULT", "CLIENT", "ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER",
}

const (
	cppWrite    = 2
	cppDaemon   = 6
	cppSoap     = 7
	cppDefault  = 8
	cppLastPerm = 13
)

var (
	cppConfigNext       = []int{8, 8, 8, 8, 8, 8, 8, 8, cppLastPerm, 8, 6, 6, 6}
	cppConfigNextLegacy = []int{8, 8, 8, 8, 8, 8, 2, 8, cppLastPerm, 8, 6, 6, 6}
)

// cppGetSecSetting is SecMan::getSecSetting (condor_secman.cpp) without a
// subsystem: the first SEC_<perm>_<feature> set along perm's nextConfig
// chain. param() returns NULL for an empty value, so an empty one is unset.
func cppGetSecSetting(params map[string]string, feature string, perm int, legacyAllowSemantics bool) string {
	legacy := perm >= cppDaemon && legacyAllowSemantics
	for ; perm < cppLastPerm; perm = nextConfig(perm, legacy) {
		if v := params[fmt.Sprintf("SEC_%s_%s", cppPerms[perm], feature)]; v != "" {
			return v
		}
	}
	return ""
}

func nextConfig(perm int, legacy bool) int {
	if legacy {
		return cppConfigNextLegacy[perm]
	}
	return cppConfigNext[perm]
}

// mapConfig is a configuration holding exactly its entries.
type mapConfig map[string]string

func (m mapConfig) Get(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

// TestSecSettingMatchesCpp: every SEC_<level>_<feature> setting a security
// config is built from resolves as HTCondor's getSecSetting resolves it --
// for every level, every combination of the levels its chain can reach being
// set, unset or set empty, with and without LEGACY_ALLOW_SEMANTICS.
func TestSecSettingMatchesCpp(t *testing.T) {
	features := []string{"AUTHENTICATION", "ENCRYPTION", "INTEGRITY", "AUTHENTICATION_METHODS", "CRYPTO_METHODS"}
	// The levels any chain passes through after its own.
	via := []int{cppDaemon, cppWrite, cppDefault}
	for perm := range cppPerms {
		if perm == cppSoap {
			continue
		}
		levels := []int{perm}
		for _, v := range via {
			if v != perm {
				levels = append(levels, v)
			}
		}
		// Each level is unset (0), set (1) or set empty (2).
		n := 1
		for range levels {
			n *= 3
		}
		for combo := range n {
			for _, legacy := range []bool{false, true} {
				for _, feature := range features {
					params := map[string]string{}
					if legacy {
						params["LEGACY_ALLOW_SEMANTICS"] = "TRUE"
					}
					c := combo
					for _, lvl := range levels {
						key := fmt.Sprintf("SEC_%s_%s", cppPerms[lvl], feature)
						switch c % 3 {
						case 1:
							params[key] = "set-at-" + cppPerms[lvl]
						case 2:
							params[key] = ""
						}
						c /= 3
					}
					want := cppGetSecSetting(params, feature, perm, legacy)
					got, _, ok := secSetting(mapConfig(params), cppPerms[perm], feature)
					if got != want || ok != (want != "") {
						t.Errorf("%s %s (legacy %v, %v): got %q (set %v), want %q",
							cppPerms[perm], feature, legacy, params, got, ok, want)
					}
				}
			}
		}
	}
}

// TestServerSecurityConfigFallsBackPerSetting: GetServerSecurityConfig
// resolves each setting of a level on its own, so an ADVERTISE_* level takes
// whichever of its settings it leaves unset from SEC_DAEMON_* before
// SEC_DEFAULT_*, and its own where it sets them.
func TestServerSecurityConfigFallsBackPerSetting(t *testing.T) {
	cfg := config.NewEmpty()
	for k, v := range map[string]string{
		"SEC_DEFAULT_AUTHENTICATION":          "OPTIONAL",
		"SEC_DAEMON_AUTHENTICATION":           "REQUIRED",
		"SEC_ADVERTISE_SCHEDD_AUTHENTICATION": "NEVER",
		"SEC_ADVERTISE_MASTER_AUTHENTICATION": "",
		"SEC_DEFAULT_ENCRYPTION":              "NEVER",
		"SEC_ADVERTISE_STARTD_ENCRYPTION":     "REQUIRED",
		"SEC_DEFAULT_AUTHENTICATION_METHODS":  "FS",
		"SEC_DAEMON_AUTHENTICATION_METHODS":   "SSL",
		"SEC_READ_INTEGRITY":                  "REQUIRED",
	} {
		cfg.Set(k, v)
	}
	sec := func(level string) *security.SecurityConfig {
		t.Helper()
		sc, err := GetServerSecurityConfig(cfg, commands.DC_NOP, level)
		if err != nil {
			t.Fatal(err)
		}
		return sc
	}
	for _, tc := range []struct {
		level          string
		authentication security.SecurityLevel
		encryption     security.SecurityLevel
		integrity      security.SecurityLevel
		methods        []security.AuthMethod
	}{
		{"DEFAULT", security.SecurityOptional, security.SecurityNever, security.SecurityOptional, []security.AuthMethod{security.AuthFS}},
		{"DAEMON", security.SecurityRequired, security.SecurityNever, security.SecurityOptional, []security.AuthMethod{security.AuthSSL}},
		// Its own ENCRYPTION, DAEMON's AUTHENTICATION and methods.
		{"ADVERTISE_STARTD", security.SecurityRequired, security.SecurityRequired, security.SecurityOptional, []security.AuthMethod{security.AuthSSL}},
		// Its own AUTHENTICATION; not ADVERTISE_STARTD's ENCRYPTION.
		{"ADVERTISE_SCHEDD", security.SecurityNever, security.SecurityNever, security.SecurityOptional, []security.AuthMethod{security.AuthSSL}},
		// An empty setting is unset.
		{"ADVERTISE_MASTER", security.SecurityRequired, security.SecurityNever, security.SecurityOptional, []security.AuthMethod{security.AuthSSL}},
		// READ falls back to DEFAULT, not DAEMON.
		{"READ", security.SecurityOptional, security.SecurityNever, security.SecurityRequired, nil},
		{"WRITE", security.SecurityOptional, security.SecurityNever, security.SecurityOptional, []security.AuthMethod{security.AuthFS}},
	} {
		sc := sec(tc.level)
		if sc.Authentication != tc.authentication {
			t.Errorf("%s authentication = %v, want %v", tc.level, sc.Authentication, tc.authentication)
		}
		if sc.Encryption != tc.encryption {
			t.Errorf("%s encryption = %v, want %v", tc.level, sc.Encryption, tc.encryption)
		}
		if sc.Integrity != tc.integrity {
			t.Errorf("%s integrity = %v, want %v", tc.level, sc.Integrity, tc.integrity)
		}
		if tc.methods != nil && !slices.Equal(sc.AuthMethods, tc.methods) {
			t.Errorf("%s methods = %v, want %v", tc.level, sc.AuthMethods, tc.methods)
		}
	}
	// READ appends ANONYMOUS to the DEFAULT methods, not to DAEMON's.
	if m := sec("READ").AuthMethods; !slices.Contains(m, security.AuthFS) || slices.Contains(m, security.AuthSSL) {
		t.Errorf("READ methods = %v, want SEC_DEFAULT_AUTHENTICATION_METHODS (FS)", m)
	}

	// Under LEGACY_ALLOW_SEMANTICS DAEMON falls back to WRITE, and an
	// ADVERTISE_* level through DAEMON to WRITE as well.
	legacy := config.NewEmpty()
	legacy.Set("LEGACY_ALLOW_SEMANTICS", "TRUE")
	legacy.Set("SEC_DEFAULT_AUTHENTICATION", "OPTIONAL")
	legacy.Set("SEC_WRITE_AUTHENTICATION", "REQUIRED")
	for _, level := range []string{"DAEMON", "ADVERTISE_STARTD"} {
		sc, err := GetServerSecurityConfig(legacy, commands.DC_NOP, level)
		if err != nil {
			t.Fatal(err)
		}
		if sc.Authentication != security.SecurityRequired {
			t.Errorf("legacy %s authentication = %v, want SEC_WRITE_AUTHENTICATION's %v", level, sc.Authentication, security.SecurityRequired)
		}
	}
}
