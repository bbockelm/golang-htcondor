package authz

import (
	"net"
	"testing"
)

// mapConfig is a trivial ConfigGetter for tests.
type mapConfig map[string]string

func (m mapConfig) Get(k string) (string, bool) { v, ok := m[k]; return v, ok }

// newTestPolicy builds a Policy with DNS resolution stubbed out so tests are
// hermetic. fwd maps hostname->IPs, rev maps IP-string->hostnames.
func newTestPolicy(t *testing.T, cfg mapConfig, fwd map[string][]string, rev map[string][]string) *Policy {
	t.Helper()
	p, err := NewPolicy(cfg, "CCB")
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	p.forwardResolve = func(h string) []string { return fwd[h] }
	p.reverseResolve = func(ip net.IP) []string {
		if ip == nil {
			return nil
		}
		return rev[ip.String()]
	}
	// Rebuild tables now that forwardResolve is set (fill_table ran in NewPolicy
	// with the default resolver). Re-run buildEntry for affected perms.
	for _, perm := range allPerms {
		p.entries[perm] = p.buildEntry(cfg, perm)
	}
	return p
}

func ip(s string) net.IP { return net.ParseIP(s) }

func TestVerifyBehaviorOptimizations(t *testing.T) {
	// DAEMON with no ALLOW -> deny everyone; READ with no config -> use-table
	// (default-deny posture, since no ALLOW present and READ tables empty).
	p := newTestPolicy(t, mapConfig{}, nil, nil)
	if p.Verify(PermDaemon, ip("10.0.0.1"), "condor@pool") {
		t.Error("DAEMON with no ALLOW must deny")
	}

	// ALLOW_DAEMON = * -> allow anyone.
	p = newTestPolicy(t, mapConfig{"ALLOW_DAEMON": "*"}, nil, nil)
	if !p.Verify(PermDaemon, ip("10.0.0.1"), "condor@pool") {
		t.Error("ALLOW_DAEMON=* must allow anyone")
	}

	// ALLOW_DAEMON=* with DENY_DAEMON=10.0.0.5 -> only-denies.
	p = newTestPolicy(t, mapConfig{"ALLOW_DAEMON": "*", "DENY_DAEMON": "10.0.0.5"}, nil, nil)
	if p.Verify(PermDaemon, ip("10.0.0.5"), "condor@pool") {
		t.Error("DENY_DAEMON must deny the listed IP")
	}
	if !p.Verify(PermDaemon, ip("10.0.0.6"), "condor@pool") {
		t.Error("only-denies must allow the unlisted IP")
	}
}

func TestVerifyUseTable(t *testing.T) {
	cfg := mapConfig{
		"ALLOW_DAEMON": "condor@pool.example/192.168.0.0/16, schedd@*/10.0.0.0/8",
		"DENY_DAEMON":  "*/192.168.5.0/24",
	}
	p := newTestPolicy(t, cfg, nil, nil)

	if !p.Verify(PermDaemon, ip("192.168.1.1"), "condor@pool.example") {
		t.Error("listed user from listed subnet should be allowed")
	}
	if p.Verify(PermDaemon, ip("192.168.1.1"), "mallory@evil.example") {
		t.Error("unlisted user should be denied")
	}
	if p.Verify(PermDaemon, ip("172.16.0.1"), "condor@pool.example") {
		t.Error("listed user from a non-listed subnet should be denied")
	}
	// Deny subnet wins even for an otherwise-allowed user.
	if p.Verify(PermDaemon, ip("192.168.5.5"), "condor@pool.example") {
		t.Error("deny subnet must override allow")
	}
	// Second allow rule: schedd from 10.x.
	if !p.Verify(PermDaemon, ip("10.1.2.3"), "schedd@some.host") {
		t.Error("second allow rule should match")
	}
}

func TestVerifyHierarchyImplication(t *testing.T) {
	// Only WRITE is configured; READ should be granted via implication, since
	// granting WRITE implies READ (DirectlyImpliedBy(READ) includes WRITE).
	cfg := mapConfig{"ALLOW_WRITE": "condor@pool/192.168.0.0/16"}
	p := newTestPolicy(t, cfg, nil, nil)

	if !p.Verify(PermWrite, ip("192.168.1.1"), "condor@pool") {
		t.Error("WRITE should be allowed directly")
	}
	if !p.Verify(PermRead, ip("192.168.1.1"), "condor@pool") {
		t.Error("READ should be implied by WRITE")
	}
	if p.Verify(PermRead, ip("192.168.1.1"), "other@pool") {
		t.Error("READ should not be granted to a user who has neither READ nor WRITE")
	}
}

func TestVerifyPoolUsernameEquivalent(t *testing.T) {
	// A rule for condor@pool should also admit condor_pool@pool and vice versa.
	cfg := mapConfig{"ALLOW_DAEMON": "condor@pool/*"}
	p := newTestPolicy(t, cfg, nil, nil)
	if !p.Verify(PermDaemon, ip("1.2.3.4"), "condor_pool@pool") {
		t.Error("condor_pool@ should be accepted as equivalent to condor@")
	}
}

func TestVerifyHostnameResolution(t *testing.T) {
	// ALLOW lists a hostname; the entry expands to its IP (forward) and the IP's
	// reverse name must match the hostname pattern.
	cfg := mapConfig{"ALLOW_DAEMON": "worker.example"}
	fwd := map[string][]string{"worker.example": {"203.0.113.9"}}
	rev := map[string][]string{"198.51.100.7": {"other.example"}}
	p := newTestPolicy(t, cfg, fwd, rev)

	if !p.Verify(PermDaemon, ip("203.0.113.9"), "anyone@x") {
		t.Error("forward-resolved IP of the hostname entry should match")
	}
	if p.Verify(PermDaemon, ip("198.51.100.7"), "anyone@x") {
		t.Error("a different host should not match")
	}
}

func TestCommandPerms(t *testing.T) {
	reg := CommandPerms(67, 68, 67)
	if len(reg) == 0 || reg[0] != PermDaemon {
		t.Errorf("register should map to DAEMON first, got %v", reg)
	}
	req := CommandPerms(67, 68, 68)
	if len(req) != 1 || req[0] != PermRead {
		t.Errorf("request should map to READ, got %v", req)
	}
}
