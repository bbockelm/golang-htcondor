package htcondor

import "testing"

func TestCondorUsername(t *testing.T) {
	if got := condorUsername(mustConfig(t, "")); got != "condor" {
		t.Errorf("default = %q, want condor", got)
	}
	if got := condorUsername(mustConfig(t, "CONDOR_USER = svc\n")); got != "svc" {
		t.Errorf("override = %q, want svc", got)
	}
}

func TestFSRootToCondor(t *testing.T) {
	if fsRootToCondor(mustConfig(t, "")) != nil {
		t.Error("unset should be nil (leave cedar's default)")
	}
	if p := fsRootToCondor(mustConfig(t, "FS_ROOT_TO_CONDOR = false\n")); p == nil || *p {
		t.Errorf("false should be &false, got %v", p)
	}
	if p := fsRootToCondor(mustConfig(t, "FS_ROOT_TO_CONDOR = true\n")); p == nil || !*p {
		t.Errorf("true should be &true, got %v", p)
	}
}

// TestGetSecurityConfigWiresFSCondor verifies the FS-auth root->condor fields are set on
// the security config the builder produces.
func TestGetSecurityConfigWiresFSCondor(t *testing.T) {
	sc, err := GetSecurityConfig(mustConfig(t, "SEC_CLIENT_AUTHENTICATION_METHODS = FS\nCONDOR_USER = svc\n"), 60000, "CLIENT")
	if err != nil {
		t.Fatal(err)
	}
	if sc.CondorUsername != "svc" {
		t.Errorf("CondorUsername = %q, want svc", sc.CondorUsername)
	}
	if sc.CondorPrivRunner == nil {
		t.Error("CondorPrivRunner should be wired onto the config")
	}
}
