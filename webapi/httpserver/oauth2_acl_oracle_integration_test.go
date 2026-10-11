//go:build integration

package httpserver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// The schedd-ACL oracle probes WRITE with a token it mints for the user. It
// asked the minter for no scopes, which the minter maps to READ -- so every
// WRITE probe was refused for the token's own limit rather than the ACL, and
// the oracle stripped mcp:write and condor:/WRITE from everybody. Against a
// real schedd: a user the ACL admits keeps both, and a user DENY_WRITE names
// loses both and keeps READ.
func TestScheddACLOracleProbesWriteWithAWriteToken(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH")
	}

	tempDir := t.TempDir()
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })

	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	const trustDomain = "test.htcondor.org"

	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\nDENY_WRITE = bob@" + trustDomain + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	master, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("starting condor_master: %v", err)
	}
	t.Cleanup(func() { stopCondorMaster(master, t) })
	defer func() {
		if t.Failed() {
			printHTCondorLogs(tempDir, t)
		}
	}()
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("condor did not start: %v", err)
	}
	scheddAddr, err := getScheddAddress(tempDir, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewServer(Config{
		ClientConfig:            loadPoolConfig(t, configFile),
		Logger:                  testLogger(t),
		ScheddName:              "local",
		ScheddAddr:              scheddAddr,
		SigningKeyPath:          keyPath,
		TrustDomain:             trustDomain,
		UIDDomain:               trustDomain,
		EnableMCP:               true,
		OAuth2Issuer:            "http://localhost:8080",
		OAuth2DBPath:            filepath.Join(tempDir, "oauth2.db"),
		OAuth2RevocationOracles: []string{OracleScheddACL},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	oracle := s.scheddACLOracle()
	if oracle == nil {
		t.Fatal("the schedd-acl oracle is not configured")
	}

	scopes := []string{"mcp:read", "mcp:write", "condor:/READ", "condor:/WRITE"}
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer checkCancel()

	decision, err := oracle.Check(checkCtx, "alice", scopes)
	if err != nil {
		t.Fatalf("probing for alice: %v", err)
	}
	if len(decision.DeniedScopes) != 0 {
		t.Errorf("the ACL admits alice at WRITE, yet the oracle denied %v", decision.DeniedScopes)
	}

	decision, err = oracle.Check(checkCtx, "bob", scopes)
	if err != nil {
		t.Fatalf("probing for bob: %v", err)
	}
	denied := slices.Clone(decision.DeniedScopes)
	slices.Sort(denied)
	if want := []string{"condor:/WRITE", "mcp:write"}; !slices.Equal(denied, want) {
		t.Errorf("DENY_WRITE names bob, and the oracle denied %v, want %v", denied, want)
	}
}
