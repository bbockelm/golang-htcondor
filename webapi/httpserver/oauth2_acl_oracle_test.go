package httpserver

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
)

// The schedd-ACL oracle reads a schedd's refusal of a level as the user's
// denial there: the schedd answers the probe's DC_SEC_QUERY DENIED, which
// PingWithOptions reports as not authorized. A schedd with no command at the
// level probed cannot answer, and the check then has no opinion.
func TestScheddACLOracleReadsRefusalAsDenial(t *testing.T) {
	keyFile := writeTestSigningKey(t)
	fs := fakeschedd.Start(t, keyFile, "test.domain")

	cfg := newTestConfig(t)
	cfg.ScheddAddr = fs.Addr()
	cfg.SigningKeyPath = keyFile
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	cfg.EnableMCP = true
	cfg.OAuth2Issuer = "http://localhost:8080"
	cfg.OAuth2RevocationOracles = []string{OracleScheddACL}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	oracle := s.scheddACLOracle()
	if oracle == nil {
		t.Fatal("the schedd-acl oracle is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	read := []string{"mcp:read", "condor:/READ"}
	decision, err := oracle.Check(ctx, "alice", read)
	if err != nil {
		t.Fatalf("probing READ: %v", err)
	}
	if len(decision.DeniedScopes) != 0 {
		t.Errorf("the schedd admits alice at READ, yet the oracle denied %v", decision.DeniedScopes)
	}

	fs.RefuseRead(true)
	decision, err = oracle.Check(ctx, "alice", read)
	if err != nil {
		t.Fatalf("probing READ the schedd refuses: %v, want a denial", err)
	}
	denied := slices.Clone(decision.DeniedScopes)
	slices.Sort(denied)
	if want := []string{"condor:/READ", "mcp:read"}; !slices.Equal(denied, want) {
		t.Errorf("the schedd refuses alice READ, and the oracle denied %v, want %v", denied, want)
	}
	fs.RefuseRead(false)

	// The fake schedd registers no command at WRITE.
	decision, err = oracle.Check(ctx, "alice", []string{"mcp:write"})
	if err == nil {
		t.Errorf("probing a level the schedd has no command at = %+v, want no opinion (an error)", decision)
	}
	if len(decision.DeniedScopes) != 0 {
		t.Errorf("a schedd that cannot answer denied %v", decision.DeniedScopes)
	}
}
