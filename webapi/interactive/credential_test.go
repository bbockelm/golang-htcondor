package interactive

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// testJWT is an unsigned JWT for sub expiring at exp: enough for the
// credential plumbing, which reads exp and never checks a signature.
func testJWT(sub string, exp time.Time) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc([]byte(fmt.Sprintf(`{"sub":%q,"exp":%d}`, sub, exp.Unix()))) + ".sig"
}

// The lease outlives the token the last call carried -- minutes against
// half an hour -- so removing the job when it runs out must present a
// credential minted again for the caller, not the one that call carried.
func TestLeaseExpiryRemovesWithARenewedCredential(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{
		HeartbeatInterval: 10 * time.Millisecond,
		DefaultLease:      60 * time.Millisecond,
	})

	carried := testJWT("alice@uid.example.com", time.Now().Add(5*time.Second))
	renewed := testJWT("alice@uid.example.com", time.Now().Add(time.Hour))
	ctx := htcondor.WithUserRequest(context.Background(), "test request")
	ctx = htcondor.WithRenewableSecurityConfig(ctx, &security.SecurityConfig{Token: carried},
		func(context.Context) (*security.SecurityConfig, error) {
			return &security.SecurityConfig{Token: renewed}, nil
		})

	if _, err := mgr.Create(ctx, alice, CreateSpec{Name: "build"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	job := schedd.setOwner(alice.Owner)
	schedd.setStatus(job, jobStatusRunning)
	if _, err := mgr.Exec(ctx, alice, "build", ExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec: %v", err)
	}

	waitFor(t, "the expired session to be removed", 3*time.Second, func() bool {
		return len(schedd.removedJobs()) > 0
	})
	if got := schedd.removedWithTokens()[0]; got != renewed {
		t.Errorf("lease expiry presented %q, want the renewed credential", got)
	}
}
