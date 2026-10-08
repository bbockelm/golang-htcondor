package jupytertunnel

import (
	"testing"
	"time"
)

// The token a connected helper holds is for its next dial, and for a
// healthy session the next dial is the next server restart. Minted with the
// first-dial TTL it lapsed thirty minutes after the helper connected, so a
// restart refused every session older than that -- and a refused helper ends
// its job.
func TestReconnectTokenOutlivesTheFirstDialTTL(t *testing.T) {
	secret := make([]byte, 32)
	roller := newMemRoller()
	reg, err := NewRegistryWithSecret(secret, roller)
	if err != nil {
		t.Fatalf("NewRegistryWithSecret: %v", err)
	}
	reg.SetReconnectTokenTTL(6 * time.Hour)

	id, token, err := reg.CreateInstance(CreateInstanceOptions{Owner: "alice"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	nonce, _ := reg.PendingNonce(id)
	roller.set(id, nonce)

	spent, err := parseAndVerify(secret, token, time.Now())
	if err != nil {
		t.Fatalf("parseAndVerify: %v", err)
	}
	next, err := reg.rollToken(id, spent)
	if err != nil {
		t.Fatalf("rollToken: %v", err)
	}

	// Two hours on: well past the thirty-minute first-dial TTL, well inside
	// the session's horizon.
	if _, err := parseAndVerify(secret, next, time.Now().Add(2*time.Hour)); err != nil {
		t.Errorf("the reconnect token has lapsed two hours after it was issued (%v); "+
			"a restart after that refuses the helper and ends the session", err)
	}
	if _, err := parseAndVerify(secret, next, time.Now().Add(7*time.Hour)); err == nil {
		t.Error("the reconnect token outlives the horizon it was given")
	}
}
