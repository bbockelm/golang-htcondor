package jupytertunnel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// memRoller is a NonceRoller with the same conditional-swap contract as
// the database one.
type memRoller struct {
	mu     sync.Mutex
	nonces map[string][]byte
}

func newMemRoller() *memRoller { return &memRoller{nonces: map[string][]byte{}} }

func (m *memRoller) set(id string, nonce []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonces[id] = append([]byte(nil), nonce...)
}

func (m *memRoller) current(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return string(m.nonces[id])
}

func (m *memRoller) RollNonce(_ context.Context, id string, from, to []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.nonces[id]
	if !ok || string(cur) != string(from) {
		return false, nil
	}
	m.nonces[id] = append([]byte(nil), to...)
	return true, nil
}

// A restarted server is a new Registry over the SAME secret and nonce
// store. The old one's in-memory state is gone, which is the whole
// scenario: the job is still running and the helper is dialing back.
func TestSessionSurvivesARestart(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	roller := newMemRoller()

	first, err := NewRegistryWithSecret(secret, roller)
	if err != nil {
		t.Fatalf("NewRegistryWithSecret: %v", err)
	}
	id, _, err := first.CreateInstance(CreateInstanceOptions{Owner: "alice"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	nonce, ok := first.PendingNonce(id)
	if !ok {
		t.Fatal("no pending nonce to persist; a restart could never re-adopt this session")
	}
	roller.set(id, nonce)

	// --- the API server restarts ---
	second, err := NewRegistryWithSecret(secret, roller)
	if err != nil {
		t.Fatalf("second registry: %v", err)
	}
	if _, ok := second.Lookup(id); ok {
		t.Fatal("the new registry already knows the session; the test is not exercising adoption")
	}

	inst, err := second.AdoptInstance(id, "alice", time.Now(), nil)
	if err != nil {
		t.Fatalf("AdoptInstance: %v", err)
	}
	if inst.Owner != "alice" {
		t.Errorf("adopted owner = %q", inst.Owner)
	}
	got, ok := second.Lookup(id)
	if !ok || got.ID != id {
		t.Error("the adopted session is not reachable by id")
	}
}

// Adoption must not invent a second live credential: the helper holds the
// only token that will be accepted.
func TestAdoptionMintsNoToken(t *testing.T) {
	secret := make([]byte, 32)
	reg, _ := NewRegistryWithSecret(secret, newMemRoller())
	inst, err := reg.AdoptInstance("deadbeef", "alice", time.Now(), nil)
	if err != nil {
		t.Fatalf("AdoptInstance: %v", err)
	}
	if inst.NextToken() != "" {
		t.Error("adoption issued a token; the helper already holds the only valid one")
	}
}

func TestAdoptionNeedsIdentity(t *testing.T) {
	reg, _ := NewRegistryWithSecret(make([]byte, 32), newMemRoller())
	if _, err := reg.AdoptInstance("", "alice", time.Now(), nil); err == nil {
		t.Error("adopted a session with no id")
	}
	if _, err := reg.AdoptInstance("x", "", time.Now(), nil); err == nil {
		t.Error("adopted a session with no owner; the proxy authorizes on owner")
	}
}

// Adopting twice keeps the first instance, so a sweep that runs after a
// helper has already attached does not drop its tunnel.
func TestAdoptionIsIdempotent(t *testing.T) {
	reg, _ := NewRegistryWithSecret(make([]byte, 32), newMemRoller())
	a, _ := reg.AdoptInstance("id1", "alice", time.Now(), nil)
	b, _ := reg.AdoptInstance("id1", "alice", time.Now(), nil)
	if a != b {
		t.Error("a second adoption replaced the instance, discarding any attached tunnel")
	}
}

// A replay must not disturb a healthy session.
//
// The grace step made ordering load-bearing. Spending the token before
// checking whether the session even has a free connection slot meant a
// replayed token -- refused a moment later because a helper is already
// connected -- had still rolled the nonce on, and the connected helper's
// token stopped being the one expected. A replay could end a working
// session that way, without ever authenticating as anything.
//
// The token here is the real one, which matters: a garbage token is
// rejected by verification before it reaches either the claim or the
// roll, so it exercises none of this.
func TestReplayDoesNotSpendATokenWhenTheSlotIsTaken(t *testing.T) {
	roller := newMemRoller()
	reg, err := NewRegistryWithSecret(make([]byte, 32), roller)
	if err != nil {
		t.Fatalf("NewRegistryWithSecret: %v", err)
	}
	id, token, err := reg.CreateInstance(CreateInstanceOptions{Owner: "alice"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	nonce, _ := reg.PendingNonce(id)
	roller.set(id, nonce)

	// Stand in for a healthy helper holding the slot.
	inst, _ := reg.Lookup(id)
	inst.mu.Lock()
	inst.connecting = true
	inst.mu.Unlock()

	before := roller.current(id)
	if _, err := reg.AcceptTunnel(id, token, nil); err == nil {
		t.Error("a dial was accepted while the slot was taken")
	}
	if after := roller.current(id); after != before {
		t.Errorf("the refused dial moved the nonce from %q to %q; the live helper's token is now stale", before, after)
	}
}

// errRoller fails the roll, so a dial gets past the claim and then dies.
type errRoller struct{}

func (e *errRoller) RollNonce(context.Context, string, []byte, []byte) (bool, error) {
	return false, errors.New("storage is down")
}

// The claim has to be released on every path, or one failed dial locks
// the session out of reconnecting for the rest of the job.
//
// Driven with a valid token and a failing roll: that is a dial that gets
// past the claim and then returns, which is the path where a missing
// release actually strands the session.
func TestConnectingClaimIsReleased(t *testing.T) {
	reg, err := NewRegistryWithSecret(make([]byte, 32), &errRoller{})
	if err != nil {
		t.Fatalf("NewRegistryWithSecret: %v", err)
	}
	id, token, err := reg.CreateInstance(CreateInstanceOptions{Owner: "alice"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}

	if _, err := reg.AcceptTunnel(id, token, nil); err == nil {
		t.Fatal("the dial should have failed on the roll")
	}

	inst, _ := reg.Lookup(id)
	inst.mu.Lock()
	stuck := inst.connecting
	inst.mu.Unlock()
	if stuck {
		t.Error("the connection claim was not released; no helper can ever reconnect")
	}
}
