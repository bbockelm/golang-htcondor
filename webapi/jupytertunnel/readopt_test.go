package jupytertunnel

import (
	"context"
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
