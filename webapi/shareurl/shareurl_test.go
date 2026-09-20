package shareurl

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := testSigner(t)
	want := Payload{Cluster: 12, Proc: 3, Owner: "alice", Exp: time.Now().Add(time.Hour).Unix(), Kind: KindInput}
	tok, err := s.Sign(want)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := s.Verify(tok, KindInput)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if *got != want {
		t.Fatalf("round trip changed the payload: got %+v want %+v", *got, want)
	}
}

// An upload token must not be redeemable as a download, or possession of
// one silently grants the other.
func TestVerifyRejectsTheOtherKind(t *testing.T) {
	s := testSigner(t)
	exp := time.Now().Add(time.Hour).Unix()

	input, err := s.Sign(Payload{Cluster: 1, Proc: 0, Owner: "alice", Exp: exp, Kind: KindInput})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Verify(input, KindOutput); err == nil {
		t.Fatal("an input token verified as an output token")
	}

	output, err := s.Sign(Payload{Cluster: 1, Proc: 0, Owner: "alice", Exp: exp, Kind: KindOutput})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Verify(output, KindInput); err == nil {
		t.Fatal("an output token verified as an input token")
	}
	// ...and each still verifies as itself, so the check above is not
	// just rejecting everything.
	if _, err := s.Verify(output, KindOutput); err != nil {
		t.Fatalf("output token rejected as its own kind: %v", err)
	}
}

// Tokens minted before Kind existed carry no "k" field and are output
// tokens. Kind's zero value has to keep meaning that.
func TestLegacyPayloadWithoutKindIsAnOutputToken(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Sign(Payload{Cluster: 7, Proc: 1, Owner: "bob", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Verify(tok, KindOutput); err != nil {
		t.Fatalf("a token minted with no Kind did not verify as an output token: %v", err)
	}
}

func TestVerifyRejectsTamperedAndExpired(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Sign(Payload{Cluster: 1, Proc: 0, Owner: "alice",
		Exp: time.Now().Add(time.Hour).Unix(), Kind: KindInput})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Flip a byte of the payload; the signature must stop matching.
	bad := []byte(tok)
	bad[0] ^= 0x01
	if _, err := s.Verify(string(bad), KindInput); err == nil {
		t.Fatal("a tampered token verified")
	}

	// A different key must not verify this token.
	other, err := NewSigner([]byte("ffffffffffffffffffffffffffffffff"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := other.Verify(tok, KindInput); err == nil {
		t.Fatal("a token verified under the wrong key")
	}

	expired, err := s.Sign(Payload{Cluster: 1, Proc: 0, Owner: "alice",
		Exp: time.Now().Add(-time.Second).Unix(), Kind: KindInput})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Verify(expired, KindInput); err == nil {
		t.Fatal("an expired token verified")
	}
}

func TestVerifyRejectsAnOwnerlessToken(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Sign(Payload{Cluster: 1, Proc: 0, Exp: time.Now().Add(time.Hour).Unix(), Kind: KindInput})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Verify(tok, KindInput); err == nil {
		t.Fatal("a token naming no owner verified; it would be redeemed as nobody")
	}
}

// The whole point of deriving from the signing key: two processes that
// read the same key agree, so a URL minted by the MCP server verifies in
// the REST daemon, and a restart does not strand outstanding URLs.
func TestKeyFromSigningKeyFileIsDeterministicAndDistinct(t *testing.T) {
	dir := t.TempDir()
	keyA := filepath.Join(dir, "POOL")
	if err := os.WriteFile(keyA, []byte("a pool signing key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	keyB := filepath.Join(dir, "OTHER")
	if err := os.WriteFile(keyB, []byte("a different key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	first, err := KeyFromSigningKeyFile(keyA)
	if err != nil {
		t.Fatalf("KeyFromSigningKeyFile: %v", err)
	}
	second, err := KeyFromSigningKeyFile(keyA)
	if err != nil {
		t.Fatalf("KeyFromSigningKeyFile (again): %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("the same signing key produced two different share keys")
	}
	if len(first) != 32 {
		t.Fatalf("expected a 32-byte key, got %d", len(first))
	}

	other, err := KeyFromSigningKeyFile(keyB)
	if err != nil {
		t.Fatalf("KeyFromSigningKeyFile: %v", err)
	}
	if string(first) == string(other) {
		t.Fatal("two different signing keys produced the same share key")
	}

	// A token minted under one derivation verifies under the other, which
	// is the cross-process property stated above.
	minter, err := NewSigner(first)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	redeemer, err := NewSigner(second)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := minter.Sign(Payload{Cluster: 5, Proc: 0, Owner: "alice",
		Exp: time.Now().Add(time.Hour).Unix(), Kind: KindInput})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := redeemer.Verify(tok, KindInput); err != nil {
		t.Fatalf("a separately derived key could not verify the token: %v", err)
	}
}

func TestKeyFromSigningKeyFileRefusesNothingToDeriveFrom(t *testing.T) {
	if _, err := KeyFromSigningKeyFile(""); err == nil {
		t.Fatal("an unconfigured signing key path produced a key")
	}
	empty := filepath.Join(t.TempDir(), "POOL")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := KeyFromSigningKeyFile(empty); err == nil {
		t.Fatal("an empty signing key file produced a key")
	}
}

func TestClampTTL(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kind      Kind
		requested time.Duration
		want      time.Duration
	}{
		{"input default", KindInput, 0, DefaultInputTTL},
		{"input negative falls back to the default", KindInput, -time.Hour, DefaultInputTTL},
		{"input honored", KindInput, 2 * time.Hour, 2 * time.Hour},
		{"input capped", KindInput, 72 * time.Hour, MaxInputTTL},
		{"output default", KindOutput, 0, DefaultOutputTTL},
		{"output capped", KindOutput, 10 * time.Hour, MaxOutputTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClampTTL(tc.kind, tc.requested); got != tc.want {
				t.Fatalf("ClampTTL(%v, %v) = %v, want %v", tc.kind, tc.requested, got, tc.want)
			}
		})
	}
}

func TestNewSignerRejectsAWeakKey(t *testing.T) {
	if _, err := NewSigner(nil); err == nil {
		t.Fatal("an empty key was accepted")
	}
	if _, err := NewSigner([]byte("short")); err == nil {
		t.Fatal("a 5-byte key was accepted")
	}
}

// Each kind addresses its subject with a different field. A token
// missing the one its kind uses would be redeemed against a zero value
// -- watch "" or job 0.0 -- instead of being refused.
func TestVerifyRequiresASubjectForTheKind(t *testing.T) {
	s := testSigner(t)
	exp := time.Now().Add(time.Hour).Unix()

	noWatch, err := s.Sign(Payload{Owner: "alice", Exp: exp, Kind: KindWatch})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Verify(noWatch, KindWatch); err == nil {
		t.Fatal("a watch token naming no watch verified; it would poll watch \"\"")
	}

	jobWithWatch, err := s.Sign(Payload{
		Cluster: 1, Proc: 0, Owner: "alice", Exp: exp, Kind: KindInput, Watch: "w1",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Verify(jobWithWatch, KindInput); err == nil {
		t.Fatal("a job token carrying a watch id verified; its subject is ambiguous")
	}

	good, err := s.Sign(Payload{Owner: "alice", Exp: exp, Kind: KindWatch, Watch: "w1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := s.Verify(good, KindWatch)
	if err != nil {
		t.Fatalf("a well-formed watch token was refused: %v", err)
	}
	if got.Watch != "w1" {
		t.Fatalf("watch id round-tripped to %q", got.Watch)
	}
}

// A watch URL is held for the life of the question, so its lifetime
// tracks the watch's rather than a transfer's.
func TestWatchTTLsAreTheWatchLifetimes(t *testing.T) {
	defaultTTL, maxTTL := Defaults(KindWatch)
	if defaultTTL != DefaultWatchTTL || maxTTL != MaxWatchTTL {
		t.Fatalf("Defaults(KindWatch) = (%v, %v), want (%v, %v)",
			defaultTTL, maxTTL, DefaultWatchTTL, MaxWatchTTL)
	}
	if got := ClampTTL(KindWatch, 0); got != DefaultWatchTTL {
		t.Fatalf("default watch TTL = %v", got)
	}
	if got := ClampTTL(KindWatch, 30*24*time.Hour); got != MaxWatchTTL {
		t.Fatalf("an over-long watch TTL clamped to %v", got)
	}
}
