package apikey

import (
	"errors"
	"strings"
	"testing"
)

// TestMintRoundTrip pins the basic mint → parse → verify cycle.
// Tampering with any character of the secret should fail
// VerifySecret; tampering with the key_id should fail Parse OR
// produce a different lookup row.
func TestMintRoundTrip(t *testing.T) {
	m, err := Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(m.Full, Prefix) {
		t.Errorf("minted key missing prefix %q: %s", Prefix, m.Full)
	}
	if !LooksLikeKey(m.Full) {
		t.Errorf("LooksLikeKey false for freshly minted key")
	}
	parsed, err := Parse(m.Full)
	if err != nil {
		t.Fatalf("Parse(minted): %v", err)
	}
	if parsed.KeyID != m.KeyID {
		t.Errorf("parsed.KeyID=%q, mint.KeyID=%q", parsed.KeyID, m.KeyID)
	}
	if err := parsed.VerifySecret(m.SecretHash); err != nil {
		t.Errorf("VerifySecret on freshly minted key: %v", err)
	}
}

// TestMintProducesDistinctKeys is a tiny statistical test — running
// Mint twice should NEVER produce the same key_id or the same secret.
// 48-bit collisions are vanishingly unlikely at this iteration count;
// a failure here means crypto/rand is broken, not unlucky.
func TestMintProducesDistinctKeys(t *testing.T) {
	const n = 100
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		m, err := Mint()
		if err != nil {
			t.Fatalf("Mint #%d: %v", i, err)
		}
		if seen[m.Full] {
			t.Fatalf("Mint #%d produced a duplicate full key", i)
		}
		seen[m.Full] = true
	}
}

// TestParseRejects walks the corner cases the auth handler relies on.
// Each case names the error sentinel it should bubble up so a future
// refactor that conflates them surfaces here.
func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{
			name: "empty string",
			in:   "",
			want: ErrBadPrefix,
		},
		{
			name: "missing prefix",
			in:   "not-an-api-key",
			want: ErrBadPrefix,
		},
		{
			name: "wrong prefix version",
			in:   "htca-v2-aaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			want: ErrBadPrefix,
		},
		{
			name: "no inner dash",
			in:   "htca-v1-aaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			want: ErrMalformed,
		},
		{
			name: "key_id too short",
			in:   "htca-v1-aaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			want: ErrBadComponent,
		},
		{
			name: "secret too short",
			in:   "htca-v1-aaaaaaaaaaaa-bbbbbbbb",
			want: ErrBadComponent,
		},
		{
			name: "non-hex characters in key_id",
			in:   "htca-v1-zzzzzzzzzzzz-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			want: ErrBadComponent,
		},
		{
			name: "non-hex characters in secret",
			in:   "htca-v1-aaaaaaaaaaaa-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			want: ErrBadComponent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.in)
			if !errors.Is(err, tc.want) {
				t.Errorf("Parse(%q): err=%v, want=%v", tc.in, err, tc.want)
			}
		})
	}
}

// TestVerifySecretRejectsTampering confirms a corrupted secret
// doesn't accidentally validate. The constant-time compare contract
// is critical for the auth path; if a future refactor switches to
// `==` this test will still pass (correctness is preserved) but the
// code review should catch the regression.
func TestVerifySecretRejectsTampering(t *testing.T) {
	m, err := Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	parsed, _ := Parse(m.Full)

	// Flip one byte of the secret in the middle of the wire-format
	// and re-parse. VerifySecret must reject.
	mid := len(m.Full) / 2
	tampered := []byte(m.Full)
	if tampered[mid] == 'a' {
		tampered[mid] = 'b'
	} else {
		tampered[mid] = 'a'
	}
	tparsed, err := Parse(string(tampered))
	if err != nil {
		// If the tamper landed in the key_id and we got
		// ErrBadComponent that's also a valid rejection — but we
		// engineered the case above to land in the secret so Parse
		// should still succeed.
		t.Fatalf("Parse(tampered): %v", err)
	}
	// If the tamper happened to land in the key_id (very unlikely
	// with mid placement but possible), the secret is still valid.
	// Skip in that case to avoid flake.
	if tparsed.secret == parsed.secret {
		t.Skip("tamper landed in key_id half; this iteration's secret unchanged")
	}
	if err := tparsed.VerifySecret(m.SecretHash); err == nil {
		t.Errorf("VerifySecret accepted a tampered secret")
	}
	if err := tparsed.VerifySecret(m.SecretHash); !errors.Is(err, ErrSecretInvalid) {
		t.Errorf("VerifySecret err=%v, want ErrSecretInvalid", err)
	}
}

// TestVerifySecretWrongHash confirms the hash comparison itself is
// correct even when the expected-hash side is wrong (e.g. a
// stale row pulled by mistake).
func TestVerifySecretWrongHash(t *testing.T) {
	m, _ := Mint()
	parsed, _ := Parse(m.Full)
	other, _ := Mint()
	if err := parsed.VerifySecret(other.SecretHash); !errors.Is(err, ErrSecretInvalid) {
		t.Errorf("VerifySecret against unrelated hash: err=%v, want ErrSecretInvalid", err)
	}
}
