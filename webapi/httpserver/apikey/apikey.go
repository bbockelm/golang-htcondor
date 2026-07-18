// Package apikey implements the wire format and crypto for HTTP API
// authentication tokens this server issues for non-interactive
// callers (Prometheus, scripts, CI). It's deliberately small and DB-
// free so it can be unit-tested without spinning up SQLite — the
// storage layer lives in the httpserver package.
//
// The wire format is:
//
//	htca-v1-<key_id>-<secret>
//
// where key_id is 12 hex chars (6 random bytes; this is what we use
// as the indexable lookup column) and secret is 32 hex chars (16
// random bytes; only its SHA-256 hash is persisted). The "htca-v1-"
// prefix is a leak-scan signature so a key accidentally pasted to a
// public log can be detected by tools that match literal substrings.
//
// Why SHA-256, not bcrypt: the secret already carries 128 bits of
// uniform entropy from crypto/rand. bcrypt's slow KDF is for low-
// entropy passwords; using it here would only add latency to every
// authenticated request. We do constant-time compare on the hash to
// avoid timing-leak shenanigans even though the security model
// doesn't strictly require it for cryptographically random secrets.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Prefix is the leak-scan signature that every key carries. Operators
// can grep logs / public sources for this literal to find leaks.
const Prefix = "htca-v1-"

// Sizes (in bytes, before hex encoding).
const (
	// keyIDLen is 6 bytes = 12 hex chars. 48 bits is more than enough
	// to make collisions astronomically unlikely at any realistic
	// scale (we'd need ~10M keys before a 1e-6 birthday-collision
	// probability), and short enough that the full key remains a
	// human-typeable length.
	keyIDLen = 6
	// secretLen is 16 bytes = 32 hex chars = 128 bits. Far above any
	// brute-force concern for an online attacker; well below the
	// session ID's 256 bits because we don't need 256 bits to
	// resist the 1e6 QPS attacker.
	secretLen = 16
)

// keyIDHexLen / secretHexLen are derived. We refer to them by name
// in parsing for readability.
const (
	keyIDHexLen  = keyIDLen * 2  // 12
	secretHexLen = secretLen * 2 // 32
)

// Errors callers should test for. Don't cmp the error string;
// errors.Is on these sentinels is the contract.
var (
	ErrMalformed     = errors.New("apikey: malformed key (expected htca-v1-<key_id>-<secret>)")
	ErrBadPrefix     = errors.New("apikey: missing htca-v1- prefix")
	ErrBadComponent  = errors.New("apikey: key_id or secret is not hex / wrong length")
	ErrSecretInvalid = errors.New("apikey: secret does not match stored hash")
)

// Minted is the result of Mint: the full wire-format string the
// caller MUST hand to the user once (and only once), plus the
// derived key_id and secret_hash that go into the DB.
type Minted struct {
	// Full is the wire-format string (htca-v1-<key_id>-<secret>).
	// Show this to the user exactly once; we never recover it.
	Full string
	// KeyID is the indexable lookup column. Safe to log / display.
	KeyID string
	// SecretHash is the hex SHA-256 of the secret half. Safe to
	// store at rest.
	SecretHash string
}

// Mint generates a fresh API key. Returns the wire-format string AND
// the (key_id, secret_hash) pair to persist. The wire-format string
// is NOT recoverable from anything we keep — show it once.
//
// Mint reads from crypto/rand; failures bubble up with errors that
// embed the operation. Real-world failure of crypto/rand is
// catastrophic and rare enough that we don't try to retry.
func Mint() (Minted, error) {
	idBytes := make([]byte, keyIDLen)
	if _, err := rand.Read(idBytes); err != nil {
		return Minted{}, fmt.Errorf("apikey: read random for key_id: %w", err)
	}
	secretBytes := make([]byte, secretLen)
	if _, err := rand.Read(secretBytes); err != nil {
		return Minted{}, fmt.Errorf("apikey: read random for secret: %w", err)
	}
	keyID := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)
	return Minted{
		Full:       Prefix + keyID + "-" + secret,
		KeyID:      keyID,
		SecretHash: hashSecretHex(secret),
	}, nil
}

// Parsed is the result of Parse: the components of a presented key.
// We intentionally don't expose the secret bytes — callers verify
// against a stored hash via VerifySecret, which means the secret
// only lives on the request stack, never in any longer-term
// structure.
type Parsed struct {
	// KeyID is the lookup column. Use it to fetch the row.
	KeyID string
	// secret is the raw secret half; kept private so the only path
	// that reads it is VerifySecret on this struct.
	secret string
}

// Parse extracts the key_id and the secret from a presented wire-
// format string. Returns ErrMalformed / ErrBadPrefix /
// ErrBadComponent for invalid inputs; never panics. Callers should
// treat ErrBadPrefix as "this isn't an API key, try other auth
// methods" — only ErrMalformed / ErrBadComponent are "this LOOKED
// like a key but was invalid".
func Parse(s string) (Parsed, error) {
	if !strings.HasPrefix(s, Prefix) {
		return Parsed{}, ErrBadPrefix
	}
	rest := strings.TrimPrefix(s, Prefix)
	// Expected shape: <12 hex>-<32 hex>. Splitting on "-" handles
	// trailing junk gracefully (we only consume two fields).
	dash := strings.IndexByte(rest, '-')
	if dash < 0 {
		return Parsed{}, ErrMalformed
	}
	keyID := rest[:dash]
	secret := rest[dash+1:]
	if len(keyID) != keyIDHexLen || len(secret) != secretHexLen {
		return Parsed{}, ErrBadComponent
	}
	if !isHex(keyID) || !isHex(secret) {
		return Parsed{}, ErrBadComponent
	}
	return Parsed{KeyID: keyID, secret: secret}, nil
}

// VerifySecret returns nil iff p.secret hashes to expectedHash. Uses
// constant-time compare on the hash byte sequence so a (theoretical)
// timing oracle can't reveal which bytes matched.
//
// expectedHash should be the hex-encoded SHA-256 stored in the DB.
// We re-hash p.secret here rather than letting callers do it so the
// "compare hashes" path is always constant-time and there's no way
// to accidentally `==` two strings.
func (p Parsed) VerifySecret(expectedHash string) error {
	got := hashSecretHex(p.secret)
	if subtle.ConstantTimeCompare([]byte(got), []byte(expectedHash)) != 1 {
		return ErrSecretInvalid
	}
	return nil
}

// hashSecretHex is the canonical hash function — call this
// EVERYWHERE the secret needs to become a hash. Both Mint and
// VerifySecret use it so the algorithm is changed in exactly one
// place if we ever rotate.
func hashSecretHex(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// isHex reports whether s is non-empty and entirely hex characters.
// Faster than encoding/hex.Decode for a fast-path check on a 12- or
// 32-char string, and avoids the allocation.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// LooksLikeKey is a pre-flight check the auth handler can use to
// decide "is this Bearer token an API key, or do I try other
// methods?". Cheaper than Parse and only inspects the prefix.
func LooksLikeKey(s string) bool {
	return strings.HasPrefix(s, Prefix)
}
