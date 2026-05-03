package jupytertunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Token authenticates a single helper-side connect-back call.
//
// On-wire layout (72 bytes, base64url-encoded for transport):
//   [ 0:16] instance_id      (16 random bytes; UUID-shaped, but not parsed as one)
//   [16:24] expires_unix     (uint64 BE)
//   [24:40] nonce            (16 random bytes; replay-protection)
//   [40:72] hmac_sha256      (over the first 40 bytes, with the registry secret)
//
// The token is single-use: once verified successfully, its nonce is added to
// the registry's "burned" set and any subsequent verification fails. A token
// also expires automatically after a server-chosen TTL.
//
// We keep the layout binary instead of JSON so the helper binary's parser is
// trivial and cannot be tricked by structural ambiguities.

const (
	tokenInstanceIDLen = 16
	tokenExpiresOff    = tokenInstanceIDLen
	tokenExpiresLen    = 8
	tokenNonceOff      = tokenExpiresOff + tokenExpiresLen
	tokenNonceLen      = 16
	tokenSigOff        = tokenNonceOff + tokenNonceLen
	tokenSigLen        = 32
	tokenLen           = tokenSigOff + tokenSigLen
)

// ErrTokenInvalid is returned when a token fails any validation step.
// We deliberately do not expose more granular errors to outside callers so
// timing/error-channel oracles don't reveal which check failed first.
var ErrTokenInvalid = errors.New("jupytertunnel: invalid or expired token")

// signedToken is the parsed/validated form. ID is the 16-byte instance id;
// Nonce is the 16-byte replay-protection field.
type signedToken struct {
	ID      [tokenInstanceIDLen]byte
	Expires time.Time
	Nonce   [tokenNonceLen]byte
}

// formatInstanceID renders the 16-byte ID as a hex string.
// We use plain hex (no UUID dashes) because the ID is a random opaque blob.
func formatInstanceID(id [tokenInstanceIDLen]byte) string {
	return fmt.Sprintf("%x", id[:])
}

// mintToken creates a fresh token for the given instance with the given TTL,
// signed with secret. Returns the encoded token string and the parsed form
// (so the caller can register the nonce/expiry without reparsing).
func mintToken(secret []byte, id [tokenInstanceIDLen]byte, ttl time.Duration) (string, signedToken, error) {
	if len(secret) == 0 {
		return "", signedToken{}, errors.New("jupytertunnel: empty signing secret")
	}
	expires := time.Now().Add(ttl)
	var nonce [tokenNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", signedToken{}, fmt.Errorf("read nonce: %w", err)
	}

	buf := make([]byte, tokenLen)
	copy(buf[:tokenInstanceIDLen], id[:])
	binary.BigEndian.PutUint64(buf[tokenExpiresOff:tokenExpiresOff+tokenExpiresLen], uint64(expires.Unix()))
	copy(buf[tokenNonceOff:tokenNonceOff+tokenNonceLen], nonce[:])

	mac := hmac.New(sha256.New, secret)
	mac.Write(buf[:tokenSigOff])
	copy(buf[tokenSigOff:], mac.Sum(nil))

	return base64.RawURLEncoding.EncodeToString(buf), signedToken{
		ID:      id,
		Expires: expires,
		Nonce:   nonce,
	}, nil
}

// parseAndVerify decodes and validates a token. Returns ErrTokenInvalid for
// any failure (decode error, bad signature, expired). The caller must still
// reject replays via the nonce-burned set — that's a registry concern.
func parseAndVerify(secret []byte, encoded string, now time.Time) (signedToken, error) {
	buf, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(buf) != tokenLen {
		return signedToken{}, ErrTokenInvalid
	}

	// Verify HMAC in constant time.
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf[:tokenSigOff])
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, buf[tokenSigOff:]) {
		return signedToken{}, ErrTokenInvalid
	}

	expiresUnix := int64(binary.BigEndian.Uint64(buf[tokenExpiresOff : tokenExpiresOff+tokenExpiresLen]))
	expires := time.Unix(expiresUnix, 0)
	if !now.Before(expires) {
		return signedToken{}, ErrTokenInvalid
	}

	out := signedToken{Expires: expires}
	copy(out.ID[:], buf[:tokenInstanceIDLen])
	copy(out.Nonce[:], buf[tokenNonceOff:tokenNonceOff+tokenNonceLen])
	return out, nil
}

// generateInstanceID returns a fresh random 16-byte id.
func generateInstanceID() ([tokenInstanceIDLen]byte, error) {
	var id [tokenInstanceIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	return id, nil
}
