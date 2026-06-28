package sqlite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Envelope encryption for the persisted session cache.
//
// A random 256-bit database master key is the root of a small key hierarchy.
// The session records are encrypted not with the master key directly but with a
// purpose-specific subkey derived from it: sessionKey = HKDF(master, "session
// cache"). Deriving per-purpose subkeys means the same master key can protect
// other future uses (each with its own context label) without key reuse.
//
// The master key is never stored in the clear: it is wrapped once per available
// HTCondor signing key (the KEKs), producing one masterKeyRow each. At boot the
// master key is recovered from the first signing key that matches a stored row,
// so the cache survives signing-key rotation (add a row per new key) and partial
// key availability (any one key suffices). A stolen database is useless without
// one of the signing keys.

const (
	keySize   = 32 // AES-256
	saltSize  = 16
	nonceSize = 12 // AES-GCM standard nonce
	kekInfo   = "condor-session-cache-dek-v1"

	// sessionCacheInfo is the HKDF context that derives the session-record
	// encryption key from the database master key.
	sessionCacheInfo = "session cache"
)

// SigningKey is one HTCondor signing key used as a key-encryption key. ID is the
// key name (e.g. "POOL"); Material is the raw (unscrambled) key bytes. Build it
// from htcondor.LoadSigningKeys.
type SigningKey struct {
	ID       string
	Material []byte
}

// masterKeyRow is the persisted wrapping of the database master key by a single
// signing key.
type masterKeyRow struct {
	KeyID   string
	Salt    []byte
	Nonce   []byte
	Wrapped []byte // AES-GCM(KEK, masterKey)
}

// envelope holds the in-memory database master key and the session-cache subkey
// derived from it.
type envelope struct {
	master     []byte // database master key; wrapped per signing key
	sessionKey []byte // HKDF(master, "session cache"); seals/opens session records
}

func newEnvelope() (*envelope, error) {
	master := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, master); err != nil {
		return nil, fmt.Errorf("generating master key: %w", err)
	}
	return envelopeFromMaster(master)
}

// envelopeFromMaster builds the envelope around an existing master key, deriving
// the session-cache subkey.
func envelopeFromMaster(master []byte) (*envelope, error) {
	sk, err := deriveSubkey(master, sessionCacheInfo)
	if err != nil {
		return nil, err
	}
	return &envelope{master: master, sessionKey: sk}, nil
}

// wrapFor wraps the master key with the KEK derived from k, producing a row to
// persist.
func (e *envelope) wrapFor(k SigningKey) (masterKeyRow, error) {
	if len(k.Material) == 0 {
		return masterKeyRow{}, fmt.Errorf("signing key %q has no material", k.ID)
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return masterKeyRow{}, err
	}
	kek, err := deriveKEK(k.Material, salt)
	if err != nil {
		return masterKeyRow{}, err
	}
	nonce, wrapped, err := gcmSeal(kek, e.master)
	if err != nil {
		return masterKeyRow{}, err
	}
	return masterKeyRow{KeyID: k.ID, Salt: salt, Nonce: nonce, Wrapped: wrapped}, nil
}

// errNoKey indicates none of the available signing keys could unwrap the master
// key.
var errNoKey = errors.New("sessioncache: no available signing key can decrypt the session cache")

// openEnvelope recovers the master key from the first row whose key_id matches an
// available signing key and whose wrapping decrypts, then derives the subkey.
// Returns errNoKey if none match (e.g. all signing keys rotated away).
func openEnvelope(rows []masterKeyRow, keys []SigningKey) (*envelope, error) {
	byID := make(map[string]SigningKey, len(keys))
	for _, k := range keys {
		byID[k.ID] = k
	}
	for _, row := range rows {
		k, ok := byID[row.KeyID]
		if !ok {
			continue
		}
		kek, err := deriveKEK(k.Material, row.Salt)
		if err != nil {
			continue
		}
		master, err := gcmOpen(kek, row.Nonce, row.Wrapped)
		if err != nil {
			continue // wrong key material for this id, or tampering; try the next
		}
		return envelopeFromMaster(master)
	}
	return nil, errNoKey
}

func (e *envelope) seal(plaintext []byte) (nonce, ciphertext []byte, err error) {
	return gcmSeal(e.sessionKey, plaintext)
}

func (e *envelope) open(nonce, ciphertext []byte) ([]byte, error) {
	return gcmOpen(e.sessionKey, nonce, ciphertext)
}

// deriveSubkey derives a 256-bit purpose-specific key from the master key using
// HKDF-SHA256 with the given context label.
func deriveSubkey(master []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, master, nil, []byte(info))
	out := make([]byte, keySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("deriving %q subkey: %w", info, err)
	}
	return out, nil
}

// deriveKEK derives a 256-bit key-encryption key from raw signing-key material
// and a per-row salt using HKDF-SHA256.
func deriveKEK(material, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, material, salt, []byte(kekInfo))
	kek := make([]byte, keySize)
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("deriving KEK: %w", err)
	}
	return kek, nil
}

func gcmSeal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.Seal(nil, nonce, plaintext, nil), nil
}

func gcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != g.NonceSize() {
		return nil, fmt.Errorf("bad nonce size %d", len(nonce))
	}
	return g.Open(nil, nonce, ciphertext, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
