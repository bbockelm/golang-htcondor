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
// A random 256-bit data-encryption key (DEK) encrypts the serialized session
// entries. The DEK itself is never stored in the clear: it is wrapped once per
// available HTCondor signing key (the KEKs), producing one masterKeyRow each.
// At boot the DEK is recovered from the first signing key that matches a stored
// row, so the cache survives signing-key rotation (add a row per new key) and
// partial key availability (any one key suffices). A stolen database is useless
// without one of the signing keys.

const (
	dekSize   = 32 // AES-256
	saltSize  = 16
	nonceSize = 12 // AES-GCM standard nonce
	kekInfo   = "condor-session-cache-dek-v1"
)

// SigningKey is one HTCondor signing key used as a key-encryption key. ID is the
// key name (e.g. "POOL"); Material is the raw (unscrambled) key bytes. Build it
// from htcondor.LoadSigningKeys.
type SigningKey struct {
	ID       string
	Material []byte
}

// masterKeyRow is the persisted wrapping of the DEK by a single signing key.
type masterKeyRow struct {
	KeyID   string
	Salt    []byte
	Nonce   []byte
	Wrapped []byte // AES-GCM(KEK, DEK)
}

// envelope holds an in-memory DEK.
type envelope struct {
	dek []byte
}

func newEnvelope() (*envelope, error) {
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generating DEK: %w", err)
	}
	return &envelope{dek: dek}, nil
}

// wrapFor wraps the DEK with the KEK derived from k, producing a row to persist.
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
	nonce, wrapped, err := gcmSeal(kek, e.dek)
	if err != nil {
		return masterKeyRow{}, err
	}
	return masterKeyRow{KeyID: k.ID, Salt: salt, Nonce: nonce, Wrapped: wrapped}, nil
}

// errNoKey indicates none of the available signing keys could unwrap the DEK.
var errNoKey = errors.New("sessioncache: no available signing key can decrypt the session cache")

// openEnvelope recovers the DEK from the first row whose key_id matches an
// available signing key and whose wrapping decrypts. Returns errNoKey if none
// match (e.g. all signing keys rotated away).
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
		dek, err := gcmOpen(kek, row.Nonce, row.Wrapped)
		if err != nil {
			continue // wrong key material for this id, or tampering; try the next
		}
		return &envelope{dek: dek}, nil
	}
	return nil, errNoKey
}

func (e *envelope) seal(plaintext []byte) (nonce, ciphertext []byte, err error) {
	return gcmSeal(e.dek, plaintext)
}

func (e *envelope) open(nonce, ciphertext []byte) ([]byte, error) {
	return gcmOpen(e.dek, nonce, ciphertext)
}

// deriveKEK derives a 256-bit key-encryption key from raw signing-key material
// and a per-row salt using HKDF-SHA256.
func deriveKEK(material, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, material, salt, []byte(kekInfo))
	kek := make([]byte, dekSize)
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
