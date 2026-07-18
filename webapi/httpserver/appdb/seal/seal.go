// Package seal provides envelope encryption for sensitive columns in
// the unified application database.
//
// Threat model: protect long-lived signing keys (the OAuth2 / IDP
// issuer's RSA private key, fosite's HMAC GlobalSecret) from leaking
// when the SQLite file is exfiltrated — backups copied off the PVC,
// container debug shells, snapshot leaks. Once the master KEK is on a
// separately-mounted secret, raw access to the DB is no longer
// equivalent to "forge tokens for any user."
//
// Design — envelope encryption:
//
//  1. The operator provides a master Key Encryption Key (KEK) by
//     pointing HTTP_API_KEK_FILE at a 32-byte secret. HTCondor config
//     values are considered public, so the file path goes in config
//     but the bytes don't.
//  2. On first use we generate a 32-byte salt and persist it in the
//     DB's kek_metadata table. The salt is non-secret — the master
//     KEK is what protects everything.
//  3. The DB-instance KEK is HKDF-SHA256(masterKEK, salt,
//     "htcondor-api/db-kek/v1"). This binds the derived key to the
//     specific DB file even if the master KEK is reused across
//     deployments, and gives us a clean rotation handle (re-derive
//     when info or salt change) without exposing the master.
//  4. Each row gets a fresh random 32-byte Data Encryption Key (DEK).
//     The DEK is wrapped under the DB KEK with AES-256-GCM; the data
//     is encrypted with the DEK, also AES-256-GCM. The wrapped DEK
//     lives in a sibling `_dek` column so an operator inspecting the
//     DB with sqlite3 can immediately tell which rows are encrypted.
//
// Both ciphertext blobs include a 1-byte version tag so we can
// migrate to a different cipher suite later without ambiguity.
//
// # Operator-managed KEK file: never auto-created
//
// This package will never create or write to the KEK file. If
// LoadMasterKEKFromFile is asked to load a path that doesn't exist,
// it returns an error (with a generation hint) and refuses to start.
// Auto-creating the file would be a footgun in containerised
// deployments: a freshly-generated KEK on an emptyDir / unmounted
// path would silently invent a new key on every restart, the
// derived DB KEK would no longer match what's in kek_metadata, and
// every wrapped DEK in the DB would become un-openable — losing the
// OAuth2 / IDP signing keys + every encrypted secret on the next
// container start. The operator MUST provide the file out-of-band
// (k8s Secret, sealed-secret, vault csi driver, etc.) and stage it
// as a stable mount.
package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

const (
	// sealVersion is the leading byte on both the wrapped DEK and
	// the ciphertext payload. v1 = AES-256-GCM with 12-byte nonce
	// for both layers. New cipher suites bump this.
	sealVersion byte = 1

	// MasterKEKBytes is the required raw master KEK length. We
	// accept either exactly this many raw bytes, or a hex-encoded
	// string that decodes to this many bytes. 32 bytes ≡ AES-256.
	MasterKEKBytes = 32

	// derivedKEKBytes / dekBytes are both 32 (AES-256).
	derivedKEKBytes = 32
	dekBytes        = 32

	// SaltBytes is the length of the per-DB salt threaded into HKDF.
	// 32 bytes is overkill for HKDF salt but uniform with the keys.
	SaltBytes = 32

	// nonceSize for AES-GCM. The standard is 12.
	nonceSize = 12
)

// hkdfInfo is the HKDF info parameter — a domain separator that
// guarantees the same master KEK can be safely reused for some
// future purpose (e.g. encrypting another file) without colliding
// keys. v1 in the suffix makes future rotations explicit.
const hkdfInfo = "htcondor-api/db-kek/v1"

// LoadMasterKEKFromFile reads the master KEK from path. The file
// must contain exactly MasterKEKBytes raw bytes, or a hex-encoded
// string that decodes to that length. Trailing whitespace / newlines
// in the hex form are tolerated — `openssl rand -hex 32 > kek` is the
// recommended generation recipe.
//
// Refuses to read a file with any world (other) bits set. Group bits
// are tolerated because kubelet applies `fsGroup` to Secret/ConfigMap
// volume mounts and forces group-read (turning a 0400 file into 0440);
// the "group" in that mount is the pod's own fsgroup, not a multi-tenant
// boundary. World-readable, however, is always wrong: it means anyone
// on the host (or in another container sharing the namespace) can read
// the KEK, which is equivalent to a leaked DB.
//
// This function NEVER creates the file. If the path doesn't exist
// the call returns an explicit error including the openssl recipe
// for the operator. Auto-generating a missing KEK would be unsafe
// in container deployments where the file location may not be
// persisted across restarts; see the package doc for the full
// rationale.
func LoadMasterKEKFromFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf(
			"kek file %s does not exist; this package never creates it. "+
				"Generate one out-of-band with: `openssl rand -hex 32 > %s && chmod 0600 %s` "+
				"and stage it via your secrets mechanism (k8s Secret, vault, …). "+
				"Auto-generating a missing KEK would silently lose every encrypted DB row on the next restart if the file location isn't persisted",
			path, path, path,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("kek file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("kek file %s: is a directory", path)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		return nil, fmt.Errorf("kek file %s is world-accessible (mode %#o); must have no other-bits set (typical: 0600, 0400, or 0440 for kubelet+fsGroup mounts)", path, perm)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path is operator-controlled
	if err != nil {
		return nil, fmt.Errorf("read kek file: %w", err)
	}
	// Trim trailing whitespace + newlines so an editor-saved hex
	// file works without surgery.
	raw = bytes.TrimRight(raw, "\r\n\t ")
	if len(raw) == MasterKEKBytes {
		return raw, nil
	}
	// Try hex decode for the openssl-rand-hex case.
	if dec, err := hex.DecodeString(string(raw)); err == nil && len(dec) == MasterKEKBytes {
		return dec, nil
	}
	return nil, fmt.Errorf("kek file %s: must contain exactly %d raw bytes or a %d-byte hex string", path, MasterKEKBytes, MasterKEKBytes)
}

// DeriveDBKey derives the DB-instance KEK from the master + a
// per-DB salt using HKDF-SHA256. Pure function; both inputs are
// required.
func DeriveDBKey(masterKEK, salt []byte) ([]byte, error) {
	if len(masterKEK) != MasterKEKBytes {
		return nil, fmt.Errorf("master KEK is %d bytes, want %d", len(masterKEK), MasterKEKBytes)
	}
	if len(salt) == 0 {
		return nil, errors.New("salt is required")
	}
	r := hkdf.New(sha256.New, masterKEK, salt, []byte(hkdfInfo))
	out := make([]byte, derivedKEKBytes)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}

// NewSalt returns SaltBytes of cryptographically-random data, suitable
// for persisting in the kek_metadata table.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return salt, nil
}

// Sealer wraps the DB-instance KEK with AES-256-GCM for envelope
// encryption. Construct once at startup; the underlying cipher.AEAD
// is goroutine-safe so callers can share a Sealer across requests.
type Sealer struct {
	aead cipher.AEAD // AES-256-GCM keyed with the DB KEK
}

// New constructs a Sealer from a 32-byte DB-instance KEK.
func New(dbKEK []byte) (*Sealer, error) {
	if len(dbKEK) != derivedKEKBytes {
		return nil, fmt.Errorf("db kek is %d bytes, want %d", len(dbKEK), derivedKEKBytes)
	}
	block, err := aes.NewCipher(dbKEK)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal returns the ciphertext for `plaintext` and the wrapped
// per-row DEK, suitable for storing in adjacent columns. Both blobs
// include a 1-byte version tag so we can migrate cipher suites later.
//
// The wrapped-DEK blob layout is:
//
//	1 byte:  sealVersion
//	12 bytes: nonce
//	48 bytes: AES-GCM(DBKey, dek)            ← 32 plaintext + 16 tag
//
// The data blob layout is:
//
//	1 byte:  sealVersion
//	12 bytes: nonce
//	N+16 bytes: AES-GCM(dek, plaintext)
func (s *Sealer) Seal(plaintext []byte) (data, wrappedDEK []byte, err error) {
	dek := make([]byte, dekBytes)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("rand dek: %w", err)
	}

	// Wrap the DEK under the DB KEK.
	dekNonce := make([]byte, nonceSize)
	if _, err := rand.Read(dekNonce); err != nil {
		return nil, nil, fmt.Errorf("rand dek nonce: %w", err)
	}
	sealedDEK := s.aead.Seal(nil, dekNonce, dek, nil)
	wrappedDEK = make([]byte, 0, 1+nonceSize+len(sealedDEK))
	wrappedDEK = append(wrappedDEK, sealVersion)
	wrappedDEK = append(wrappedDEK, dekNonce...)
	wrappedDEK = append(wrappedDEK, sealedDEK...)

	// Encrypt the data under the per-row DEK.
	dataAEAD, err := newGCM(dek)
	if err != nil {
		return nil, nil, err
	}
	dataNonce := make([]byte, nonceSize)
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, nil, fmt.Errorf("rand data nonce: %w", err)
	}
	sealedData := dataAEAD.Seal(nil, dataNonce, plaintext, nil)
	data = make([]byte, 0, 1+nonceSize+len(sealedData))
	data = append(data, sealVersion)
	data = append(data, dataNonce...)
	data = append(data, sealedData...)

	return data, wrappedDEK, nil
}

// Open is the inverse of Seal. Returns the original plaintext.
// Authentication failure (wrong KEK, tampering) surfaces as a
// non-nil error.
func (s *Sealer) Open(data, wrappedDEK []byte) ([]byte, error) {
	if len(wrappedDEK) < 1+nonceSize+dekBytes+gcmTag {
		return nil, errors.New("seal: wrapped DEK truncated")
	}
	if wrappedDEK[0] != sealVersion {
		return nil, fmt.Errorf("seal: unsupported wrapped DEK version %d", wrappedDEK[0])
	}
	dekNonce := wrappedDEK[1 : 1+nonceSize]
	sealedDEK := wrappedDEK[1+nonceSize:]
	dek, err := s.aead.Open(nil, dekNonce, sealedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("seal: open DEK (KEK mismatch?): %w", err)
	}

	if len(data) < 1+nonceSize+gcmTag {
		return nil, errors.New("seal: data truncated")
	}
	if data[0] != sealVersion {
		return nil, fmt.Errorf("seal: unsupported data version %d", data[0])
	}
	dataAEAD, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	dataNonce := data[1 : 1+nonceSize]
	sealedData := data[1+nonceSize:]
	plaintext, err := dataAEAD.Open(nil, dataNonce, sealedData, nil)
	if err != nil {
		return nil, fmt.Errorf("seal: open data: %w", err)
	}
	return plaintext, nil
}

// gcmTag is the AES-GCM authenticator tag length (16 bytes for the
// stdlib's default). Used by Open's length sanity checks.
const gcmTag = 16

// newGCM is the AES-256-GCM constructor pulled out so Seal/Open share
// the same error-wrapping pattern.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return aead, nil
}
