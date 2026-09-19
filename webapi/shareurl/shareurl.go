// Package shareurl mints and verifies the short-lived signed URLs that
// let a caller act on one job without an authenticated session:
// downloading its output sandbox, or uploading its input into the
// spool. Possession of the URL is the authorization.
//
// The signing lives here, rather than inside the HTTP server, because
// two processes need it. htcondor-api serves the redeem endpoints, but
// htcondor-mcp runs standalone over stdio with no HTTP listener of its
// own -- it still has to hand an agent a URL that the REST daemon will
// honor. Both derive the same key from the same pool signing key file
// (see KeyFromSigningKeyFile), so a token minted by one verifies in the
// other.
package shareurl

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/droppriv"
	"golang.org/x/crypto/hkdf"
)

// Kind names what a token authorizes. A token is valid for exactly one
// of these: an upload URL that could be redeemed as a download (or the
// reverse) would silently widen what possession of it grants.
type Kind string

const (
	// KindOutput authorizes downloading a job's sandbox. Its wire value
	// is empty on purpose: tokens minted before this field existed carry
	// no "k" at all, and they are output tokens.
	KindOutput Kind = ""
	// KindInput authorizes uploading input files into a job's spool.
	KindInput Kind = "input"
)

// Lifetimes. Downloads default short -- the URL is meant for "drop this
// in chat so a colleague can grab the output", not long-term sharing.
//
// Uploads get a longer window for two reasons. The URL is minted before
// the file moves, so it has to survive sitting in somebody's inbox until
// they get to it, and the upload itself can be a slow multi-gigabyte PUT.
// Widening it costs little here because expiry is not what protects a
// spool upload: the job must still be held awaiting input, which stops
// being true the moment the spool completes (see InputHoldCode's use in
// the redeem path). The token goes inert on its own.
const (
	DefaultOutputTTL = 10 * time.Minute
	MaxOutputTTL     = 1 * time.Hour
	DefaultInputTTL  = 1 * time.Hour
	MaxInputTTL      = 24 * time.Hour
)

// Defaults returns the default and maximum lifetime for a kind.
func Defaults(k Kind) (def, max time.Duration) {
	if k == KindInput {
		return DefaultInputTTL, MaxInputTTL
	}
	return DefaultOutputTTL, MaxOutputTTL
}

// ClampTTL applies the kind's policy to a requested lifetime. A
// non-positive request means "use the default".
func ClampTTL(k Kind, requested time.Duration) time.Duration {
	def, max := Defaults(k)
	if requested <= 0 {
		return def
	}
	if requested > max {
		return max
	}
	return requested
}

// Payload is the data carried inside a signed token. It is kept tight:
// anything richer (a per-share revocation list, say) would need
// persistent state, which these ephemeral URLs deliberately avoid.
//
// The field tags are load-bearing -- they are the wire format of tokens
// already in circulation, so they keep their original one-letter
// spellings.
type Payload struct {
	Cluster int    `json:"c"`
	Proc    int    `json:"p"`
	Owner   string `json:"o"`
	Exp     int64  `json:"e"`
	Kind    Kind   `json:"k,omitempty"`
}

// Expired reports whether the payload's expiry has passed.
func (p Payload) Expired(now time.Time) bool { return now.Unix() > p.Exp }

// JobID renders the payload's target as HTCondor spells it.
func (p Payload) JobID() string { return fmt.Sprintf("%d.%d", p.Cluster, p.Proc) }

// Signer signs and verifies tokens with one key.
type Signer struct{ key []byte }

// NewSigner returns a Signer over key. A short or empty key is
// rejected rather than producing tokens nobody should trust.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("share URL key must be at least 16 bytes, got %d", len(key))
	}
	return &Signer{key: key}, nil
}

// hkdfInfo separates this key from every other thing derived from the
// same pool signing key (IDTOKENs, the MCP access JWT). Changing the
// string invalidates every outstanding URL, which is why it carries a
// version.
const hkdfInfo = "htcondor-api share-url v1"

// KeyFromSigningKeyFile derives the share-URL key from a pool signing
// key on disk. Deterministic by design: every process that can read the
// same key file arrives at the same share key, so URLs minted by a
// standalone MCP server verify in the REST daemon, and neither one's
// restart invalidates URLs already handed out.
//
// The read goes through droppriv because a pool signing key is
// root-owned mode-0600 and these daemons run privilege-dropped;
// OpenAsRoot degrades to an ordinary read where that does not apply.
func KeyFromSigningKeyFile(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("no signing key configured")
	}
	f, err := droppriv.OpenAsRoot(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open signing key %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing key %s: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("signing key %s is empty", path)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, raw, nil, []byte(hkdfInfo)), key); err != nil {
		return nil, fmt.Errorf("failed to derive share key: %w", err)
	}
	return key, nil
}

// Sign produces a URL-safe token of the form base64(payload).base64(hmac).
// The HMAC is over the base64 payload bytes so a verifier can reject a
// forgery without JSON-parsing anything an attacker chose.
func (s *Signer) Sign(p Payload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(enc))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return enc + "." + sig, nil
}

// Verify parses, authenticates, expiry-checks, and kind-checks a token,
// returning the payload only when every check passes.
//
// Callers must not report which check failed: the difference between
// "bad signature" and "expired" tells a prober whether it has a real
// token, and the difference between kinds maps out what else exists.
func (s *Signer) Verify(tok string, want Kind) (*Payload, error) {
	dot := strings.IndexByte(tok, '.')
	if dot <= 0 || dot == len(tok)-1 {
		return nil, fmt.Errorf("malformed token")
	}
	encPayload, encSig := tok[:dot], tok[dot+1:]

	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(encPayload))
	expectSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectSig), []byte(encSig)) {
		return nil, fmt.Errorf("invalid signature")
	}

	raw, err := base64.RawURLEncoding.DecodeString(encPayload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}
	if p.Kind != want {
		return nil, fmt.Errorf("token is not valid for this operation")
	}
	if p.Expired(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}
	if p.Owner == "" {
		return nil, fmt.Errorf("token names no owner")
	}
	return &p, nil
}
