// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/sshgateway"
)

// Certificate lifetimes.
//
// Twelve hours is a working day: long enough not to interrupt, short
// enough to be the only revocation this has. There is no CRL and no
// OCSP -- a certificate cannot be withdrawn once issued, so its
// lifetime IS the control, and that is the reason not to make it
// generous.
const (
	sshCertDefaultLifetime = 12 * time.Hour
	sshCertMaxLifetime     = 24 * time.Hour
)

// sshCAResponse describes the certificate authority to a client.
type sshCAResponse struct {
	// PublicKey is the authorized_keys form.
	PublicKey string `json:"public_key"`
	// KnownHostsLine is what to add to known_hosts so this client
	// trusts the gateway's host key without pinning it by hand.
	KnownHostsLine string `json:"known_hosts_line"`
	// Fingerprint is for comparing against what an operator published.
	Fingerprint string `json:"fingerprint"`

	// GatewayHost and GatewayPort say where to ssh, when the operator
	// configured HTTP_API_SSH_GATEWAY_HOST.
	//
	// Published so a client needs no configuration of its own. This
	// server already knows the name -- it is the host certificate's
	// principal and the pattern in KnownHostsLine -- and until now kept
	// it to itself, which left every client asking a human where the
	// gateway is. Omitted rather than guessed when unset: the listen
	// address is not the answer, since a container on :2222 sits behind
	// a service publishing 22 somewhere else.
	GatewayHost string `json:"gateway_host,omitempty"`
	GatewayPort int    `json:"gateway_port,omitempty"`
}

type sshCertRequest struct {
	// PublicKey is an authorized_keys line: the half that stays on the
	// caller's machine is never sent here.
	PublicKey string `json:"public_key"`
	// LifetimeSeconds may ask for LESS than the default. More is
	// clamped rather than refused, because a client asking for a week
	// wants a certificate, not an error.
	LifetimeSeconds int `json:"lifetime_seconds,omitempty"`
}

type sshCertResponse struct {
	// Certificate is the line to save as <key>-cert.pub, which ssh
	// picks up beside the private key on its own.
	Certificate string    `json:"certificate"`
	Principal   string    `json:"principal"`
	ValidBefore time.Time `json:"valid_before"`
	Fingerprint string    `json:"fingerprint"`
}

// handleSSHCA publishes the gateway's certificate authority.
//
// Public information by nature -- it is the key that verifies
// signatures, not one that makes them -- but still behind
// authentication, because the only reason to want it is to use this
// gateway.
func (s *Handler) handleSSHCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if _, _, err := s.requireAuthentication(r); err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	ca := s.sshCASigner
	if ca == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"This access point does not issue SSH certificates")
		return
	}

	pub := ca.PublicKey()
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	gatewayHost, gatewayPort := sshgateway.ParseGatewayAddress(s.sshGatewayPublicHost)
	s.writeJSON(w, http.StatusOK, sshCAResponse{
		PublicKey: authorized,
		// Narrowed to the operator's configured names when there are
		// any, which confines what this CA is trusted to vouch for on
		// the client. A wildcard otherwise: narrowing on a guess would
		// silently stop working the first time somebody uses an alias.
		KnownHostsLine: sshgateway.KnownHostsLine(pub, sshgateway.ParseHostNames(s.sshGatewayPublicHost)),
		Fingerprint:    ssh.FingerprintSHA256(pub),
		GatewayHost:    gatewayHost,
		GatewayPort:    gatewayPort,
	})
}

// handleSSHCertificate signs a certificate for the caller.
//
// This is an identity-only endpoint: nothing downstream re-checks who
// asked, so the name it signs has to be one the schedd has vouched
// for. createAuthenticatedContext resolves it through the token cache
// or by asking the schedd, and leaves it EMPTY when it could not --
// which is why an empty name is refused here rather than treated as
// anonymous.
func (s *Handler) handleSSHCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, _, err := s.requireAuthentication(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	account := ownerFromActor(htcondor.GetAuthenticatedUserFromContext(ctx))
	if account == "" {
		// Fail closed. A certificate names an account; issuing one
		// without knowing the account is issuing it to anybody.
		s.writeError(w, http.StatusForbidden,
			"Your account could not be established, so no certificate can be issued")
		return
	}

	// A certificate buys sshGatewayScopes -- condor:/WRITE and a shell.
	// A caller holding less than that must not be able to trade up.
	//
	// The distinction that matters is scoped versus unscoped, not
	// present versus absent: an API key minted for HTTP-only scopes,
	// or a grant the user approved for condor:/READ, is a deliberate
	// restriction and issuing over it is an escalation. A browser
	// session carries no scopes at all because that route has no scope
	// model -- refusing those would refuse every human who came to
	// enroll.
	// `scoped` is false for a credential carrying NO scopes at all, so
	// the API-key marker is checked too. Without it a zero-scope key
	// slips past this gate entirely, arrives at the schedd with no
	// credential of its own, and GetSecurityConfigOrDefault falls back
	// to this daemon's configuration -- a queue superuser on a normal
	// access point. That is the same shape as the three gaps closed in
	// "close three authorization gaps on routes that reach HTCondor".
	if scopes, scoped := scopedCredential(ctx); scoped || AuthenticatedViaAPIKey(ctx) {
		if _, ok := scopes[sshCertRequiredScope]; !ok {
			s.logger.Info(logging.DestinationHTTP,
				"Refused an SSH certificate to an under-scoped credential",
				"account", account, "required", sshCertRequiredScope)
			s.writeError(w, http.StatusForbidden,
				"This credential is not authorized for "+sshCertRequiredScope+
					", which is what an SSH certificate grants")
			return
		}
	}

	ca := s.sshCASigner
	if ca == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"This access point does not issue SSH certificates")
		return
	}

	var req sshCertRequest
	setBodyLimit(w, r, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Could not read the request body")
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(req.PublicKey)))
	if err != nil {
		s.writeError(w, http.StatusBadRequest,
			"public_key must be one line of authorized_keys, as in `ssh-ed25519 AAAA...`")
		return
	}
	if err := acceptableUserKey(pub); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		// Signing a certificate over a certificate produces something
		// nothing will accept, and the request means the caller sent
		// the wrong file.
		s.writeError(w, http.StatusBadRequest,
			"public_key is a certificate; send the public key it was issued for")
		return
	}

	// Clamped in SECONDS, before the multiply. time.Duration is
	// nanoseconds, so a large lifetime_seconds wraps -- and a wrapped
	// negative slips past a `> max` check entirely.
	lifetime := sshCertDefaultLifetime
	if req.LifetimeSeconds > 0 {
		secs := req.LifetimeSeconds
		if capSecs := int(sshCertMaxLifetime / time.Second); secs > capSecs {
			secs = capSecs
		}
		lifetime = time.Duration(secs) * time.Second
	}

	serial, err := sshCertSerial()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not issue a certificate")
		return
	}

	cert, err := sshgateway.SignUserCertificate(ca, pub, account, lifetime, serial)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Signing an SSH certificate failed",
			"account", account, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not issue a certificate")
		return
	}

	s.logger.Info(logging.DestinationHTTP, "Issued an SSH certificate",
		"account", account, "serial", serial,
		"lifetime_seconds", int(lifetime.Seconds()),
		"key_fingerprint", ssh.FingerprintSHA256(pub))

	s.writeJSON(w, http.StatusOK, sshCertResponse{
		Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		Principal:   account,
		ValidBefore: time.Unix(int64(cert.ValidBefore), 0).UTC(), //nolint:gosec // set from a unix time moments ago
		Fingerprint: ssh.FingerprintSHA256(pub),
	})
}

// sshCertRequiredScope is what a certificate ends up granting, and so
// what a caller must already hold to be given one.
const sshCertRequiredScope = "condor:/WRITE"

// acceptableUserKey refuses key types a certificate should not be
// issued over.
//
// A certificate is public and long-lived, so a weak key under one is a
// third-party-forgeable credential for that account rather than merely
// the holder's own problem. ssh-dss is 1024-bit by construction and
// deprecated; RSA below 3072 is too short to sign a credential that
// names an account.
func acceptableUserKey(pub ssh.PublicKey) error {
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256:
		return nil
	case ssh.KeyAlgoRSA:
		ck, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("public_key: this RSA key cannot be inspected")
		}
		rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return errors.New("public_key: this RSA key cannot be inspected")
		}
		if rk.N.BitLen() < minRSABits {
			return fmt.Errorf("public_key: RSA keys must be at least %d bits, this one is %d",
				minRSABits, rk.N.BitLen())
		}
		return nil
	default:
		return fmt.Errorf("public_key: %s keys are not accepted; use ed25519, ecdsa, or RSA of at least %d bits",
			pub.Type(), minRSABits)
	}
}

// minRSABits is the floor for an RSA key a certificate is issued over.
const minRSABits = 3072

// sshCertSerial returns a random serial.
//
// Random rather than counted: a counter needs durable state to stay
// unique across restarts, and the serial is only ever used to
// correlate a log line with a certificate somebody is holding.
func sshCertSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}
