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
	"encoding/binary"
	"encoding/json"
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
	s.writeJSON(w, http.StatusOK, sshCAResponse{
		PublicKey: authorized,
		// The wildcard is deliberate: a gateway may be reached by
		// several names, and narrowing it here would silently stop
		// working the first time somebody uses an alias.
		KnownHostsLine: "@cert-authority * " + authorized,
		Fingerprint:    ssh.FingerprintSHA256(pub),
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

	ca := s.sshCASigner
	if ca == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"This access point does not issue SSH certificates")
		return
	}

	var req sshCertRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
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
	if _, isCert := pub.(*ssh.Certificate); isCert {
		// Signing a certificate over a certificate produces something
		// nothing will accept, and the request means the caller sent
		// the wrong file.
		s.writeError(w, http.StatusBadRequest,
			"public_key is a certificate; send the public key it was issued for")
		return
	}

	lifetime := sshCertDefaultLifetime
	if req.LifetimeSeconds > 0 {
		lifetime = time.Duration(req.LifetimeSeconds) * time.Second
	}
	if lifetime > sshCertMaxLifetime {
		lifetime = sshCertMaxLifetime
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
