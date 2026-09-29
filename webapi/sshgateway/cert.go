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

package sshgateway

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/logging"
)

// CertAuth accepts SSH certificates this deployment's CA signed.
//
// It exists for what keyboard-interactive structurally cannot do:
// BatchMode clients, which refuse the method outright, and not asking a
// human to approve every single connection. A certificate is obtained
// once through the browser and then works until it expires.
//
// What it does NOT do is accept bare public keys. A key on its own
// carries no identity and no expiry, so accepting one would mean this
// server keeping a list of which key belongs to whom -- the very
// thing a CA exists to avoid, and a list that never forgets a
// compromised key.
type CertAuth struct {
	// Authority is the CA whose signatures are accepted. Required.
	Authority ssh.PublicKey
	// Scopes are granted to a certificate-authenticated session, since
	// there is no OAuth2 grant to take them from.
	Scopes []string

	Logger *logging.Logger
}

// ErrNotACertificate is returned for a bare public key.
var ErrNotACertificate = errors.New("sshgateway: this gateway accepts certificates, not bare keys")

// Callback is the ssh.ServerConfig PublicKeyCallback.
//
// The account comes from the certificate's single valid principal, NOT
// from conn.User(): the username on this gateway names the job to
// reach, so tying the certificate to it would mean a separate
// certificate per job.
//
// That is a deliberate departure from how OpenSSH uses principals, and
// it is why the certificate must name exactly one. A certificate with
// several would leave the gateway choosing an identity, and choosing
// is the thing to never do.
func (c *CertAuth) Callback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, ErrNotACertificate
	}
	if cert.CertType != ssh.UserCert {
		return nil, errors.New("sshgateway: not a user certificate")
	}
	if len(cert.ValidPrincipals) != 1 {
		return nil, fmt.Errorf("sshgateway: a certificate must name exactly one principal, this one names %d",
			len(cert.ValidPrincipals))
	}
	account := cert.ValidPrincipals[0]
	if account == "" {
		return nil, errors.New("sshgateway: the certificate's principal is empty")
	}

	// WHICH authority signed this has to be checked here, explicitly.
	//
	// CertChecker.CheckCert verifies the certificate's signature
	// against the key embedded in the certificate -- and never asks
	// whether that key is ours. Only CertChecker.Authenticate consults
	// IsUserAuthority, and it also insists the principal match
	// conn.User(), which on this gateway is the job to reach rather
	// than a name. Calling CheckCert alone therefore accepts any
	// self-signed certificate: a complete bypass, and one that looks
	// exactly like working code.
	if c.Authority == nil {
		return nil, errors.New("sshgateway: no certificate authority configured")
	}
	if cert.SignatureKey == nil ||
		!bytes.Equal(cert.SignatureKey.Marshal(), c.Authority.Marshal()) {
		return nil, errors.New("sshgateway: certificate signed by an unrecognized authority")
	}

	// And now the rest: the signature itself, the validity window, the
	// principal, and any critical option this server does not
	// understand.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), c.Authority.Marshal())
		},
	}
	if err := checker.CheckCert(account, cert); err != nil {
		return nil, fmt.Errorf("sshgateway: %w", err)
	}

	if c.Logger != nil {
		c.Logger.Info(logging.DestinationHTTP, "SSH gateway certificate login",
			"account", account,
			"remote", conn.RemoteAddr().String(),
			"requested_target", conn.User(),
			"key_id", cert.KeyId,
			"expires", time.Unix(int64(cert.ValidBefore), 0).UTC()) //nolint:gosec // bounded by the CA that signed it
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			ExtAccount: account,
			ExtScopes:  joinScopes(c.Scopes),
			// No access token: there is no OAuth2 grant behind a
			// certificate. Anything reading ExtAccessToken has to cope
			// with it being absent.
			ExtRequestedTarget: conn.User(),
		},
	}, nil
}

func joinScopes(scopes []string) string {
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

// SignUserCertificate issues a certificate for account, valid for ttl.
//
// The caller has already proved who they are; this only decides what
// the certificate says. principals is exactly one name on purpose --
// see CertAuth.Callback.
//
// permit-pty and permit-port-forwarding are set because a terminal and
// a forwarded port are the point. Nothing else is, and in particular
// permit-agent-forwarding is left out rather than decided: this
// gateway does not enforce certificate extensions at all, so listing
// one would imply a control that does not exist.
func SignUserCertificate(ca ssh.Signer, pub ssh.PublicKey, account string, ttl time.Duration, serial uint64) (*ssh.Certificate, error) {
	if ca == nil {
		return nil, errors.New("sshgateway: no certificate authority configured")
	}
	if account == "" {
		return nil, errors.New("sshgateway: refusing to sign a certificate with no principal")
	}
	if ttl <= 0 {
		return nil, errors.New("sshgateway: a certificate needs a positive lifetime")
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("%s@htcondor-ssh-gateway", account),
		ValidPrincipals: []string{account},
		// A minute of slack for clock skew between this host and the
		// client's. Less than that and a correctly-issued certificate
		// is refused by the very gateway that signed it.
		ValidAfter:  uint64(now.Add(-1 * time.Minute).Unix()), //nolint:gosec // a unix time in this century is positive
		ValidBefore: uint64(now.Add(ttl).Unix()),              //nolint:gosec // same
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":             "",
				"permit-port-forwarding": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, fmt.Errorf("sshgateway: signing the certificate: %w", err)
	}
	return cert, nil
}
