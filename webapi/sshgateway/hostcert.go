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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// hostCertLifetime is how long a self-issued host certificate lasts.
//
// Ten years, which is longer than anything else this package signs and
// deliberately so. Expiry is a control over a credential somebody else
// holds; nobody holds this one. The host key and the CA that signs it
// live in the same process, sealed by the same KEK, so a theft that
// gets one gets both and a shorter lifetime buys nothing against it.
//
// What a shorter lifetime would reliably buy is an outage: a daemon
// that has been up for longer than the certificate stops being
// verifiable by every client at once, at whatever hour it happens. The
// certificate is reissued on every start, so ten years is really "no
// expiry, with a backstop if this code is still running in 2036".
const hostCertLifetime = 10 * 365 * 24 * time.Hour

// NewHostCertSigner wraps a host key in a certificate signed by the
// gateway's own CA, so clients can verify the gateway from the CA alone.
//
// Without this the gateway presents a bare host key, and the
// `@cert-authority * <ca>` line the CA endpoint publishes does nothing
// for it: @cert-authority tells ssh to trust host CERTIFICATES signed
// by that key, and there was no certificate to trust. Users following
// the documented setup still got an unverified-host prompt -- which,
// under a client like VS Code's Remote-SSH that shows the prompt
// nowhere useful, reads as a connection that hangs for no reason.
//
// principals are the names the certificate is good for. EMPTY means
// every name, which is what OpenSSH does with a host certificate that
// lists none, and is the right default here because this process does
// not know the names it is reached by: it binds `:2222` and is fronted
// by whatever the operator put in front of it. An operator who does
// know can narrow it.
func NewHostCertSigner(host, ca ssh.Signer, principals []string, now time.Time) (ssh.Signer, error) {
	if host == nil {
		return nil, errors.New("sshgateway: no host key to certify")
	}
	if ca == nil {
		return nil, errors.New("sshgateway: no certificate authority configured")
	}

	serial, err := hostCertSerial()
	if err != nil {
		return nil, fmt.Errorf("sshgateway: generating a serial: %w", err)
	}

	cert := &ssh.Certificate{
		Key:             host.PublicKey(),
		Serial:          serial,
		CertType:        ssh.HostCert,
		KeyId:           "htcondor-ssh-gateway",
		ValidPrincipals: principals,
		// The same minute of slack as a user certificate, for the same
		// reason: a client whose clock is a little behind ours should
		// not be told the host is not yet valid.
		ValidAfter:  uint64(now.Add(-1 * time.Minute).Unix()), //nolint:gosec // a unix time in this century is positive
		ValidBefore: uint64(now.Add(hostCertLifetime).Unix()), //nolint:gosec // same
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, fmt.Errorf("sshgateway: signing the host certificate: %w", err)
	}

	signer, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		return nil, fmt.Errorf("sshgateway: building the host certificate signer: %w", err)
	}
	return signer, nil
}

// hostCertSerial returns a random serial. Random rather than counted
// for the same reason the user certificates are: a counter needs
// durable state to stay unique across restarts, and the serial only
// ever correlates a log line with a certificate somebody is holding.
func hostCertSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// KnownHostsLine is the line a client adds so this gateway verifies
// from the CA alone.
//
// The pattern is the operator's host names when they configured any,
// and `*` otherwise. `*` is broad -- it says "trust this CA for any
// host" -- but it is also the only thing that works when the server
// does not know its own names, and narrowing it silently would break
// the first person who reaches the gateway by an alias.
func KnownHostsLine(ca ssh.PublicKey, hostNames []string) string {
	authority := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca)))
	pattern := "*"
	if len(hostNames) > 0 {
		pattern = strings.Join(hostNames, ",")
	}
	return fmt.Sprintf("@cert-authority %s %s", pattern, authority)
}
