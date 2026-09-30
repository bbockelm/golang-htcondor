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

// Package sshkeys resolves the two long-lived keys the SSH gateway
// needs: the host key it presents to every client, and the CA key it
// signs user certificates with.
//
// Both keys have a property that shapes every decision here: once a
// client has seen them, replacing one is indistinguishable from an
// attack. A new host key trips StrictHostKeyChecking on every user at
// once, and the recovery they will learn is "delete the known_hosts
// line" -- which is a permanent loss of exactly the protection the key
// exists to provide. A new CA key invalidates every outstanding
// certificate simultaneously.
//
// So the rule throughout is: mint freely when there is nothing to
// lose, and refuse loudly the moment there is. Concretely --
//
//   - A key file configured by the operator always wins, and any
//     problem reading it is fatal. There is deliberately no fallback
//     to the database, because a fallback engages exactly when the
//     operator's intent failed to load.
//   - With no file and no sealer there is nowhere safe to keep a key,
//     so Resolve returns ErrNoKeyStore and the caller disables the
//     gateway. It must not invent an in-memory key: that changes the
//     host key on every restart and on every replica.
//   - With a sealer and no stored key, minting is correct -- nobody
//     has seen anything yet.
//   - With a stored key that cannot be opened, Resolve fails. The
//     likely cause is a swapped or missing HTTP_API_KEK_FILE, which is
//     recoverable; the trust users have already extended is not.
//
// This mirrors openOrCreateMaster's posture for the application master
// key, for the same reason.
package sshkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb/seal"
)

// Purpose names one of the gateway's two keys. The value is the
// primary key in ssh_gateway_keys, so it is part of the on-disk
// format and must not be renamed.
type Purpose string

const (
	// HostKey is presented to clients as the gateway's SSH host key.
	HostKey Purpose = "host"
	// CAKey signs user certificates.
	CAKey Purpose = "ca"
)

func (p Purpose) valid() bool { return p == HostKey || p == CAKey }

// describe is what appears in operator-facing messages.
func (p Purpose) describe() string {
	switch p {
	case HostKey:
		return "SSH gateway host key"
	case CAKey:
		return "SSH gateway certificate authority key"
	default:
		return fmt.Sprintf("SSH gateway key %q", string(p))
	}
}

// configKnob is the setting that supplies this key from a file.
func (p Purpose) configKnob() string {
	switch p {
	case HostKey:
		return "HTTP_API_SSH_HOST_KEY_FILE"
	case CAKey:
		return "HTTP_API_SSH_CA_KEY_FILE"
	default:
		return "HTTP_API_SSH_*_KEY_FILE"
	}
}

// ErrNoKeyStore means there is no configured key file and no sealer,
// so this deployment has nowhere to keep a stable key. Callers should
// treat it as "the gateway is unavailable", not as a reason to
// generate something ephemeral.
var ErrNoKeyStore = errors.New("sshkeys: no key file configured and no database encryption available")

// Options carries everything Resolve needs. DB and Sealer may be nil,
// in which case only the file paths can satisfy a call.
type Options struct {
	DB     *sql.DB
	Sealer *seal.Sealer
	Logger *logging.Logger

	// HostKeyFile and CAKeyFile are paths to OpenSSH-format private
	// keys. Empty means "use the database".
	//
	// There is no environment variable carrying the key bytes
	// themselves, on purpose: the environment of a process is
	// readable through /proc/<pid>/environ and lands in crash dumps,
	// while a projected secret volume does not.
	HostKeyFile string
	CAKeyFile   string
}

func (o Options) fileFor(p Purpose) string {
	switch p {
	case HostKey:
		return strings.TrimSpace(o.HostKeyFile)
	case CAKey:
		return strings.TrimSpace(o.CAKeyFile)
	default:
		return ""
	}
}

func (o Options) log() *logging.Logger { return o.Logger }

// Key is a resolved signer plus the things an operator needs to see.
type Key struct {
	Purpose Purpose
	Signer  ssh.Signer

	// Source is human-readable provenance for the startup log:
	// "file /etc/secrets/ssh_host_key" or "application database".
	Source string

	// Fingerprint is the SHA256 form ssh-keygen -l prints.
	Fingerprint string

	// Authorized is the authorized_keys line for the public half.
	Authorized string
}

func newKey(p Purpose, signer ssh.Signer, source string) *Key {
	pub := signer.PublicKey()
	return &Key{
		Purpose:     p,
		Signer:      signer,
		Source:      source,
		Fingerprint: ssh.FingerprintSHA256(pub),
		Authorized:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
	}
}

// Resolve returns the key for p, from the configured file if there is
// one and from the database otherwise, minting and sealing a fresh key
// on first use. See the package documentation for the failure
// semantics, which are the substance of this function.
func Resolve(ctx context.Context, p Purpose, o Options) (*Key, error) {
	if !p.valid() {
		return nil, fmt.Errorf("sshkeys: unknown purpose %q", string(p))
	}

	if path := o.fileFor(p); path != "" {
		key, err := loadFromFile(p, path)
		if err != nil {
			// Deliberately no fallback to the database. An operator
			// who configured a file meant that key; falling back
			// would substitute a different one at precisely the
			// moment their intent failed to load, and the
			// substitution is invisible to everything except the
			// clients it breaks.
			return nil, err
		}
		o.warnIfShadowed(ctx, p, key)
		return key, nil
	}

	if o.DB == nil || o.Sealer == nil {
		return nil, fmt.Errorf(
			"%s is unavailable: set %s to a private key staged by your secrets mechanism, "+
				"or configure HTTP_API_KEK_FILE so the key can be generated and stored sealed in the "+
				"application database: %w",
			p.describe(), p.configKnob(), ErrNoKeyStore)
	}

	key, err := o.loadFromDB(ctx, p)
	if err == nil {
		return key, nil
	}
	// Only "there is no key yet" may proceed to minting. Anything else
	// -- above all a row that will not decrypt -- stops here.
	//
	// mint's own INSERT ... ON CONFLICT DO NOTHING would also refuse to
	// overwrite the row if this check were removed, so the two are
	// redundant today. They are both kept deliberately: the day that
	// insert becomes an upsert, this is what still stands between a
	// misconfigured KEK and a silently replaced host key.
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return o.mint(ctx, p)
}

// loadFromFile reads an OpenSSH private key from path.
//
// The permission posture matches seal.LoadMasterKEKFromFile, and for
// the same reasons: opened through droppriv because the HTCondor
// convention for a credential is root-owned while the daemon runs as
// condor, and group bits tolerated because kubelet's fsGroup turns a
// 0400 mounted secret into 0440. World-readable is always wrong.
func loadFromFile(p Purpose, path string) (*Key, error) {
	f, err := droppriv.OpenMaybeAsRoot(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf(
			"%s: %s points at %s, which does not exist. This file is never created for you -- "+
				"generate it out of band with `ssh-keygen -t ed25519 -N '' -f %s` and stage it "+
				"through your secrets mechanism on a path that survives restarts",
			p.describe(), p.configKnob(), path, path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.describe(), err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", p.describe(), path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s: %s is a directory", p.describe(), path)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		return nil, fmt.Errorf(
			"%s: %s is world-accessible (mode %#o); it must have no other-bits set "+
				"(typical: 0600, 0400, or 0440 for a kubelet fsGroup mount)",
			p.describe(), path, perm)
	}

	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("%s: reading %s: %w", p.describe(), path, err)
	}

	signer, err := ssh.ParsePrivateKey(raw)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, fmt.Errorf(
			"%s: %s is protected by a passphrase, which cannot be supplied to an unattended daemon. "+
				"Stage an unencrypted key (`ssh-keygen -p -N '' -f %s` removes the passphrase) and rely "+
				"on file permissions and your secrets mechanism instead",
			p.describe(), path, path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: parsing %s: %w", p.describe(), path, err)
	}
	return newKey(p, signer, "file "+path), nil
}

// warnIfShadowed reports a stored key that a configured file is now
// overriding.
//
// Swapping which key the gateway presents has the same blast radius as
// losing one, and is otherwise completely silent -- the server starts
// normally and every user's client reports a changed host key at once.
// Naming both fingerprints at startup is what turns that into a
// five-second diagnosis.
func (o Options) warnIfShadowed(ctx context.Context, p Purpose, inUse *Key) {
	if o.DB == nil || o.log() == nil {
		return
	}
	var stored string
	err := o.DB.QueryRowContext(ctx,
		`SELECT fingerprint FROM ssh_gateway_keys WHERE purpose = ?`, string(p)).Scan(&stored)
	if err != nil || stored == "" || stored == inUse.Fingerprint {
		return
	}
	o.log().Warn(logging.DestinationHTTP,
		"A stored "+p.describe()+" is being overridden by the configured key file; "+
			"clients that connected before this change will report a changed key",
		"purpose", string(p),
		"in_use", inUse.Fingerprint,
		"in_use_source", inUse.Source,
		"stored", stored,
		"knob", p.configKnob())
}

// loadFromDB returns the sealed key stored for p, or sql.ErrNoRows.
//
// An unopenable row is an error and never a reason to mint: see the
// package documentation.
func (o Options) loadFromDB(ctx context.Context, p Purpose) (*Key, error) {
	var sealed, dek []byte
	err := o.DB.QueryRowContext(ctx,
		`SELECT private_key, private_key_dek FROM ssh_gateway_keys WHERE purpose = ?`,
		string(p)).Scan(&sealed, &dek)
	if err != nil {
		// sql.ErrNoRows passes through unwrapped; Resolve tests for it.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("%s: reading the stored key: %w", p.describe(), err)
	}

	raw, err := o.Sealer.Open(sealed, dek)
	if err != nil {
		return nil, fmt.Errorf(
			"%s: the stored key cannot be decrypted, most likely because HTTP_API_KEK_FILE no longer "+
				"holds the key it was sealed under. Refusing to generate a replacement: a new key "+
				"presents as a man-in-the-middle to every client that has already connected. Restore "+
				"the original KEK file, or point %s at the key you want served: %w",
			p.describe(), p.configKnob(), err)
	}
	defer zero(raw)

	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: the stored key decrypted but does not parse: %w", p.describe(), err)
	}
	return newKey(p, signer, "application database"), nil
}

// mint generates a fresh key, seals it and stores it.
//
// The insert is conditional and the result is read back rather than
// returned directly: two processes sharing a database must converge on
// one key, and the loser of that race has to serve the winner's key
// rather than its own. Returning the locally generated signer would
// give two replicas two host keys, which is the failure this whole
// package exists to prevent.
func (o Options) mint(ctx context.Context, p Purpose) (*Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%s: generating a key: %w", p.describe(), err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "htcondor-api "+string(p))
	if err != nil {
		return nil, fmt.Errorf("%s: encoding the generated key: %w", p.describe(), err)
	}
	raw := pem.EncodeToMemory(block)
	defer zero(raw)

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%s: preparing the generated key: %w", p.describe(), err)
	}
	fresh := newKey(p, signer, "application database")

	sealed, dek, err := o.Sealer.Seal(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: sealing the generated key: %w", p.describe(), err)
	}

	// DO NOTHING, never an upsert. This statement must not be able to
	// replace an existing key: it is the second of the two guards
	// described in Resolve, and the one that holds when two processes
	// reach here at once.
	if _, err := o.DB.ExecContext(ctx,
		`INSERT INTO ssh_gateway_keys
		   (purpose, private_key, private_key_dek, public_key, fingerprint, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(purpose) DO NOTHING`,
		string(p), sealed, dek, fresh.Authorized, fresh.Fingerprint, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("%s: storing the generated key: %w", p.describe(), err)
	}

	stored, err := o.loadFromDB(ctx, p)
	if err != nil {
		return nil, err
	}
	if o.log() != nil && stored.Fingerprint == fresh.Fingerprint {
		o.log().Info(logging.DestinationHTTP,
			"Generated and stored a new "+p.describe(),
			"purpose", string(p),
			"fingerprint", stored.Fingerprint)
	}
	return stored, nil
}

// zero overwrites b. Private-key material should not outlive its use
// in a heap that may be dumped.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
