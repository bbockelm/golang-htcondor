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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"net"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"

	"github.com/bbockelm/golang-htcondor/webapi/sshgateway"
)

// The SecurityTag is the whole reason withCondorCredential exists as
// one shared function. cedar's client session cache is keyed
// {SecurityTag, address, command}; with an empty tag every caller
// talking to the same schedd shares one entry, so one user's request
// resumes a session another user authenticated and runs as them.
//
// A second copy of this code would be free to forget it, and nothing
// in a single-user test would notice.
func TestCondorCredentialIsTaggedPerCaller(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	h := &Handler{
		signingKeyPath: keyPath,
		trustDomain:    "test.htcondor.org",
		uidDomain:      "test.htcondor.org",
		logger:         testLogger(t),
	}

	ctxA, err := h.withCondorCredential(context.Background(), "alice", []string{"condor:/WRITE"})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	ctxB, err := h.withCondorCredential(context.Background(), "bob", []string{"condor:/WRITE"})
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	secA, okA := htcondor.GetSecurityConfigFromContext(ctxA)
	secB, okB := htcondor.GetSecurityConfigFromContext(ctxB)
	if !okA || !okB {
		t.Fatal("no security config was attached")
	}
	if secA.SecurityTag == "" {
		t.Fatal("the security tag is empty; every caller would share one cedar session")
	}
	if secA.SecurityTag == secB.SecurityTag {
		t.Errorf("alice and bob share the security tag %q", secA.SecurityTag)
	}
}

// With nothing to mint from, the context comes back usable and
// uncredentialed rather than erroring: the schedd decides what an
// unauthenticated caller may do, and that is not this function's call.
// With nothing to mint from, there is nothing safe to return.
//
// This used to assert the opposite -- that a caller got a context and no
// error -- on the reasoning that the schedd would then decide what an
// unauthenticated connection may do. It does not. A context with no
// credential is not unauthenticated downstream, it is THIS DAEMON, so the
// old behaviour handed a caller whose credential could not be minted more
// authority than one whose could.
func TestCondorCredentialWithoutASigningKey(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	_, err := h.withCondorCredential(context.Background(), "alice", nil)
	if err == nil {
		t.Fatal("a caller with no mintable credential was handed a context anyway")
	}
	if !strings.Contains(err.Error(), "HTTP_API_SIGNING_KEY") {
		t.Errorf("the refusal does not say what to configure: %v", err)
	}
}

func TestSSHGatewayResolvesJobIDs(t *testing.T) {
	h := &Handler{}
	key, err := h.sshGatewayResolve(context.Background(), "bbockelm", sshgateway.Target{Cluster: 12345, Proc: 7}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if key.Owner != "bbockelm" || key.Cluster != 12345 || key.Proc != 7 {
		t.Errorf("key = %+v", key)
	}
}

// The owner on the key comes from the OAuth2 grant, never from the SSH
// username -- which is the target selector and is attacker-chosen.
func TestSSHGatewayKeyOwnerIsTheAccount(t *testing.T) {
	h := &Handler{}
	key, err := h.sshGatewayResolve(context.Background(), "alice",
		sshgateway.Target{Raw: "bob", Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if key.Owner != "alice" {
		t.Errorf("owner = %q, want the authenticated account", key.Owner)
	}
}

// Any username that is not a job id is a session name, so a server
// with no session manager has to say so in terms the person at the
// terminal can act on -- they typed their own login and got here
// without asking for anything.
func TestSSHGatewaySessionWithoutAManagerIsExplained(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	_, err := h.sshGatewayResolve(context.Background(), "bbockelm", sshgateway.Target{Name: "work"}, nil)
	if err == nil {
		t.Fatal("a session resolved with no manager")
	}
	if !strings.Contains(err.Error(), "work") {
		t.Errorf("the error does not name the session asked for: %v", err)
	}
	if !strings.Contains(err.Error(), "12345.0") {
		t.Errorf("the error does not show the form that would work: %v", err)
	}
}

// A held job never runs, so waiting out the timeout tells the caller
// nothing they can use. The hold reason is what they need.
func TestSSHGatewayHeldSessionReportsTheHoldReason(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	_, err := h.sshGatewayAwaitRunning(context.Background(), nil,
		interactive.Caller{Actor: "bbockelm", Owner: "bbockelm"}, "work",
		interactive.Info{
			Name: "work", JobID: "12345.0", ClusterID: 12345,
			JobStatus: 5, Status: "Held", HoldReason: "no matching machines",
		}, nil)
	if err == nil {
		t.Fatal("a held session resolved")
	}
	if !strings.Contains(err.Error(), "no matching machines") {
		t.Errorf("the hold reason is missing: %v", err)
	}
}

// A running session resolves straight through, without a schedd round
// trip -- which is also what makes the held case above reachable with a
// nil manager.
func TestSSHGatewayRunningSessionResolves(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	key, err := h.sshGatewayAwaitRunning(context.Background(), nil,
		interactive.Caller{Actor: "bbockelm", Owner: "bbockelm"}, "work",
		interactive.Info{Name: "work", JobID: "77.3", ClusterID: 77, ProcID: 3, JobStatus: 2}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if key.Owner != "bbockelm" || key.Cluster != 77 || key.Proc != 3 {
		t.Errorf("key = %+v", key)
	}
}

// Setting the address is an explicit request for a listener. Starting
// without the OAuth2 provider it authenticates against must fail
// loudly, not leave a port that quietly is not there.
func TestSSHGatewayWithoutOAuth2IsAStartupError(t *testing.T) {
	h := &Handler{sshGatewayAddress: "127.0.0.1:0", logger: testLogger(t)}
	err := h.startSSHGateway(context.Background(), "https://ap.example.edu")
	if err == nil {
		t.Fatal("the gateway started with no OAuth2 provider")
	}
	if !strings.Contains(err.Error(), "HTTP_API_SSH_GATEWAY_ADDRESS") {
		t.Errorf("the error does not name the knob to unset: %v", err)
	}
}

func TestSSHGatewayUnconfiguredIsNotAnError(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	if err := h.startSSHGateway(context.Background(), "https://ap.example.edu"); err != nil {
		t.Fatalf("an unconfigured gateway errored: %v", err)
	}
	if h.sshGateway != nil {
		t.Error("a listener was created for an unconfigured gateway")
	}
}

func TestSSHGatewayPromptName(t *testing.T) {
	h := &Handler{}
	if got := h.sshGatewayPromptName("https://ap2001.chtc.wisc.edu:9618/x"); got != "ap2001.chtc.wisc.edu:9618" {
		t.Errorf("prompt = %q", got)
	}
}

// The gateway must not start without the config it needs to mint a
// per-caller HTCondor credential.
//
// This is the failure that looks safe and is not. withCondorCredential
// returns the context unchanged when there is nothing to mint with,
// and a context carrying no security config does NOT fail closed
// downstream -- GetSecurityConfigOrDefault falls through to this
// daemon's own configuration. Every session would then reach the
// schedd as the daemon, which on a normal access point is a queue
// superuser: any authenticated user could shell into anybody's job.
func TestSSHGatewayRefusesToStartWithoutSigningConfig(t *testing.T) {
	for _, tc := range []struct {
		name        string
		signingKey  string
		trustDomain string
	}{
		{"no signing key", "", "test.htcondor.org"},
		{"no trust domain", "/tmp/key", ""},
		{"neither", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{
				sshGatewayAddress: "127.0.0.1:0",
				signingKeyPath:    tc.signingKey,
				trustDomain:       tc.trustDomain,
				oauth2Provider:    &OAuth2Provider{},
				logger:            testLogger(t),
			}
			err := h.startSSHGateway(context.Background(), "https://ap.example.edu")
			if err == nil {
				t.Fatal("the gateway started with no way to mint a caller credential")
			}
			if !strings.Contains(err.Error(), "HTTP_API_SIGNING_KEY") {
				t.Errorf("the error does not name what to set: %v", err)
			}
		})
	}
}

// And if one is ever asked for anyway, it is refused rather than
// silently running as the daemon.
func TestSSHGatewayCredentialRefusesWhenNothingCanBeMinted(t *testing.T) {
	h := &Handler{logger: testLogger(t)} // no signing key: nothing to mint with

	_, err := h.sshGatewayCredential(context.Background(), "alice", []string{"condor:/WRITE"})
	if err == nil {
		t.Fatal("a channel with no mintable credential was allowed to proceed")
	}
	// The refusal now comes from withCondorCredential, one layer in, so
	// it names the missing setting rather than the account. Either is a
	// usable diagnostic; what must not happen is the channel proceeding.
	if !strings.Contains(err.Error(), "HTTP_API_SIGNING_KEY") {
		t.Errorf("the error does not say what to configure: %v", err)
	}
}

// An empty account never reaches a credential.
func TestSSHGatewayCredentialRefusesAnEmptyAccount(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	if _, err := h.sshGatewayCredential(context.Background(), "", nil); err == nil {
		t.Fatal("a credential was minted for nobody")
	}
}

func TestSSHGatewayLockoutIsOnByDefault(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	bans, err := h.sshGatewayBanlist()
	if err != nil {
		t.Fatalf("building the lockout list: %v", err)
	}
	// A zero config is the enabled default: a public SSH port with no
	// lockout is not a reasonable thing to ship, so nothing has to be
	// set for one to exist.
	if bans == nil {
		t.Fatal("no lockout list for a default configuration")
	}
}

func TestSSHGatewayLockoutCanBeTurnedOff(t *testing.T) {
	h := &Handler{
		logger:            testLogger(t),
		sshGatewayLockout: SSHGatewayLockoutConfig{Disabled: true},
	}
	bans, err := h.sshGatewayBanlist()
	if err != nil {
		t.Fatalf("building the lockout list: %v", err)
	}
	if bans != nil {
		t.Fatal("the lockout list was built although it is disabled")
	}
}

// A typo in the trusted list must stop startup. It is the setting that
// exists so an operator cannot lock themselves out of their own
// gateway, and one that is silently ignored leaves them believing they
// are covered when they are not.
func TestSSHGatewayLockoutRejectsABadTrustedNetwork(t *testing.T) {
	h := &Handler{
		logger: testLogger(t),
		sshGatewayLockout: SSHGatewayLockoutConfig{
			TrustedNetworks: []string{"192.0.2.0/24", "192.0.2.oops"},
		},
	}
	if _, err := h.sshGatewayBanlist(); err == nil {
		t.Fatal("a malformed trusted network was accepted")
	}
}

func TestSSHGatewayLockoutHonoursItsSettings(t *testing.T) {
	h := &Handler{
		logger: testLogger(t),
		sshGatewayLockout: SSHGatewayLockoutConfig{
			Threshold:       2,
			TrustedNetworks: []string{"192.0.2.0/24"},
		},
	}
	bans, err := h.sshGatewayBanlist()
	if err != nil {
		t.Fatalf("building the lockout list: %v", err)
	}

	stranger := &net.TCPAddr{IP: net.ParseIP("198.51.100.5"), Port: 1}
	bans.Fail(stranger, sshgateway.WeightAbandoned, "test")
	if ok, _ := bans.Allow(stranger); !ok {
		t.Fatal("one failure locked a source out although the threshold is two")
	}
	bans.Fail(stranger, sshgateway.WeightAbandoned, "test")
	if ok, _ := bans.Allow(stranger); ok {
		t.Fatal("the configured threshold of two was not applied")
	}

	friend := &net.TCPAddr{IP: net.ParseIP("192.0.2.5"), Port: 1}
	for i := 0; i < 20; i++ {
		bans.Fail(friend, sshgateway.WeightForged, "test")
	}
	if ok, _ := bans.Allow(friend); !ok {
		t.Fatal("a trusted network was locked out")
	}
}
