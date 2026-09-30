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
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// unopenedChannel is an ssh.NewChannel that is never accepted: channelContext
// only reads its type.
type unopenedChannel struct{ typ string }

func (c unopenedChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, errors.New("this channel is never accepted")
}
func (c unopenedChannel) Reject(ssh.RejectionReason, string) error { return nil }
func (c unopenedChannel) ChannelType() string                      { return c.typ }
func (c unopenedChannel) ExtraData() []byte                        { return nil }

// A channel whose credential could not be minted must still be classified as
// the caller's, because that is the case the classification exists for: it is
// the failure path that used to end up with MORE authority than the success
// path, falling through to this daemon's own pool credential.
//
// The three shapes are the three ways it happens in production, and the third
// is the one a test written against the first two would miss:
// withCondorCredential in webapi/httpserver/sshgateway.go returns the context
// unchanged, with no error, whenever the signing key or trust domain is
// unconfigured.
func TestChannelContextIsMarkedWhenNoCredentialIsMinted(t *testing.T) {
	cases := []struct {
		name string
		cred func(context.Context, string, []string) (context.Context, error)
	}{
		{"minting fails", func(ctx context.Context, _ string, _ []string) (context.Context, error) {
			return ctx, errors.New("signing key unreadable")
		}},
		{"no minter configured", nil},
		{"minter returns the context unchanged", func(ctx context.Context, _ string, _ []string) (context.Context, error) {
			return ctx, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{Credential: tc.cred}
			ctx := s.channelContext(context.Background(), "alice@example.org",
				[]string{"condor:/READ"}, unopenedChannel{typ: "session"})

			if _, ok := htcondor.GetSecurityConfigFromContext(ctx); ok {
				t.Fatal("this case was supposed to produce a context with no credential")
			}
			origin, reason := htcondor.CredentialOriginFromContext(ctx)
			if origin != htcondor.OriginUser {
				t.Fatalf("a credential-less channel context is %s, not %s: every CEDAR call under "+
					"it authenticates as this daemon, which on an access point is a queue superuser",
					origin, htcondor.OriginUser)
			}
			if reason == "" {
				t.Error("the mark carries no reason, so the refusal will not name this surface")
			}
		})
	}
}

// The successful path keeps whatever the minter attached, and the mark it was
// given on the way in.
func TestChannelContextKeepsAMintedCredential(t *testing.T) {
	s := &Server{Credential: func(ctx context.Context, account string, _ []string) (context.Context, error) {
		return htcondor.WithSecurityConfig(ctx, &security.SecurityConfig{Token: account}), nil
	}}
	ctx := s.channelContext(context.Background(), "alice@example.org",
		[]string{"condor:/READ"}, unopenedChannel{typ: "direct-tcpip"})

	got, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok {
		t.Fatal("the minted credential was dropped")
	}
	if got.Token != "alice@example.org" {
		t.Fatalf("the credential is not the minted one: token %q", got.Token)
	}
	if origin, _ := htcondor.CredentialOriginFromContext(ctx); origin != htcondor.OriginUser {
		t.Fatalf("an authenticated channel context is %s, want %s", origin, htcondor.OriginUser)
	}
}
