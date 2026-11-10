package authz

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// The identities a cedar server hands Policy.Authorize, end to end: an
// authenticated peer as its full user@domain, and a peer that did not
// authenticate as unauthenticated@unmapped -- the strings C++ DaemonCore
// passes IpVerify::Verify, so an ALLOW_* entry means the same thing to a Go
// daemon as to a C++ one.

const readCmd = 81002 // registered at READ

type handled struct{ user, authzUser string }

// serveOnce runs a cedar server whose READ command is authorized by p, dials
// it once with clientAuth, and reports whether the command ran and what its
// handler saw. The server offers FS with authentication OPTIONAL, so a
// REQUIRED client authenticates as <user>@uid.example and an OPTIONAL one
// does not authenticate at all.
func serveOnce(t *testing.T, p *Policy, clientAuth security.SecurityLevel) (handled, bool) {
	t.Helper()
	ran := make(chan handled, 1)
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		UIDDomain:      "uid.example",
		SessionCache:   security.NewSessionCache(),
	})
	srv.Authorizer = p.Authorize
	srv.Handle(readCmd, func(ctx context.Context, c *cedarserver.Conn) error {
		ran <- handled{user: c.Negotiation.User, authzUser: c.AuthorizationUser()}
		m := message.NewMessageForStream(c.Stream)
		if err := m.PutInt(ctx, 1); err != nil {
			return err
		}
		return m.FinishMessage(ctx)
	}, "READ")

	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()
	defer func() { _ = ln.Close() }()

	hc, err := client.ConnectAndAuthenticate(ctx, fmt.Sprintf("<%s>", ln.Addr()), &security.SecurityConfig{
		Command:        readCmd,
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: clientAuth,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionCache:   security.NewSessionCache(),
	})
	if err != nil {
		return handled{}, false
	}
	defer func() { _ = hc.Close() }()
	// A refused command closes the connection without an answer.
	if v, err := message.NewMessageFromStream(hc.GetStream()).GetInt(ctx); err != nil || v != 1 {
		return handled{}, false
	}
	return <-ran, true
}

func TestCedarAuthenticatedPeerIsAuthorizedAsFQU(t *testing.T) {
	p := newTestPolicy(t, mapConfig{"ALLOW_READ": "*@uid.example"}, nil, nil)

	h, ok := serveOnce(t, p, security.SecurityRequired)
	if !ok {
		t.Fatal("an FS peer was refused under ALLOW_READ = *@uid.example")
	}
	if _, domain := security.SplitFQU(h.authzUser); domain != "uid.example" || h.user != h.authzUser {
		t.Errorf("handler saw User %q, AuthorizationUser %q; want the same <user>@uid.example", h.user, h.authzUser)
	}

	if _, ok := serveOnce(t, p, security.SecurityOptional); ok {
		t.Error("an unauthenticated peer was admitted by ALLOW_READ = *@uid.example")
	}
}

func TestCedarUnauthenticatedPeerIsAuthorizedAsUnmapped(t *testing.T) {
	for _, allow := range []string{"unauthenticated@unmapped", "*@unmapped"} {
		p := newTestPolicy(t, mapConfig{"ALLOW_READ": allow}, nil, nil)
		h, ok := serveOnce(t, p, security.SecurityOptional)
		if !ok {
			t.Errorf("ALLOW_READ = %s refused an unauthenticated peer", allow)
			continue
		}
		if h.user != "" || h.authzUser != cedarserver.UnauthenticatedFQU {
			t.Errorf("ALLOW_READ = %s: handler saw User %q, AuthorizationUser %q; want \"\" and %q",
				allow, h.user, h.authzUser, cedarserver.UnauthenticatedFQU)
		}
		if _, ok := serveOnce(t, p, security.SecurityRequired); ok {
			t.Errorf("ALLOW_READ = %s admitted an FS peer", allow)
		}
	}
}
