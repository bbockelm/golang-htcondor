package htcondor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// fakeUserRecSchedd answers ENABLE_USERREC and DISABLE_USERREC with the
// framing command_act_on_user_ads uses, and records what it was sent.
type fakeUserRecSchedd struct {
	addr  string
	count int
	ads   []*classad.ClassAd
	cmd   int
	reply *classad.ClassAd
}

func newFakeUserRecSchedd(t *testing.T, reply *classad.ClassAd) *fakeUserRecSchedd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeUserRecSchedd{addr: fmt.Sprintf("<%s>", ln.Addr().String()), reply: reply}
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionCache:   security.NewSessionCache(),
	})
	for _, cmd := range []int{commands.ENABLE_USERREC, commands.DISABLE_USERREC} {
		cmd := cmd
		srv.Handle(cmd, func(ctx context.Context, c *cedarserver.Conn) error {
			in := message.NewMessageFromStream(c.Stream)
			n, err := in.GetInt(ctx)
			if err != nil {
				return err
			}
			f.cmd, f.count = cmd, n
			for range n {
				ad, err := in.GetClassAd(ctx)
				if err != nil {
					return err
				}
				f.ads = append(f.ads, ad)
			}
			out := message.NewMessageForStream(c.Stream)
			if err := out.PutClassAd(ctx, f.reply); err != nil {
				return err
			}
			return out.FinishMessage(ctx)
		}, "ADMINISTRATOR")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return f
}

func TestDisableProjectRecordWireFormat(t *testing.T) {
	f := newFakeUserRecSchedd(t, mustAd(t, map[string]any{"Result": 0, "NumAds": 1}))
	s := NewSchedd("test", f.addr)
	res, err := s.DisableUserRecord(placementTestContext(t), UserRecordProject, "Chem101", "Suspended by root via web UI")
	if err != nil {
		t.Fatalf("DisableUserRecord: %v", err)
	}
	if res.NumAds != 1 {
		t.Errorf("NumAds = %d", res.NumAds)
	}
	if f.cmd != commands.DISABLE_USERREC || f.count != 1 || len(f.ads) != 1 {
		t.Fatalf("cmd=%d count=%d ads=%d", f.cmd, f.count, len(f.ads))
	}
	ad := f.ads[0]
	for attr, want := range map[string]string{
		"TargetType":    "Project",
		"Name":          "Chem101",
		"DisableReason": "Suspended by root via web UI",
	} {
		if got, _ := ad.EvaluateAttrString(attr); got != want {
			t.Errorf("%s = %q, want %q", attr, got, want)
		}
	}
	if _, ok := ad.Lookup("User"); ok {
		t.Error("a project command must not carry User")
	}
}

func TestEnableOwnerRecordWireFormat(t *testing.T) {
	f := newFakeUserRecSchedd(t, mustAd(t, map[string]any{"Result": 0, "NumAds": 1}))
	s := NewSchedd("test", f.addr)
	if _, err := s.EnableUserRecord(placementTestContext(t), UserRecordOwner, "alice@ap.example"); err != nil {
		t.Fatalf("EnableUserRecord: %v", err)
	}
	ad := f.ads[0]
	if got, _ := ad.EvaluateAttrString("User"); got != "alice@ap.example" {
		t.Errorf("User = %q", got)
	}
	for _, attr := range []string{"TargetType", "DisableReason", "_userrec_opt_create"} {
		if _, ok := ad.Lookup(attr); ok {
			t.Errorf("enable carried %s", attr)
		}
	}
}

func TestUserRecordActionReportsScheddError(t *testing.T) {
	f := newFakeUserRecSchedd(t, mustAd(t, map[string]any{"Result": UserRecordErrNotFound, "NumAds": 0}))
	s := NewSchedd("test", f.addr)
	_, err := s.DisableUserRecord(placementTestContext(t), UserRecordOwner, "nobody@ap.example", "")
	var uerr *UserRecordError
	if !errors.As(err, &uerr) || uerr.Code != UserRecordErrNotFound {
		t.Fatalf("err = %v, want UserRecordError code %d", err, UserRecordErrNotFound)
	}
}

func TestCreateProjectRecordQueryAd(t *testing.T) {
	ad := createUserRecordQueryAdOfKind(UserRecordProject, nil)
	if got, _ := ad.EvaluateAttrString("TargetType"); got != "Project" {
		t.Errorf("TargetType = %q", got)
	}
}
