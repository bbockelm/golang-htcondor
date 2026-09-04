package htcondor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// fakePlacementd is a stand-in for condor_placementd on the wire. It reproduces
// the framing the C++ daemon uses, which is the part of the protocol most
// easily gotten wrong: the query commands write every result ad AND the
// trailing Summary ad into one CEDAR message, calling end_of_message only once
// at the very end.
type fakePlacementd struct {
	addr string
	// requests records the command ad each handler received, keyed by
	// command, so a test can assert what went out on the wire.
	requests map[int]*classad.ClassAd
}

// newFakePlacementd starts a placementd whose reply to each command is
// supplied by replies: the ads to write, in order. For the login command that
// is a single ad; for the query commands the LAST ad must be the Summary that
// terminates the stream.
func newFakePlacementd(t *testing.T, replies map[int][]*classad.ClassAd) *fakePlacementd {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	f := &fakePlacementd{
		addr:     fmt.Sprintf("<%s>", ln.Addr().String()),
		requests: make(map[int]*classad.ClassAd),
	}

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
		SessionCache:   security.NewSessionCache(),
	})

	for _, cmd := range []int{
		PlacementUserLogin,
		PlacementQueryUsers,
		PlacementQueryTokens,
		PlacementQueryAuthorizations,
	} {
		cmd := cmd
		// The real daemon registers every command at ADMINISTRATOR with
		// forced authentication.
		srv.Handle(cmd, func(ctx context.Context, c *cedarserver.Conn) error {
			in := message.NewMessageFromStream(c.Stream)
			ad, err := in.GetClassAd(ctx)
			if err != nil {
				return err
			}
			f.requests[cmd] = ad

			out := message.NewMessageForStream(c.Stream)
			for _, reply := range replies[cmd] {
				if err := out.PutClassAd(ctx, reply); err != nil {
					return err
				}
			}
			return out.FinishMessage(ctx)
		}, "ADMINISTRATOR")
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return f
}

// placementTestContext carries a security config matching the fake daemon's,
// so the client authenticates over loopback with FS instead of trying to read
// the machine's HTCondor configuration.
func placementTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return WithSecurityConfig(ctx, &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
	})
}

func mustAd(t *testing.T, attrs map[string]any) *classad.ClassAd {
	t.Helper()
	ad := classad.New()
	for k, v := range attrs {
		if err := ad.Set(k, v); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	return ad
}

func summaryAd(t *testing.T) *classad.ClassAd {
	t.Helper()
	return mustAd(t, map[string]any{"MyType": summaryAdType})
}

func TestPlacementdLogin(t *testing.T) {
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementUserLogin: {mustAd(t, map[string]any{"Token": "eyJhbGciOi.payload.sig"})},
	})

	ctx := placementTestContext(t)
	p := NewPlacementd(f.addr)

	result, err := p.Login(ctx, PlacementLoginRequest{
		UserName:       "student1@example.edu",
		Authorizations: []string{"READ", "WRITE"},
		Project:        "Chem101",
		Requester:      "prof@example.edu",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Token != "eyJhbGciOi.payload.sig" {
		t.Errorf("Token = %q", result.Token)
	}
	if result.Ad == nil {
		t.Error("Ad should carry the raw reply")
	}

	req := f.requests[PlacementUserLogin]
	if req == nil {
		t.Fatal("no request ad recorded")
	}
	for attr, want := range map[string]string{
		"UserName":       "student1@example.edu",
		"Authorizations": "READ,WRITE",
		"Project":        "Chem101",
		"Requester":      "prof@example.edu",
	} {
		if got, _ := req.EvaluateAttrString(attr); got != want {
			t.Errorf("request %s = %q, want %q", attr, got, want)
		}
	}
}

// A login that names no project or requester must not send those attributes at
// all: the daemon treats a present-but-empty Project as a project request and
// refuses it, since no user's project list contains "".
func TestPlacementdLoginOmitsUnsetOptionalFields(t *testing.T) {
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementUserLogin: {mustAd(t, map[string]any{"Token": "tok"})},
	})

	if _, err := NewPlacementd(f.addr).Login(placementTestContext(t), PlacementLoginRequest{
		UserName: "student1@example.edu",
	}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	req := f.requests[PlacementUserLogin]
	if _, ok := req.EvaluateAttrString("Project"); ok {
		t.Error("Project should be absent when unset")
	}
	if _, ok := req.EvaluateAttrString("Requester"); ok {
		t.Error("Requester should be absent when unset")
	}
	// Authorizations is always sent; empty means "the user's full set".
	if got, ok := req.EvaluateAttrString("Authorizations"); !ok || got != "" {
		t.Errorf("Authorizations = %q, ok=%v; want empty and present", got, ok)
	}
}

func TestPlacementdLoginError(t *testing.T) {
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementUserLogin: {mustAd(t, map[string]any{
			"ErrorString": "User don't have requested authorizations",
			"ErrorCode":   PlacementErrAuthorizationDenied,
		})},
	})

	_, err := NewPlacementd(f.addr).Login(placementTestContext(t), PlacementLoginRequest{
		UserName:       "student1@example.edu",
		Authorizations: []string{"ADMIN"},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	var perr *PlacementError
	if !errors.As(err, &perr) {
		t.Fatalf("error is %T, want *PlacementError", err)
	}
	if perr.Code != PlacementErrAuthorizationDenied {
		t.Errorf("Code = %d, want %d", perr.Code, PlacementErrAuthorizationDenied)
	}
}

// A reply with no token and no error is a contract violation, not an empty
// success -- returning it would hand the caller a blank credential.
func TestPlacementdLoginRejectsEmptyReply(t *testing.T) {
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementUserLogin: {classad.New()},
	})

	if _, err := NewPlacementd(f.addr).Login(placementTestContext(t), PlacementLoginRequest{
		UserName: "student1@example.edu",
	}); err == nil {
		t.Fatal("expected an error for a reply with neither token nor error")
	}
}

func TestPlacementdLoginRequiresUserName(t *testing.T) {
	// No server needed: the client rejects this before dialing.
	if _, err := NewPlacementd("<127.0.0.1:1>").Login(context.Background(), PlacementLoginRequest{
		UserName: "   ",
	}); err == nil {
		t.Fatal("expected an error for a blank UserName")
	}
}

func TestPlacementdQueryUsers(t *testing.T) {
	tokenExp := time.Now().Add(12 * time.Hour).Truncate(time.Second)
	mapExp := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)

	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementQueryUsers: {
			mustAd(t, map[string]any{
				"UserName":        "student1@example.edu",
				"ApUserId":        "student1@ap.example.edu",
				"TokenExpiration": tokenExp.Unix(),
				// The daemon's spelling, typo and all.
				"MappingExpration": mapExp.Unix(),
				"Projects":         "Chem101,Chem102",
				"Authorizations":   "READ,WRITE",
				"Authorized":       true,
			}),
			// A user whose mapping is gone but whose token still lives:
			// no projects, no authorizations, Authorized false.
			mustAd(t, map[string]any{
				"UserName":         "alum@example.edu",
				"ApUserId":         "alum@ap.example.edu",
				"TokenExpiration":  tokenExp.Unix(),
				"MappingExpration": 0,
				"Authorized":       false,
			}),
			summaryAd(t),
		},
	})

	users, err := NewPlacementd(f.addr).QueryUsers(placementTestContext(t), "")
	if err != nil {
		t.Fatalf("QueryUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}

	u := users[0]
	if u.UserName != "student1@example.edu" || u.APUserID != "student1@ap.example.edu" {
		t.Errorf("identity = %q / %q", u.UserName, u.APUserID)
	}
	if !u.TokenExpiration.Equal(tokenExp) {
		t.Errorf("TokenExpiration = %v, want %v", u.TokenExpiration, tokenExp)
	}
	if !u.MappingExpiration.Equal(mapExp) {
		t.Errorf("MappingExpiration = %v, want %v", u.MappingExpiration, mapExp)
	}
	if len(u.Projects) != 2 || u.Projects[0] != "Chem101" || u.Projects[1] != "Chem102" {
		t.Errorf("Projects = %v", u.Projects)
	}
	if len(u.Authorizations) != 2 {
		t.Errorf("Authorizations = %v", u.Authorizations)
	}
	if !u.Authorized {
		t.Error("Authorized should be true")
	}

	alum := users[1]
	if alum.Authorized {
		t.Error("unmapped user should report Authorized false")
	}
	// 0 is how the daemon spells "no expiration"; it must not become
	// 1970-01-01.
	if !alum.MappingExpiration.IsZero() {
		t.Errorf("MappingExpiration = %v, want zero", alum.MappingExpiration)
	}
	if len(alum.Projects) != 0 {
		t.Errorf("Projects = %v, want none", alum.Projects)
	}
}

func TestPlacementdQueryUsersFiltersByName(t *testing.T) {
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementQueryUsers: {summaryAd(t)},
	})

	users, err := NewPlacementd(f.addr).QueryUsers(placementTestContext(t), "student1@example.edu")
	if err != nil {
		t.Fatalf("QueryUsers: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("got %d users, want 0", len(users))
	}
	if got, _ := f.requests[PlacementQueryUsers].EvaluateAttrString("UserName"); got != "student1@example.edu" {
		t.Errorf("request UserName = %q", got)
	}
}

func TestPlacementdQueryTokens(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementQueryTokens: {
			mustAd(t, map[string]any{
				"Requester":       "prof@example.edu",
				"UserName":        "student1@example.edu",
				"ApUserId":        "student1@ap.example.edu",
				"Authorizations":  "READ,WRITE",
				"TokenId":         "abc123",
				"TokenExpiration": exp.Unix(),
				"Project":         "Chem101",
			}),
			summaryAd(t),
		},
	})

	tokens, err := NewPlacementd(f.addr).QueryTokens(placementTestContext(t), PlacementTokenQuery{
		UserName:  "student1@example.edu",
		ValidOnly: true,
	})
	if err != nil {
		t.Fatalf("QueryTokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("got %d tokens, want 1", len(tokens))
	}
	tok := tokens[0]
	if tok.TokenID != "abc123" || tok.Requester != "prof@example.edu" || tok.Project != "Chem101" {
		t.Errorf("token = %+v", tok)
	}
	if !tok.Expiration.Equal(exp) {
		t.Errorf("Expiration = %v, want %v", tok.Expiration, exp)
	}
	if len(tok.Authorizations) != 2 {
		t.Errorf("Authorizations = %v", tok.Authorizations)
	}

	req := f.requests[PlacementQueryTokens]
	if v, ok := req.EvaluateAttrBool("ValidOnly"); !ok || !v {
		t.Errorf("ValidOnly = %v, ok=%v", v, ok)
	}
	if _, ok := req.EvaluateAttrString("TokenId"); ok {
		t.Error("TokenId should be absent when unset")
	}
}

func TestPlacementdQueryAuthorizations(t *testing.T) {
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementQueryAuthorizations: {
			mustAd(t, map[string]any{
				"Name":        "INSTRUCTOR",
				"Label":       "Instructor",
				"Color":       "#7c3aed",
				"Description": "May request tokens on behalf of students",
			}),
			summaryAd(t),
		},
	})

	authz, err := NewPlacementd(f.addr).QueryAuthorizations(placementTestContext(t), "")
	if err != nil {
		t.Fatalf("QueryAuthorizations: %v", err)
	}
	if len(authz) != 1 {
		t.Fatalf("got %d authorizations, want 1", len(authz))
	}
	if authz[0].Name != "INSTRUCTOR" || authz[0].Label != "Instructor" || authz[0].Color != "#7c3aed" {
		t.Errorf("authorization = %+v", authz[0])
	}
}

// The query commands report some failures only in the trailing Summary ad,
// after zero or more result ads have already gone out.
func TestPlacementdQueryErrorInSummary(t *testing.T) {
	f := newFakePlacementd(t, map[int][]*classad.ClassAd{
		PlacementQueryAuthorizations: {
			mustAd(t, map[string]any{
				"MyType":      summaryAdType,
				"ErrorString": "User not authorized",
				"ErrorCode":   PlacementErrUserNotAuthorized,
			}),
		},
	})

	_, err := NewPlacementd(f.addr).QueryAuthorizations(placementTestContext(t), "nobody@example.edu")
	var perr *PlacementError
	if !errors.As(err, &perr) {
		t.Fatalf("error is %T (%v), want *PlacementError", err, err)
	}
	if perr.Code != PlacementErrUserNotAuthorized {
		t.Errorf("Code = %d, want %d", perr.Code, PlacementErrUserNotAuthorized)
	}
}

func TestPlacementSplitList(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"READ,WRITE", []string{"READ", "WRITE"}},
		{"READ WRITE", []string{"READ", "WRITE"}},
		{"READ, WRITE ,ADMIN", []string{"READ", "WRITE", "ADMIN"}},
		{"", nil},
		{"  ", nil},
	}
	for _, tc := range cases {
		ad := classad.New()
		if err := ad.Set("Authorizations", tc.raw); err != nil {
			t.Fatalf("set: %v", err)
		}
		got := placementSplitList(ad, "Authorizations")
		if len(got) != len(tc.want) {
			t.Errorf("%q -> %v, want %v", tc.raw, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%q -> %v, want %v", tc.raw, got, tc.want)
				break
			}
		}
	}
	// A missing attribute is not an empty list of one empty string.
	if got := placementSplitList(classad.New(), "Authorizations"); got != nil {
		t.Errorf("missing attribute -> %v, want nil", got)
	}
}

// DaemonPlacementd must map to the ad type the collector stores placementd ads
// under, which is the daemon's MyType verbatim rather than a "…Ad" name.
func TestDaemonPlacementdAdType(t *testing.T) {
	if got := DaemonPlacementd.adType(); got != PlacementdAdType {
		t.Errorf("adType() = %q, want %q", got, PlacementdAdType)
	}
	if PlacementdAdType != "PlacementD" {
		t.Errorf("PlacementdAdType = %q, want PlacementD", PlacementdAdType)
	}
	// A placementd ad is a GENERIC ad in the collector: there is no
	// QUERY_PLACEMENTD_ADS command, and the daemon's MyType is what the
	// generic query selects on. Both mappings must therefore fall through
	// to their defaults rather than be special-cased.
	if got := getCommandForAdType(PlacementdAdType); got != commands.QUERY_GENERIC_ADS {
		t.Errorf("getCommandForAdType(%q) = %v, want QUERY_GENERIC_ADS", PlacementdAdType, got)
	}
	if got := getTargetTypeForAdType(PlacementdAdType); got != "PlacementD" {
		t.Errorf("getTargetTypeForAdType(%q) = %q, want PlacementD", PlacementdAdType, got)
	}
}
