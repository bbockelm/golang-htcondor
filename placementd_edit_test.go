package htcondor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// fakePlacementdV2 serves PLACEMENT_QUERY and PLACEMENT_EDIT with the
// daemon's framing: the query request is one ad; the edit request is a header
// ad followed by NumOperations operation ads, all in ONE message; every reply
// is N ads plus a trailing Summary in ONE message.
type fakePlacementdV2 struct {
	addr string

	mu sync.Mutex
	// queryReq is the PLACEMENT_QUERY request ad.
	queryReq *classad.ClassAd
	// editHeader and editOps are the PLACEMENT_EDIT request, as read.
	editHeader *classad.ClassAd
	editOps    []*classad.ClassAd
}

func newFakePlacementdV2(t *testing.T, queryReply, editReply []*classad.ClassAd) *fakePlacementdV2 {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakePlacementdV2{addr: fmt.Sprintf("<%s>", ln.Addr().String())}

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
		SessionCache:   security.NewSessionCache(),
	})

	writeAll := func(ctx context.Context, c *cedarserver.Conn, ads []*classad.ClassAd) error {
		out := message.NewMessageForStream(c.Stream)
		for _, ad := range ads {
			if err := out.PutClassAd(ctx, ad); err != nil {
				return err
			}
		}
		return out.FinishMessage(ctx)
	}

	srv.Handle(PlacementQueryCommand, func(ctx context.Context, c *cedarserver.Conn) error {
		in := message.NewMessageFromStream(c.Stream)
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.queryReq = ad
		f.mu.Unlock()
		return writeAll(ctx, c, queryReply)
	}, "ADMINISTRATOR")

	srv.Handle(PlacementEditCommand, func(ctx context.Context, c *cedarserver.Conn) error {
		in := message.NewMessageFromStream(c.Stream)
		header, err := in.GetClassAd(ctx)
		if err != nil {
			return err
		}
		n, ok := header.EvaluateAttrInt("NumOperations")
		if !ok {
			return fmt.Errorf("header has no NumOperations")
		}
		ops := make([]*classad.ClassAd, 0, n)
		for i := int64(0); i < n; i++ {
			op, err := in.GetClassAd(ctx)
			if err != nil {
				return fmt.Errorf("operation %d: %w", i, err)
			}
			ops = append(ops, op)
		}
		f.mu.Lock()
		f.editHeader, f.editOps = header, ops
		f.mu.Unlock()
		return writeAll(ctx, c, editReply)
	}, "ADMINISTRATOR")

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return f
}

func mustParseAd(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(text)
	if err != nil {
		t.Fatalf("parse %s: %v", text, err)
	}
	return ad
}

// exprText is the unevaluated text of attr, for asserting that a value went
// out as a list, an expression or the literal undefined rather than a string.
func exprText(t *testing.T, ad *classad.ClassAd, attr string) string {
	t.Helper()
	e, ok := ad.Lookup(attr)
	if !ok {
		return "<absent>"
	}
	return e.String()
}

func TestPlacementdQueryRequestAndDecode(t *testing.T) {
	created := time.Unix(1760000000, 0)
	f := newFakePlacementdV2(t, []*classad.ClassAd{
		mustParseAd(t, `[MyType = "PlacementAccount"; Id = "a1b2"; Source = "internal"; Version = 4;
			CreatedAt = 1760000000; UpdatedAt = 1760000100; ModifiedBy = "admin@pool";
			Name = "alice@ap.example"; Authorizations = {"READ", "WRITE"}; Projects = {"ProjA", "ProjB"};
			DefaultProject = "ProjA"; Identities = {"alice@wisc.edu"}]`),
		summaryAd(t),
	}, nil)

	objs, err := NewPlacementd(f.addr).Query(placementTestContext(t), PlacementQuery{
		TargetType:   PlacementTargetAccount,
		Key:          "alice@ap.example",
		Requirements: `Source == "internal"`,
		Projection:   []string{"Name", "Projects"},
		Limit:        5,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(objs) != 1 || objs[0].Account == nil {
		t.Fatalf("objs = %+v", objs)
	}
	a := objs[0].Account
	if a.ID != "a1b2" || a.Source != PlacementSourceInternal || a.Version != 4 || a.ModifiedBy != "admin@pool" {
		t.Errorf("meta = %+v", a.PlacementEntityMeta)
	}
	if !a.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v", a.CreatedAt)
	}
	if strings.Join(a.Projects, ",") != "ProjA,ProjB" || a.DefaultProject != "ProjA" {
		t.Errorf("projects = %v default %q", a.Projects, a.DefaultProject)
	}
	if strings.Join(a.Authorizations, ",") != "READ,WRITE" || strings.Join(a.Identities, ",") != "alice@wisc.edu" {
		t.Errorf("authz = %v identities = %v", a.Authorizations, a.Identities)
	}

	req := f.queryReq
	if got, _ := req.EvaluateAttrString("TargetType"); got != "Account" {
		t.Errorf("TargetType = %q", got)
	}
	if got, _ := req.EvaluateAttrString("Name"); got != "alice@ap.example" {
		t.Errorf("Name = %q", got)
	}
	// Requirements is an expression, not a quoted string.
	if got := exprText(t, req, "Requirements"); !strings.Contains(got, "Source ==") || strings.HasPrefix(got, `"`) {
		t.Errorf("Requirements = %s", got)
	}
	if got, _ := req.EvaluateAttrString("Projection"); got != "Name,Projects" {
		t.Errorf("Projection = %q", got)
	}
	if got, _ := req.EvaluateAttrInt("Limit"); got != 5 {
		t.Errorf("Limit = %d", got)
	}
	if _, ok := req.Lookup("Id"); ok {
		t.Error("Id should be absent when unset")
	}
}

func TestPlacementdQueryDecodesEveryType(t *testing.T) {
	f := newFakePlacementdV2(t, []*classad.ClassAd{
		mustParseAd(t, `[MyType = "PlacementIdentity"; Id = "i1"; Source = "mapfile"; Version = 1;
			Identity = "alice@wisc.edu"; AccountId = "a1"; Account = "alice@ap"; ExpiresAt = 1767225600;
			Expired = false; DisplayName = "Alice"; Comment = "TA"; Authorizations = {"READ"};
			Projects = {"P"}; DefaultProject = "P"; LastTokenExpiration = 1767000000]`),
		// ExpiresAt absent means the mapping never expires.
		mustParseAd(t, `[MyType = "PlacementIdentity"; Id = "i2"; Identity = "bob"; Expired = true]`),
		mustParseAd(t, `[MyType = "PlacementProject"; Id = "p1"; Name = "ProjA"; Description = "d"; Accounts = {"alice@ap"}]`),
		mustParseAd(t, `[MyType = "PlacementAuthorization"; Id = "z1"; Name = "READ"; Label = "Read"; Color = "normal"; Description = "x"; Requestable = 1]`),
		mustParseAd(t, `[MyType = "PlacementMapfileStatus"; PlacementdMapfileLoadTime = 1760000000;
			PlacementdMapfileLoadAttemptTime = 1760000300; PlacementdMapfileOK = false;
			PlacementdMapfileQuarantined = 2; PlacementdMapfileConflicts = 1; PlacementdApiVersion = 2;
			UserMapfile = "/etc/condor/placementd.map"; AuthorizationsMapfile = "/etc/condor/authz.map";
			Problems = { [Kind = "malformed"; File = "/etc/condor/placementd.map"; Line = 7; Key = "carol"; Message = "bad expiry"] }]`),
		summaryAd(t),
	}, nil)

	objs, err := NewPlacementd(f.addr).Query(placementTestContext(t), PlacementQuery{TargetType: PlacementTargetIdentity})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(objs) != 5 {
		t.Fatalf("got %d objects", len(objs))
	}
	id := objs[0].Identity
	if id == nil || id.Identity != "alice@wisc.edu" || id.Account != "alice@ap" || id.AccountID != "a1" ||
		id.ExpiresAt.Unix() != 1767225600 || id.DisplayName != "Alice" || id.LastTokenExpiration.Unix() != 1767000000 {
		t.Errorf("identity = %+v", id)
	}
	if never := objs[1].Identity; never == nil || !never.ExpiresAt.IsZero() || !never.Expired {
		t.Errorf("second identity = %+v", never)
	}
	if pr := objs[2].Project; pr == nil || pr.Name != "ProjA" || len(pr.Accounts) != 1 {
		t.Errorf("project = %+v", pr)
	}
	// Requestable arrives as 0/1 from a SQLite column as readily as a bool.
	if au := objs[3].Authorization; au == nil || au.Label != "Read" || !au.Requestable {
		t.Errorf("authorization = %+v", au)
	}
	st := objs[4].MapfileStatus
	if st == nil || st.OK || st.Quarantined != 2 || st.Conflicts != 1 || st.APIVersion != 2 || st.LoadTime.Unix() != 1760000000 {
		t.Fatalf("status = %+v", st)
	}
	if len(st.Problems) != 1 || st.Problems[0].Line != 7 || st.Problems[0].Key != "carol" || st.Problems[0].Kind != "malformed" {
		t.Errorf("problems = %+v", st.Problems)
	}
}

func TestPlacementdQueryErrorInSummaryV2(t *testing.T) {
	f := newFakePlacementdV2(t, []*classad.ClassAd{
		mustAd(t, map[string]any{"MyType": summaryAdType, "ErrorCode": PlacementErrUnknownType, "ErrorString": "unknown TargetType"}),
	}, nil)
	_, err := NewPlacementd(f.addr).Query(placementTestContext(t), PlacementQuery{TargetType: "Widget"})
	var perr *PlacementError
	if !errors.As(err, &perr) || perr.Code != PlacementErrUnknownType || perr.Name() != "unknown_type" {
		t.Fatalf("err = %v", err)
	}
}

func TestPlacementdQueryRejectsBadRequirements(t *testing.T) {
	_, err := NewPlacementd("<127.0.0.1:1>").Query(context.Background(), PlacementQuery{
		TargetType: PlacementTargetAccount, Requirements: "Name == ",
	})
	var perr *PlacementError
	if !errors.As(err, &perr) || perr.Code != PlacementErrInvalidArgument {
		t.Fatalf("err = %v, want code 16 before dialing", err)
	}
}

func TestPlacementdEditFraming(t *testing.T) {
	f := newFakePlacementdV2(t, nil, []*classad.ClassAd{
		mustParseAd(t, `[MyType = "PlacementEditResult"; Index = 0; Id = "acct-uuid"; Version = 1]`),
		mustParseAd(t, `[MyType = "PlacementEditResult"; Index = 1; Id = "ident-uuid"; Version = 1]`),
		mustParseAd(t, `[MyType = "PlacementEditResult"; Index = 2; Id = "ident-2"; Version = 8; Warning = "still in the mapfile"]`),
		summaryAd(t),
	})

	results, err := NewPlacementd(f.addr).Edit(placementTestContext(t), []PlacementOp{
		{
			Operation: PlacementOpCreate, TargetType: PlacementTargetAccount,
			Fields: map[string]any{
				"Name":           "alice@ap.example",
				"Authorizations": []string{"READ", "WRITE"},
				"Projects":       []string{},
				"DefaultProject": nil,
			},
		},
		{
			Operation: PlacementOpCreate, TargetType: PlacementTargetIdentity,
			Fields: map[string]any{
				"Identity":  "alice@wisc.edu",
				"Account":   "alice@ap.example",
				"ExpiresAt": time.Unix(1767225600, 0),
			},
		},
		{
			Operation: PlacementOpUpdate, TargetType: PlacementTargetIdentity, ID: "ident-2",
			ExpectedVersion: 7,
			Fields:          map[string]any{"ExpiresAt": nil, "Comment": "renewed"},
		},
	}, PlacementEditOptions{DryRun: true, OnBehalfOf: "alice", Comment: "onboarding"})
	if err != nil {
		t.Fatalf("Edit: %v", err)
	}
	if len(results) != 3 || results[0].ID != "acct-uuid" || results[2].Version != 8 || results[2].Warning == "" {
		t.Fatalf("results = %+v", results)
	}

	h := f.editHeader
	if got, _ := h.EvaluateAttrString("MyType"); got != "PlacementEdit" {
		t.Errorf("header MyType = %q", got)
	}
	if got, _ := h.EvaluateAttrInt("NumOperations"); got != 3 {
		t.Errorf("NumOperations = %d", got)
	}
	if got, ok := h.EvaluateAttrBool("DryRun"); !ok || !got {
		t.Errorf("DryRun = %v, %v", got, ok)
	}
	if got, _ := h.EvaluateAttrString("OnBehalfOf"); got != "alice" {
		t.Errorf("OnBehalfOf = %q, want alice", got)
	}
	if got, _ := h.EvaluateAttrString("Comment"); got != "onboarding" {
		t.Errorf("Comment = %q, want onboarding", got)
	}
	if len(f.editOps) != 3 {
		t.Fatalf("daemon read %d operation ads", len(f.editOps))
	}

	acct := f.editOps[0]
	if got, _ := acct.EvaluateAttrString("Operation"); got != "Create" {
		t.Errorf("Operation = %q", got)
	}
	if got := placementStringList(acct, "Authorizations"); !acct.EvaluateAttr("Authorizations").IsList() || strings.Join(got, ",") != "READ,WRITE" {
		t.Errorf("Authorizations went out as %s, want a ClassAd list", exprText(t, acct, "Authorizations"))
	}
	if v := acct.EvaluateAttr("Projects"); !v.IsList() {
		t.Errorf("Projects went out as %s, want an empty list", exprText(t, acct, "Projects"))
	}
	if got := exprText(t, acct, "DefaultProject"); got != "undefined" {
		t.Errorf("DefaultProject = %s, want undefined", got)
	}
	for _, attr := range []string{"Id", "ExpectedVersion", "Cascade"} {
		if _, ok := acct.Lookup(attr); ok {
			t.Errorf("Create carried %s", attr)
		}
	}
	if got, _ := acct.EvaluateAttrString("Name"); got != "alice@ap.example" {
		t.Errorf("Name field = %q", got)
	}

	ident := f.editOps[1]
	if got, _ := ident.EvaluateAttrInt("ExpiresAt"); got != 1767225600 {
		t.Errorf("ExpiresAt = %d", got)
	}

	upd := f.editOps[2]
	if got, _ := upd.EvaluateAttrString("Id"); got != "ident-2" {
		t.Errorf("Id = %q", got)
	}
	if got, _ := upd.EvaluateAttrInt("ExpectedVersion"); got != 7 {
		t.Errorf("ExpectedVersion = %d, want 7", got)
	}
	if got := exprText(t, upd, "ExpiresAt"); got != "undefined" {
		t.Errorf("ExpiresAt = %s, want the literal undefined", got)
	}
	if _, ok := upd.Lookup("DisplayName"); ok {
		t.Error("an Update must carry only the attributes it changes")
	}
}

// A failed batch still reports each operation's result, and the Summary's
// code becomes the returned error.
func TestPlacementdEditFailureCarriesResults(t *testing.T) {
	f := newFakePlacementdV2(t, nil, []*classad.ClassAd{
		mustParseAd(t, `[MyType = "PlacementEditResult"; Index = 0; Id = "x"; Version = 3]`),
		mustParseAd(t, `[MyType = "PlacementEditResult"; Index = 1; ErrorCode = 15; ErrorString = "owned by mapfile"]`),
		mustParseAd(t, `[MyType = "Summary"; ErrorCode = 15; ErrorString = "owned by mapfile"]`),
	})
	results, err := NewPlacementd(f.addr).Edit(placementTestContext(t), []PlacementOp{
		{Operation: PlacementOpDelete, TargetType: PlacementTargetProject, Key: "ProjA", Cascade: true},
		{Operation: PlacementOpUpdate, TargetType: PlacementTargetAccount, Key: "bob@ap", Fields: map[string]any{"Projects": []string{"P"}}},
	}, PlacementEditOptions{})
	var perr *PlacementError
	if !errors.As(err, &perr) || perr.Code != PlacementErrOwnedBySource {
		t.Fatalf("err = %v, want code 15", err)
	}
	if len(results) != 2 || results[1].ErrorCode != PlacementErrOwnedBySource {
		t.Fatalf("results = %+v", results)
	}
	if v, ok := f.editOps[0].EvaluateAttrBool("Cascade"); !ok || !v {
		t.Error("Cascade did not go out")
	}
	if v, ok := f.editHeader.EvaluateAttrBool("DryRun"); !ok || v {
		t.Errorf("DryRun = %v, %v; want false and present", v, ok)
	}
	// Unset audit fields are not sent at all.
	for _, attr := range []string{"OnBehalfOf", "Comment"} {
		if _, ok := f.editHeader.Lookup(attr); ok {
			t.Errorf("%s sent though unset", attr)
		}
	}
}

// A Summary with only an ErrorCode is a failure too: the design keys the
// batch outcome on ErrorCode.
func TestPlacementdEditSummaryCodeOnly(t *testing.T) {
	f := newFakePlacementdV2(t, nil, []*classad.ClassAd{
		mustParseAd(t, `[MyType = "Summary"; ErrorCode = 14]`),
	})
	_, err := NewPlacementd(f.addr).Edit(placementTestContext(t), []PlacementOp{
		{Operation: PlacementOpAdopt, TargetType: PlacementTargetAll},
	}, PlacementEditOptions{})
	var perr *PlacementError
	if !errors.As(err, &perr) || perr.Code != PlacementErrVersionMismatch {
		t.Fatalf("err = %v, want code 14", err)
	}
}

func TestPlacementOpValidation(t *testing.T) {
	cases := []struct {
		name string
		ops  []PlacementOp
	}{
		{"empty batch", nil},
		{"too many", make([]PlacementOp, placementMaxOperations+1)},
		{"create with selector", []PlacementOp{{Operation: "Create", TargetType: "Project", Key: "x"}}},
		{"rename by name", []PlacementOp{{Operation: "Update", TargetType: "Project", Key: "x", Fields: map[string]any{"Name": "y"}}}},
		{"rekey identity by identity", []PlacementOp{{Operation: "Update", TargetType: "Identity", Key: "x", Fields: map[string]any{"Identity": "y"}}}},
		{"identity with a Name", []PlacementOp{{Operation: "Create", TargetType: "Identity", Fields: map[string]any{"Name": "y", "Account": "a"}}}},
		{"field overrides operation", []PlacementOp{{Operation: "Update", TargetType: "Project", ID: "u", Fields: map[string]any{"operation": "Delete"}}}},
		{"cascade on update", []PlacementOp{{Operation: "Update", TargetType: "Project", ID: "u", Cascade: true}}},
		{"unsupported value", []PlacementOp{{Operation: "Update", TargetType: "Project", ID: "u", Fields: map[string]any{"Description": 1.5}}}},
		{"missing operation", []PlacementOp{{TargetType: "Project", ID: "u"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPlacementd("<127.0.0.1:1>").Edit(context.Background(), tc.ops, PlacementEditOptions{})
			var perr *PlacementError
			if !errors.As(err, &perr) || perr.Code != PlacementErrInvalidArgument {
				t.Fatalf("err = %v, want code 16 before dialing", err)
			}
		})
	}

	// A rename selects by ID and carries the new name as a field.
	ad, err := placementOpAd(PlacementOp{Operation: "Update", TargetType: "Account", ID: "u1", Fields: map[string]any{"Name": "new@ap"}})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got, _ := ad.EvaluateAttrString("Name"); got != "new@ap" {
		t.Errorf("Name = %q", got)
	}
}

func TestPlacementdAPIVersion(t *testing.T) {
	if got := PlacementdAPIVersion(classad.New()); got != 1 {
		t.Errorf("absent = %d, want 1", got)
	}
	if got := PlacementdAPIVersion(mustAd(t, map[string]any{PlacementdAPIVersionAttr: 2})); got != 2 {
		t.Errorf("2 = %d", got)
	}
	if got := PlacementdAPIVersion(nil); got != 1 {
		t.Errorf("nil = %d", got)
	}
}

// Two access points' placementds in one collector, the other one's listed
// first.
func versionAds(t *testing.T) (foreign, local *classad.ClassAd) {
	t.Helper()
	foreign = mustAd(t, map[string]any{
		"Name": "other-ap.example.org", "Machine": "other-ap.example.org",
		"MyAddress": "<10.0.0.2:9618?sock=placementd_9_9>", PlacementdAPIVersionAttr: 2,
	})
	local = mustAd(t, map[string]any{
		"Name": "this-ap.example.org", "Machine": "this-ap.example.org",
		"MyAddress": "<10.0.0.1:9618?sock=placementd_1_1>",
	})
	return foreign, local
}

// The version is the placementd's this client uses, never whichever ad the
// collector lists first.
func TestSelectPlacementdAdByAddress(t *testing.T) {
	foreign, local := versionAds(t)
	ads := []*classad.ClassAd{foreign, local}

	got := SelectPlacementdAd(ads, "10.0.0.1:9618?sock=placementd_1_1", nil)
	if got != local {
		t.Fatalf("selected %v, want this access point's ad", got)
	}
	if v := PlacementdAPIVersion(got); v != 1 {
		t.Errorf("version = %d, want this access point's 1, not the other's 2", v)
	}

	// The address the client has matches no ad: nothing, not the first ad.
	if got := SelectPlacementdAd(ads, "<10.0.0.1:9618?sock=placementd_2_2>", nil); got != nil {
		t.Errorf("an unmatched address selected %v", got)
	}
	if got := SelectPlacementdAd([]*classad.ClassAd{foreign}, "<10.0.0.1:9618?sock=placementd_1_1>", nil); got != nil {
		t.Errorf("only another access point's ad, selected %v", got)
	}
}

// When the address is stale, accept identifies the daemon; an ambiguous
// answer is no answer.
func TestSelectPlacementdAdByAccept(t *testing.T) {
	foreign, local := versionAds(t)
	ads := []*classad.ClassAd{foreign, local}
	onThisHost := func(ad *classad.ClassAd) bool {
		m, _ := ad.EvaluateAttrString("Machine")
		return m == "this-ap.example.org"
	}
	if got := SelectPlacementdAd(ads, "<10.0.0.1:9618?sock=placementd_2_2>", onThisHost); got != local {
		t.Errorf("selected %v, want this access point's ad", got)
	}
	if got := SelectPlacementdAd([]*classad.ClassAd{foreign}, "", onThisHost); got != nil {
		t.Errorf("only another access point's ad, selected %v", got)
	}
	admitAll := func(*classad.ClassAd) bool { return true }
	if got := SelectPlacementdAd(ads, "", admitAll); got != nil {
		t.Errorf("two admitted ads selected %v", got)
	}
}

func TestPlacementdAdProjectionCarriesWhatIsRead(t *testing.T) {
	for _, want := range []string{"MyAddress", "Name", "Machine", PlacementdAPIVersionAttr} {
		found := false
		for _, a := range PlacementdAdProjection() {
			found = found || a == want
		}
		if !found {
			t.Errorf("%s missing from %v", want, PlacementdAdProjection())
		}
	}
}

func TestPlacementErrorNames(t *testing.T) {
	want := map[int]string{
		13: "not_found", 14: "version_mismatch", 15: "owned_by_other_source",
		16: "invalid_argument", 17: "still_referenced", 18: "duplicate", 19: "unknown_type",
	}
	for code, name := range want {
		if got := PlacementErrorName(code); got != name {
			t.Errorf("PlacementErrorName(%d) = %q, want %q", code, got, name)
		}
	}
	if PlacementQueryCommand != 564 || PlacementEditCommand != 565 {
		t.Errorf("command numbers = %d, %d; want SCHED_VERS(400)+164/165", PlacementQueryCommand, PlacementEditCommand)
	}
}

// An identity is keyed by Identity on the wire, in queries and in edits;
// every other type by Name.
func TestPlacementIdentityKeyAttribute(t *testing.T) {
	if PlacementKeyAttr(PlacementTargetIdentity) != "Identity" || PlacementKeyAttr(PlacementTargetAccount) != "Name" {
		t.Fatalf("key attrs = %q, %q", PlacementKeyAttr(PlacementTargetIdentity), PlacementKeyAttr(PlacementTargetAccount))
	}

	q, err := placementQueryAd(PlacementQuery{TargetType: PlacementTargetIdentity, Key: "alice@wisc.edu"})
	if err != nil {
		t.Fatalf("query ad: %v", err)
	}
	if got, _ := q.EvaluateAttrString("Identity"); got != "alice@wisc.edu" {
		t.Errorf("query Identity = %q", got)
	}
	if _, ok := q.Lookup("Name"); ok {
		t.Error("an identity query must not send Name")
	}

	sel, err := placementOpAd(PlacementOp{Operation: PlacementOpDelete, TargetType: PlacementTargetIdentity, Key: "alice@wisc.edu"})
	if err != nil {
		t.Fatalf("selector op: %v", err)
	}
	if got, _ := sel.EvaluateAttrString("Identity"); got != "alice@wisc.edu" {
		t.Errorf("selector Identity = %q", got)
	}
	if _, ok := sel.Lookup("Name"); ok {
		t.Error("an identity op must not send Name")
	}

	// With an Id, Identity is the new value.
	rekey, err := placementOpAd(PlacementOp{Operation: PlacementOpUpdate, TargetType: PlacementTargetIdentity, ID: "u1",
		Fields: map[string]any{"Identity": "alice@cilogon.org"}})
	if err != nil {
		t.Fatalf("rekey op: %v", err)
	}
	if got, _ := rekey.EvaluateAttrString("Identity"); got != "alice@cilogon.org" {
		t.Errorf("rekey Identity = %q", got)
	}
}
