package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// An approval names an account the placementd could hold: one "@", no
// separators or quoting characters, and never a name the schedd treats as
// a super user.
func TestAccessRequestApproveRefusesBadAccounts(t *testing.T) {
	srv := newRequestsServer(t, func(c *Config) {
		cfg, err := config.NewFromReader(strings.NewReader("QUEUE_SUPER_USERS = root, condor, superjoe@ap.example, %wheel\n"))
		if err != nil {
			t.Fatal(err)
		}
		c.HTCondorConfig = cfg
	})
	id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
	admin := srv.admin(t)
	for _, account := range []string{
		"root", "root@ap.example", "ROOT@elsewhere.example", "condor@ap.example", "condor_pool@ap.example",
		"superjoe@ap.example", "SuperJoe@other.example", "wheel@ap.example",
		"newbie", "@ap.example", "newbie@", "a@b@ap.example", "new bie@ap.example", "new\tbie@ap.example",
		`new"bie@ap.example`, `new\bie@ap.example`, "new,bie@ap.example", "new\u202ebie@ap.example",
	} {
		rec := srv.do(t, admin, "POST", approvePath(id), fmt.Sprintf(`{"account":%q,"authorizations":["READ"]}`, account))
		mustStatus(t, rec, http.StatusBadRequest, "account "+account)
	}
	if srv.fake.editCount() != 0 || len(srv.fake.queries) != 0 {
		t.Errorf("a refused account reached the placementd: %d edits, %d queries", srv.fake.editCount(), len(srv.fake.queries))
	}
	if r := srv.stored(t, requesterIdentity); r.Status != accessRequestPending {
		t.Errorf("request is %s", r.Status)
	}
}

// existingAccount puts an account other identities already use in the
// fake directory.
func existingAccount(srv *requestsServer, source string) {
	a := &htcondor.PlacementAccount{
		PlacementEntityMeta: htcondor.PlacementEntityMeta{ID: "acct-1", Version: 9, Source: source},
		Name:                "shared@ap.example",
		Authorizations:      []string{"READ", "WRITE"},
		Projects:            []string{"Physics"},
		DefaultProject:      "Physics",
		Identities:          []string{"alice@idp.example", "bob@idp.example"},
	}
	srv.fake.accounts[a.Name] = a
}

// Linking a request to an account that already exists is an explicit
// choice: without it the approval is refused and shows who else is on the
// account, and what it holds.
func TestAccessRequestApproveExistingAccountNeedsAttach(t *testing.T) {
	srv := newRequestsServer(t)
	existingAccount(srv, htcondor.PlacementSourceInternal)
	id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
	admin := srv.admin(t)

	rec := srv.do(t, admin, "POST", approvePath(id), `{"account":"shared@ap.example","authorizations":["READ","WRITE"],"projects":["Physics"]}`)
	mustStatus(t, rec, http.StatusConflict, "attach without the flag")
	var body placementAccountExistsBody
	decodeBody(t, rec, &body)
	if !body.AccountExists || body.Account == nil ||
		strings.Join(body.Account.Identities, ",") != "alice@idp.example,bob@idp.example" ||
		strings.Join(body.Account.Authorizations, ",") != "READ,WRITE" {
		t.Errorf("409 body = %+v", body)
	}
	if srv.fake.editCount() != 0 {
		t.Fatal("an unconfirmed attach reached PLACEMENT_EDIT")
	}

	rec = srv.do(t, admin, "POST", approvePath(id), `{"account":"shared@ap.example","attach_to_existing":true}`)
	mustStatus(t, rec, http.StatusOK, "attach with the flag")
	ops := srv.fake.edits[0]
	if len(ops) != 1 || ops[0].Operation != htcondor.PlacementOpCreate || ops[0].TargetType != htcondor.PlacementTargetIdentity ||
		ops[0].Fields["Identity"] != requesterIdentity || ops[0].Fields["Account"] != "shared@ap.example" {
		t.Errorf("ops = %+v", ops)
	}
}

// An approval never changes an existing account: its grants are every
// identity's on it, and the directory page is where they are changed.
func TestAccessRequestApproveNeverUpdatesTheAccount(t *testing.T) {
	for _, source := range []string{htcondor.PlacementSourceInternal, htcondor.PlacementSourceMapfile} {
		t.Run(source, func(t *testing.T) {
			srv := newRequestsServer(t)
			existingAccount(srv, source)
			id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
			rec := srv.do(t, srv.admin(t), "POST", approvePath(id),
				`{"account":"shared@ap.example","attach_to_existing":true,"authorizations":["READ"],"projects":["Chemistry"],"default_project":"Chemistry"}`)
			mustStatus(t, rec, http.StatusOK, "approve with narrower grants")
			if srv.fake.editCount() != 1 {
				t.Fatalf("%d batches", srv.fake.editCount())
			}
			for _, op := range srv.fake.edits[0] {
				if op.TargetType == htcondor.PlacementTargetAccount {
					t.Errorf("the batch changes the account: %+v", op)
				}
			}
			if ops := srv.fake.edits[0]; len(ops) != 1 || ops[0].TargetType != htcondor.PlacementTargetIdentity {
				t.Errorf("ops = %+v", ops)
			}
		})
	}
}

// The account is suggested from the identity only for domains the operator
// trusts to name people.
func TestAccessRequestSuggestedAccountNeedsAPrefillDomain(t *testing.T) {
	list := func(srv *requestsServer) map[string]string {
		rec := srv.do(t, srv.admin(t), "GET", "/api/v1/placement/admin/requests", "")
		var out placementAccessRequestList
		decodeBody(t, rec, &out)
		got := map[string]string{}
		for _, r := range out.Requests {
			got[r.Identity] = r.SuggestedAccount
		}
		return got
	}

	srv := newRequestsServer(t)
	srv.fileRequest(t, srv.placementSession(t, requesterIdentity))
	if got := list(srv)[requesterIdentity]; got != "" {
		t.Errorf("with no prefill domains the suggestion is %q", got)
	}

	srv = newRequestsServer(t, func(c *Config) { c.PlacementPrefillDomains = []string{"IdP.example"} })
	srv.fileRequest(t, srv.placementSession(t, requesterIdentity))
	srv.fileRequest(t, srv.placementSession(t, "root@evil.example"))
	srv.fileRequest(t, srv.placementSession(t, "opaque-subject-123"))
	got := list(srv)
	if got[requesterIdentity] != "newbie@ap.example" || got["root@evil.example"] != "" || got["opaque-subject-123"] != "" {
		t.Errorf("suggestions = %v", got)
	}
}

// The name and email a provider sends are capped and stripped of
// invisible characters, and the email is kept only when the provider says
// it verified it.
func TestPlacementSessionProfileFromTheProvider(t *testing.T) {
	long := strings.Repeat("n", 300)
	s, c := newbieServer(t, map[string]any{
		"sub": newbieSubject, "eppn": newbieIdentity,
		"name": "New\u202e Bie\u200b\x07" + long, "email": "newbie@example.edu",
	})
	sd, ok := s.getAnySessionFromRequest(cookieRequest(c))
	if !ok {
		t.Fatal("no session")
	}
	if sd.Email != "" {
		t.Errorf("an unverified email was kept: %q", sd.Email)
	}
	if strings.ContainsAny(sd.DisplayName, "\u202e\u200b\x07") || len([]rune(sd.DisplayName)) > 256 ||
		!strings.HasPrefix(sd.DisplayName, "New Bie") {
		t.Errorf("display name = %q (%d runes)", sd.DisplayName, len([]rune(sd.DisplayName)))
	}

	for _, verified := range []any{true, "true"} {
		s, c = newbieServer(t, map[string]any{
			"sub": newbieSubject, "eppn": newbieIdentity, "name": "Newbie",
			"email": "new\u2066bie@example.edu", "email_verified": verified,
		})
		if sd, _ := s.getAnySessionFromRequest(cookieRequest(c)); sd == nil || sd.Email != "newbie@example.edu" {
			t.Errorf("email_verified=%v: email = %+v", verified, sd)
		}
	}
}

// Approval takes the request out of pending before it edits the
// directory, so the requester cannot withdraw it, nor another admin deny
// it, while the change is being made.
func TestAccessRequestApprovalHoldsTheRequest(t *testing.T) {
	srv := newRequestsServer(t)
	newbie := srv.placementSession(t, requesterIdentity)
	id := srv.fileRequest(t, newbie).Request.ID
	admin := srv.admin(t)
	var withdraw, deny, mine int
	var midStatus string
	srv.fake.onEdit = func() {
		withdraw = srv.do(t, newbie, "DELETE", "/api/v1/placement/me/request", "").Code
		deny = srv.do(t, srv.admin(t), "POST", fmt.Sprintf("/api/v1/placement/admin/requests/%d/deny", id), `{"reason":"no"}`).Code
		rec := srv.do(t, newbie, "GET", "/api/v1/placement/me/request", "")
		mine = rec.Code
		if r := decodeMeRequest(t, rec).Request; r != nil {
			midStatus = r.Status
		}
	}
	rec := srv.do(t, admin, "POST", approvePath(id), `{"account":"newbie@ap.example","authorizations":["READ"]}`)
	mustStatus(t, rec, http.StatusOK, "approve")
	if withdraw != http.StatusConflict || deny != http.StatusConflict {
		t.Errorf("during the approval: withdraw %d, deny %d; want 409 for both", withdraw, deny)
	}
	// The requester still sees it as waiting.
	if mine != http.StatusOK || midStatus != accessRequestPending {
		t.Errorf("during the approval the requester saw %d %q", mine, midStatus)
	}
	if r := srv.stored(t, requesterIdentity); r.Status != accessRequestApproved || r.DecidedBy != "root" {
		t.Errorf("after the approval: %+v", r)
	}

	// A failed batch gives the request back.
	id2 := srv.fileRequest(t, srv.placementSession(t, "second@idp.example")).Request.ID
	srv.fake.onEdit = nil
	srv.fake.results = []htcondor.PlacementEditResult{{Index: 0, ErrorCode: htcondor.PlacementErrInvalidArgument}}
	srv.fake.editErr = &htcondor.PlacementError{Code: htcondor.PlacementErrInvalidArgument, Message: "bad"}
	rec = srv.do(t, admin, "POST", approvePath(id2), `{"account":"second@ap.example"}`)
	mustStatus(t, rec, http.StatusBadRequest, "refused batch")
	if r := srv.stored(t, "second@idp.example"); r.Status != accessRequestPending || r.DecidedBy != "" {
		t.Errorf("after a refused batch: %+v", r)
	}
}

// An approval that never finished (the server stopped mid-way) does not
// hold its request forever.
func TestAccessRequestStaleApprovalIsReleased(t *testing.T) {
	srv := newRequestsServer(t)
	id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
	store := srv.placementOnboard.requests
	if _, err := store.beginApproval(context.Background(), id, "root"); err != nil {
		t.Fatal(err)
	}
	// Not yet stale.
	rec := srv.do(t, srv.admin(t), "GET", "/api/v1/placement/admin/requests", "")
	var list placementAccessRequestList
	decodeBody(t, rec, &list)
	if list.Pending != 0 {
		t.Errorf("an approval in progress counts as pending: %+v", list)
	}
	store.now = func() time.Time { return time.Now().Add(accessRequestApprovalLease + time.Minute) }
	rec = srv.do(t, srv.admin(t), "GET", "/api/v1/placement/admin/requests", "")
	decodeBody(t, rec, &list)
	if list.Pending != 1 || len(list.Requests) != 1 || list.Requests[0].Status != accessRequestPending {
		t.Errorf("a stale approval was not released: %+v", list)
	}
}

// Text from requesters may not carry bidirectional overrides or other
// invisible formatting characters.
func TestAccessRequestRefusesFormatCharacters(t *testing.T) {
	srv := newRequestsServer(t)
	srv.placementOnboard.requestIdentityLimiter = NewLoginRateLimiter(1000, 1000)
	srv.placementOnboard.requestAddressLimiter = NewLoginRateLimiter(1000, 1000)
	newbie := srv.placementSession(t, requesterIdentity)
	for _, body := range []string{
		`{"note":"approve me \u202egnp.exe"}`,
		`{"note":"zero\u200bwidth"}`,
		`{"note":"isolate \u2066x\u2069"}`,
		`{"note":"\ufeffbom"}`,
		`{"projects":["Phys\u200dics"]}`,
	} {
		mustStatus(t, srv.do(t, newbie, "POST", "/api/v1/placement/me/request", body), http.StatusBadRequest, body)
	}
	if r := srv.stored(t, requesterIdentity); r != nil {
		t.Errorf("stored %+v", r)
	}
	// Ordinary non-ASCII text is fine.
	mustStatus(t, srv.do(t, newbie, "POST", "/api/v1/placement/me/request", `{"note":"Ünïcødé — 日本語"}`), http.StatusCreated, "plain text")
}

// Behind a proxy this server was not told about, every request comes from
// the proxy's address; limiting by it would make every user share one
// budget. The per-identity limit still applies.
func TestAccessRequestAddressLimitNeedsARealAddress(t *testing.T) {
	srv := newRequestsServer(t)
	from := func(c *http.Cookie, addr, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/v1/placement/me/request", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.RemoteAddr = addr
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < accessRequestAddressBurst+5; i++ {
		c := srv.placementSession(t, fmt.Sprintf("p%d@idp.example", i))
		mustStatus(t, from(c, "10.1.2.3:4444", `{}`), http.StatusCreated, fmt.Sprintf("identity %d from the proxy", i))
	}
	// The identity limit is still there.
	c := srv.placementSession(t, "busy@idp.example")
	for i := 0; i < accessRequestIdentityBurst; i++ {
		from(c, "10.1.2.3:4444", `{}`)
	}
	mustStatus(t, from(c, "10.1.2.3:4444", `{}`), http.StatusTooManyRequests, "past the identity limit")
}

func TestAccessRequestApproveRefusesPastExpiry(t *testing.T) {
	srv := newRequestsServer(t)
	id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
	for _, exp := range []string{`"2001-01-01T00:00:00Z"`, "978307200"} {
		rec := srv.do(t, srv.admin(t), "POST", approvePath(id), `{"account":"newbie@ap.example","expires_at":`+exp+`}`)
		mustStatus(t, rec, http.StatusBadRequest, "expiry "+exp)
	}
	if srv.fake.editCount() != 0 {
		t.Error("a past expiry reached PLACEMENT_EDIT")
	}
}

// Somebody whose mapping expired is already in the directory, where an
// approval cannot create them again; they are told to ask for an
// extension instead of filing a request nobody can approve.
func TestAccessRequestExpiredIdentityAsksForAnExtension(t *testing.T) {
	srv := newRequestsServer(t)
	srv.fake.users = append(srv.fake.users, htcondor.PlacementUser{
		UserName: "lapsed@idp.example", APUserID: "lapsed@ap.example", Authorized: true,
		MappingExpiration: time.Now().Add(-time.Hour),
	})
	rec := srv.do(t, srv.placementSession(t, "lapsed@idp.example"), "POST", "/api/v1/placement/me/request", `{}`)
	mustStatus(t, rec, http.StatusConflict, "an expired identity")
	if !strings.Contains(rec.Body.String(), "extend") {
		t.Errorf("message = %s", rec.Body.String())
	}
	if r := srv.stored(t, "lapsed@idp.example"); r != nil {
		t.Errorf("stored %+v", r)
	}
}

// Decided and withdrawn requests hold personal data; they are deleted
// once older than the retention. Pending ones are kept.
func TestAccessRequestRetention(t *testing.T) {
	srv := newRequestsServer(t, func(c *Config) { c.PlacementRequestRetention = 48 * time.Hour })
	store := srv.placementOnboard.requests
	ctx := context.Background()
	start := time.Now()
	store.now = func() time.Time { return start }

	mk := func(identity string) int64 {
		r, err := store.create(ctx, placementAccessRequest{Identity: identity, Email: identity})
		if err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	denied := mk("denied@idp.example")
	if _, err := store.decide(ctx, denied, placementAccessDecision{Status: accessRequestDenied, By: "root", Note: "no"}); err != nil {
		t.Fatal(err)
	}
	mk("withdrawn@idp.example")
	if _, err := store.withdraw(ctx, "withdrawn@idp.example"); err != nil {
		t.Fatal(err)
	}
	pending := mk("pending@idp.example")

	store.now = func() time.Time { return start.Add(24 * time.Hour) }
	srv.sweepPlacementAccessRequests(ctx)
	if r, _ := store.get(ctx, denied); r == nil {
		t.Fatal("a decision within the retention was deleted")
	}
	store.now = func() time.Time { return start.Add(49 * time.Hour) }
	srv.sweepPlacementAccessRequests(ctx)
	if r, _ := store.get(ctx, denied); r != nil {
		t.Errorf("a denied request past the retention is still there: %+v", r)
	}
	if r, _ := store.latest(ctx, "withdrawn@idp.example"); r != nil {
		t.Errorf("a withdrawn request past the retention is still there: %+v", r)
	}
	if r, _ := store.get(ctx, pending); r == nil || r.Status != accessRequestPending {
		t.Errorf("a pending request was swept: %+v", r)
	}
}
