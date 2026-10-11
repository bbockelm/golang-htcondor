package httpserver

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
)

// limitedBearer is an auth func presenting an IDTOKEN for user@test.domain
// limited to authz (nil: no limits), which the server already knows as
// that user.
func (f *twoOwnerFixture) limitedBearer(t *testing.T, user string, authz []string) func(*http.Request) {
	t.Helper()
	now := time.Now().Unix()
	identity := user + "@test.domain"
	tok, err := security.GenerateJWT(filepath.Dir(f.keyFile), filepath.Base(f.keyFile), identity, "test.domain", now, now+3600, authz)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	if _, err := f.s.tokenCache.Add(tok); err != nil {
		t.Fatalf("caching the bearer: %v", err)
	}
	f.s.tokenCache.MarkValidated(tok, identity)
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

// A share URL acts with no more authorization than its minter's credential
// carried, and no more than downloading or uploading needs: minted by a
// READ-only credential it is refused, minted by one that can write it
// carries READ and WRITE, and the credential that redeems it is limited to
// exactly that.
func TestShareURLsCarryTheMintersAuthorization(t *testing.T) {
	f := twoOwnerScheddServer(t)
	held := fakeschedd.JobAd(3, 0, "alice", 5)
	held.InsertAttr("HoldReasonCode", int64(16)) // waiting for input to be spooled
	f.schedd.AddJobs(held)

	mint := func(path string, auth func(*http.Request)) (int, string) {
		t.Helper()
		w := f.do(t, http.MethodPost, path, "", auth)
		var resp struct {
			URL     string `json:"url"`
			Uploads []struct {
				URL string `json:"url"`
			} `json:"uploads"`
		}
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("POST %s: %v", path, err)
			}
			if len(resp.Uploads) > 0 {
				resp.URL = resp.Uploads[0].URL
			}
		}
		return w.Code, resp.URL
	}
	payloadOf := func(rawURL string, kind shareurl.Kind) *shareurl.Payload {
		t.Helper()
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		p, err := f.s.verifyShareToken(u.Query().Get("t"), kind)
		if err != nil {
			t.Fatalf("minted token does not verify: %v", err)
		}
		return p
	}

	readOnly := f.limitedBearer(t, "alice", []string{"READ"})
	readWrite := f.limitedBearer(t, "alice", []string{"READ", "WRITE"})
	unlimited := f.limitedBearer(t, "alice", nil)

	for _, tc := range []struct {
		path string
		kind shareurl.Kind
	}{
		{"/api/v1/jobs/1.0/output/share", shareurl.KindOutput},
		{"/api/v1/jobs/3.0/input/share", shareurl.KindInput},
	} {
		if code, _ := mint(tc.path, readOnly); code != http.StatusForbidden {
			t.Errorf("POST %s with a READ-only credential: status %d, want 403", tc.path, code)
		}
		for name, auth := range map[string]func(*http.Request){"READ WRITE": readWrite, "unlimited": unlimited} {
			code, u := mint(tc.path, auth)
			if code != http.StatusOK {
				t.Errorf("POST %s with a %s credential: status %d, want 200", tc.path, name, code)
				continue
			}
			if got := payloadOf(u, tc.kind).Authz; !slices.Equal(got, []string{"READ", "WRITE"}) {
				t.Errorf("POST %s with a %s credential: URL carries %v, want [READ WRITE]", tc.path, name, got)
			}
		}
	}

	// Redeeming: a token carrying READ WRITE downloads as its owner,
	// limited to exactly that; one carrying less, or nothing, is refused
	// before anything reaches the schedd.
	redeem := func(authz []string) int {
		t.Helper()
		tok, err := f.s.signShareToken(shareurl.Payload{
			Cluster: 1, Proc: 0, Owner: "alice",
			Exp:  time.Now().Add(time.Minute).Unix(),
			Kind: shareurl.KindOutput, Authz: authz,
		})
		if err != nil {
			t.Fatal(err)
		}
		return f.do(t, http.MethodGet, "/api/v1/share/output?t="+url.QueryEscape(tok), "", func(*http.Request) {}).Code
	}
	if code := redeem([]string{"READ"}); code != http.StatusForbidden {
		t.Errorf("redeeming a READ-only download: status %d, want 403", code)
	}
	if code := redeem(nil); code != http.StatusForbidden {
		t.Errorf("redeeming a download that carries no authorization: status %d, want 403", code)
	}
	if n := len(f.schedd.Transfers()); n != 0 {
		t.Fatalf("%d refused download(s) reached the schedd", n)
	}
	if code := redeem([]string{"READ", "WRITE"}); code != http.StatusOK {
		t.Errorf("redeeming a READ WRITE download: status %d, want 200", code)
	}
	got := f.schedd.Transfers()
	if len(got) != 1 {
		t.Fatalf("schedd saw %d downloads, want 1", len(got))
	}
	if got[0].User != "alice@test.domain" {
		t.Errorf("download ran as %q, want alice@test.domain", got[0].User)
	}
	limits := slices.Sorted(slices.Values(got[0].Limits))
	if !slices.Equal(limits, []string{"READ", "WRITE"}) {
		t.Errorf("download credential limited to %v, want [READ WRITE]", got[0].Limits)
	}
}
