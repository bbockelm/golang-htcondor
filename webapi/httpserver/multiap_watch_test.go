package httpserver

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
)

// Job watches in multi-AP mode: the routes, the share URL's scope, the
// evaluator's source, the change stream and the MCP tools, against an
// in-process hub. The absence rule itself is tested in webapi/multiap
// (watch_test.go) and webapi/jobwatch (multiap_absence_test.go).

func TestMultiAPWatchRoutesAllowlist(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/api/v1/watches/w-1/share", true},
		{http.MethodGet, "/api/v1/watches/w-1/share", false},
		{http.MethodPost, "/api/v1/watches/w-1", false},
		{http.MethodPost, "/api/v1/watches//share", false},
		{http.MethodGet, "/api/v1/share/watch", true},
		{http.MethodHead, "/api/v1/share/watch", true},
		{http.MethodPost, "/api/v1/share/watch", false},
		{http.MethodGet, "/api/v1/jobs/watch", true},
		{http.MethodDelete, "/api/v1/jobs/watch", false},
	} {
		if got := multiAPAllowed(c.method, c.path); got != c.want {
			t.Errorf("multiAPAllowed(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// registerWatch stores a watch for owner directly.
func registerMultiAPWatch(t *testing.T, srv *Server, owner, constraint string) *jobwatch.Watch {
	t.Helper()
	w, err := jobwatch.New(owner, "", constraint, jobwatch.EventDone, "", jobwatch.ModeAll)
	if err != nil {
		t.Fatal(err)
	}
	got, err := srv.jobWatch.Register(context.Background(), w, 0)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestMultiAPWatchEvaluatorReadsTheHub: the server's evaluator follows a
// watch over every AP, tracking the same cluster.proc on two APs as two
// jobs, and never another owner's.
func TestMultiAPWatchEvaluatorReadsTheHub(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry(ap1, ap2)))
	w := registerMultiAPWatch(t, srv, "alice", "ClusterId == 1")
	if _, err := srv.jobWatchEval.CheckOwner(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	all, err := srv.jobWatch.ForOwner(context.Background(), "alice", nil)
	if err != nil || len(all) != 1 || all[0].ID != w.ID {
		t.Fatalf("ForOwner = %v, %v", all, err)
	}
	got := map[string]bool{}
	for _, id := range all[0].Tracked {
		got[id.Schedd] = true
		if id.Cluster != 1 || id.Proc != 0 {
			t.Errorf("tracked %+v", id)
		}
	}
	if len(all[0].Tracked) != 2 || !got[ap1] || !got[ap2] {
		t.Errorf("tracked %+v, want alice's 1.0 on %s and on %s", all[0].Tracked, ap1, ap2)
	}
	if n := srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// TestMultiAPWatchShareURL: a watch URL minted in multi-AP mode names
// every AP inside its HMAC and is redeemed here; one that names none, or
// one AP, is refused, and so is one whose payload was altered.
func TestMultiAPWatchShareURL(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry(ap1, ap2)))
	w := registerMultiAPWatch(t, srv, "alice", "ClusterId == 1")

	rec := doAs(t, srv, "alice", http.MethodPost, "/api/v1/watches/"+w.ID+"/share")
	var minted ShareWatchResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &minted) != nil {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body.String())
	}
	tok := minted.URL[strings.Index(minted.URL, "?t=")+3:]
	p, err := srv.verifyShareToken(tok, shareurl.KindWatch)
	if err != nil || p.Schedd != shareurl.AllAccessPoints || p.Owner != "alice" || p.Watch != w.ID {
		t.Fatalf("minted payload %+v, %v: want every AP, alice, %s", p, err, w.ID)
	}

	if rec := redeemWatch(t, srv, tok); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"watch_id":"`+w.ID) {
		t.Errorf("redeem: %d %s", rec.Code, rec.Body.String())
	}
	for name, s := range map[string]string{"no access point": "", "one access point": ap1} {
		other := shareToken(t, srv, shareurl.Payload{Schedd: s, Kind: shareurl.KindWatch, Watch: w.ID, Authz: []string{}})
		if rec := redeemWatch(t, srv, other); rec.Code != http.StatusForbidden {
			t.Errorf("a watch URL naming %s = %d %s, want 403", name, rec.Code, rec.Body.String())
		}
	}
	// The scope is inside the HMAC: rewriting it breaks the signature.
	enc, sig, _ := strings.Cut(tok, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(enc)
	forged := strings.Replace(string(raw), `"s":"*"`, `"s":""`, 1)
	if forged == string(raw) {
		t.Fatalf("payload %s carries no scope to forge", raw)
	}
	if rec := redeemWatch(t, srv, base64.RawURLEncoding.EncodeToString([]byte(forged))+"."+sig); rec.Code != http.StatusUnauthorized {
		t.Errorf("a forged scope = %d %s, want 401", rec.Code, rec.Body.String())
	}

	// Minting for an identity in another domain is refused.
	if rec := doAs(t, srv, "alice@other.example", http.MethodPost, "/api/v1/watches/"+w.ID+"/share"); rec.Code != http.StatusUnauthorized {
		t.Errorf("mint as alice@other.example = %d %s, want 401", rec.Code, rec.Body.String())
	}
}

// TestSingleAPRefusesAMultiAPWatchURL: the other direction.
func TestSingleAPRefusesAMultiAPWatchURL(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "d"
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.setupRoutes()
	w := registerMultiAPWatch(t, srv, "alice", "ClusterId == 1")
	tok := shareToken(t, srv, shareurl.Payload{Schedd: shareurl.AllAccessPoints, Kind: shareurl.KindWatch, Watch: w.ID, Authz: []string{}})
	if rec := redeemWatch(t, srv, tok); rec.Code != http.StatusForbidden {
		t.Errorf("a multi-AP watch URL on a single-AP server = %d %s, want 403", rec.Code, rec.Body.String())
	}
}

func redeemWatch(t *testing.T, srv *Server, tok string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/share/watch?wait=0&t="+url.QueryEscape(tok), nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// TestMultiAPJobsWatchStream: /api/v1/jobs/watch streams the caller's
// own transitions from the hub's feed, each named by its complete id.
func TestMultiAPJobsWatchStream(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, multiAPHub(t), multiaptest.NewRegistry(ap1, ap2)))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/jobs/watch", nil)
	req.Header.Set("X-Remote-User", "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	hubRow := func(schedd, user string, status int64) string {
		ad := classad.New()
		ad.InsertAttrString("ScheddName", schedd)
		ad.InsertAttrString("User", user)
		ad.InsertAttrString("Owner", strings.Split(user, "@")[0])
		ad.InsertAttr("ClusterId", int64(1))
		ad.InsertAttr("ProcId", int64(0))
		ad.InsertAttr("JobStatus", status)
		return ad.MarshalOld()
	}
	// Wait for the subscription before publishing.
	lines := bufio.NewScanner(resp.Body)
	for lines.Scan() && !strings.HasPrefix(lines.Text(), "event: ") {
	}
	feed := srv.jobWatchFeed
	for _, ev := range []jobwatch.WatchEvent{
		{Kind: jobwatch.WatchUpsert, Key: "k-bob", AdText: hubRow(ap1, "bob@d", 1)},
		{Kind: jobwatch.WatchUpsert, Key: "k-bob", AdText: hubRow(ap1, "bob@d", 2)},
		{Kind: jobwatch.WatchUpsert, Key: "k-alice", AdText: hubRow(ap2, "alice@d", 1)},
		{Kind: jobwatch.WatchUpsert, Key: "k-alice", AdText: hubRow(ap2, "alice@d", 2)},
	} {
		feed.Apply(ev)
	}
	for lines.Scan() {
		line := lines.Text()
		if !strings.HasPrefix(line, "data: ") || !strings.Contains(line, `"key"`) {
			continue
		}
		if !strings.Contains(line, `"1.0@`+ap2+`"`) {
			t.Fatalf("first event %s: want alice's 1.0@%s (bob's comes first on the feed and must not appear)", line, ap2)
		}
		return
	}
	t.Fatalf("stream ended: %v", lines.Err())
}

// TestMultiAPWatchMCPTools: watch_jobs over MCP in multi-AP mode
// registers a watch the hub evaluator follows across APs, reports jobs
// with their AP, and refuses an identity in another domain.
func TestMultiAPWatchMCPTools(t *testing.T) {
	hub := multiAPHub(t)
	srv, err := NewServer(Config{
		MultiAP:                  MultiAPConfig{ScheddConstraint: `regexp("^ap", Name)`, service: multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2))},
		Logger:                   newTestLogger(t),
		EnableMCP:                true,
		OAuth2DBPath:             t.TempDir() + "/oauth2.db",
		OAuth2Issuer:             "http://localhost:8080",
		UserHeader:               "X-Remote-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           writeTestSigningKey(t),
		TrustDomain:              "test.domain",
		UIDDomain:                "d",
		// create_watch_url mints URLs under it.
		HTTPBaseURL: "https://api.example.org",
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func(user, tool string, args map[string]any) (map[string]any, string) {
		t.Helper()
		return mcpCallAs(t, srv, user, tool, args)
	}

	sc, text := call("alice", "watch_jobs", map[string]any{"constraint": "ClusterId == 1", "event": "done", "mode": "any"})
	if sc == nil {
		t.Fatalf("watch_jobs: %s", text)
	}
	id, _ := sc["watch_id"].(string)
	hub.DeleteJob(ap2, 1, 0)
	hub.PutHistory(ap2, "alice@d", 1, 0, time.Now().Unix())
	sc, text = call("alice", "check_watches", map[string]any{"watch_id": id})
	if sc == nil || sc["new_count"] != float64(1) {
		t.Fatalf("check_watches: %v %s", sc, text)
	}
	if !strings.Contains(text, "1.0@"+ap2) || strings.Contains(text, "1.0@"+ap1) {
		t.Errorf("check_watches text does not name only 1.0@%s: %s", ap2, text)
	}
	sc, text = call("alice", "create_watch_url", map[string]any{"watch_id": id})
	if sc == nil {
		t.Fatalf("create_watch_url: %s", text)
	}
	minted, _ := sc["url"].(string)
	p, err := srv.verifyShareToken(minted[strings.Index(minted, "?t=")+3:], shareurl.KindWatch)
	if err != nil || p.Schedd != shareurl.AllAccessPoints {
		t.Errorf("create_watch_url payload %+v, %v: want every AP", p, err)
	}
	if sc, text := call("alice@other.example", "watch_jobs", map[string]any{"constraint": "ClusterId == 1"}); sc != nil {
		t.Errorf("watch_jobs as alice@other.example was served: %s", text)
	}
	if n := srv.Handler.mcpServer.MultiAPScheddCalls(); n != 0 {
		t.Errorf("getSchedd called %d times", n)
	}
}

// mcpCallAs calls an MCP tool on srv as user, with a credential,
// returning its structured content (nil on a tool error) and its text.
func mcpCallAs(t *testing.T, srv *Server, user, tool string, args map[string]any) (map[string]any, string) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args})
	// A credential to present to an AP a call is routed to; the fake
	// schedds do not accept it, but they count the connection.
	sec, err := htcondor.NewClientSecurityConfigWithConfig(context.Background(), nil, "x.y.z", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	sec.SecurityTag = user + "-tag"
	ctx := htcondor.WithAuthenticatedUser(htcondor.WithSecurityConfig(context.Background(), sec), user)
	out := srv.Handler.mcpServer.HandleMessage(ctx, &mcpserver.MCPMessage{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params})
	b, _ := json.Marshal(out)
	var env struct {
		Result struct {
			IsError           bool           `json:"isError"`
			StructuredContent map[string]any `json:"structuredContent"`
			Content           []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *mcpserver.MCPError `json:"error"`
	}
	_ = json.Unmarshal(b, &env)
	text := ""
	for _, c := range env.Result.Content {
		text += c.Text
	}
	if env.Error != nil {
		text += env.Error.Message
	}
	if env.Result.IsError || env.Error != nil {
		return nil, text
	}
	return env.Result.StructuredContent, text
}
