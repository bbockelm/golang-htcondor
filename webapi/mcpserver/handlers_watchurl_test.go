package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
	"github.com/bbockelm/golang-htcondor/webapi/watchpoll"
)

// watchURLServer is watchServer plus what minting a URL needs: a signer
// derived from a pool key, and the REST daemon's address.
func watchURLServer(t *testing.T) *Server {
	t.Helper()
	s := watchServer(t, &stubSource{})
	keyPath := filepath.Join(t.TempDir(), "POOL")
	if err := os.WriteFile(keyPath, []byte("test pool signing key"), 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	key, err := shareurl.KeyFromSigningKeyFile(keyPath)
	if err != nil {
		t.Fatalf("derive share key: %v", err)
	}
	signer, err := shareurl.NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	s.shareSigner = signer
	s.signingKeyPath = keyPath
	s.httpBaseURL = "https://ap.example.org"
	return s
}

func registerFor(t *testing.T, s *Server, owner string) *jobwatch.Watch {
	t.Helper()
	w, err := jobwatch.New(owner, "done-42", "ClusterId == 42", jobwatch.EventDone, "", jobwatch.ModeAll)
	if err != nil {
		t.Fatalf("jobwatch.New: %v", err)
	}
	w, err = s.jobWatch.Register(context.Background(), w, time.Hour)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return w
}

func structuredOfResult(t *testing.T, result interface{}) map[string]interface{} {
	t.Helper()
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T, want a map", result)
	}
	sc, ok := m["structuredContent"].(map[string]interface{})
	if !ok {
		t.Fatalf("structuredContent is %T", m["structuredContent"])
	}
	return sc
}

// The minted URL must be one this deployment can actually redeem: the
// right endpoint, and a token that verifies as a watch token naming that
// watch. A URL that looks right and verifies as nothing is the failure
// worth catching here.
func TestCreateWatchURLMintsARedeemableURL(t *testing.T) {
	s := watchURLServer(t)
	w := registerFor(t, s, "alice")

	res, err := s.toolCreateWatchURL(aliceCtx(), map[string]interface{}{"watch_id": w.ID})
	if err != nil {
		t.Fatalf("toolCreateWatchURL: %v", err)
	}
	sc := structuredOfResult(t, res)

	url, _ := sc["url"].(string)
	const prefix = "https://ap.example.org/api/v1/share/watch?t="
	if !strings.HasPrefix(url, prefix) {
		t.Fatalf("url %q does not point at the redeem endpoint", url)
	}
	got, err := s.shareSigner.Verify(strings.TrimPrefix(url, prefix), shareurl.KindWatch)
	if err != nil {
		t.Fatalf("this server could not verify its own URL: %v", err)
	}
	if got.Watch != w.ID || got.Owner != "alice" {
		t.Fatalf("token names watch %q owner %q, want %q/alice", got.Watch, got.Owner, w.ID)
	}

	// A poller sizes its client timeout from these, so they have to be
	// the endpoint's real numbers rather than something restated here.
	if sc["max_wait_seconds"] != int(watchpoll.MaxWait.Seconds()) ||
		sc["default_wait_seconds"] != int(watchpoll.DefaultWait.Seconds()) {
		t.Fatalf("advertised waits %v/%v do not match the endpoint's %v/%v",
			sc["max_wait_seconds"], sc["default_wait_seconds"],
			int(watchpoll.MaxWait.Seconds()), int(watchpoll.DefaultWait.Seconds()))
	}
}

// Minting is owner-scoped: the URL is redeemed as the token's owner, so
// naming somebody else's watch has to be refused at mint time.
func TestCreateWatchURLRefusesAnotherOwnersWatch(t *testing.T) {
	s := watchURLServer(t)
	w := registerFor(t, s, "bob")

	if _, err := s.toolCreateWatchURL(aliceCtx(), map[string]interface{}{"watch_id": w.ID}); err == nil {
		t.Fatal("alice minted a URL for bob's watch")
	}
}

func TestCreateWatchURLRefusesAnUnknownWatch(t *testing.T) {
	s := watchURLServer(t)
	_, err := s.toolCreateWatchURL(aliceCtx(), map[string]interface{}{"watch_id": "no-such-watch"})
	if err == nil {
		t.Fatal("an unknown watch id was accepted")
	}
	if !strings.Contains(err.Error(), "watch_jobs") {
		t.Fatalf("the refusal does not say how to get a watch id: %v", err)
	}
}

func TestCreateWatchURLRequiresAWatchID(t *testing.T) {
	s := watchURLServer(t)
	if _, err := s.toolCreateWatchURL(aliceCtx(), map[string]interface{}{}); err == nil {
		t.Fatal("a missing watch_id was accepted")
	}
}

// The two deployment gaps have different fixes, so the refusals must
// name which one is missing.
func TestCreateWatchURLNamesWhatIsMissing(t *testing.T) {
	s := watchURLServer(t)
	w := registerFor(t, s, "alice")
	args := map[string]interface{}{"watch_id": w.ID}

	s.shareSigner = nil
	_, err := s.toolCreateWatchURL(aliceCtx(), args)
	if err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("without a signer, error = %v; want one naming the signing key", err)
	}

	s = watchURLServer(t)
	w = registerFor(t, s, "alice")
	s.httpBaseURL = "  "
	_, err = s.toolCreateWatchURL(aliceCtx(), map[string]interface{}{"watch_id": w.ID})
	if err == nil || !strings.Contains(err.Error(), "HTTP_API_BASE_URL") {
		t.Fatalf("without a base URL, error = %v; want one naming HTTP_API_BASE_URL", err)
	}
}

// A watch URL grants a read of one watch, so it must not be classified
// read-only for the scope gate nor left unannotated.
func TestCreateWatchURLIsAnnotated(t *testing.T) {
	if IsReadOnlyTool("create_watch_url") {
		t.Fatal("create_watch_url is classified read-only; it mints a capability")
	}
	ann, ok := toolAnnotations["create_watch_url"]
	if !ok {
		t.Fatal("create_watch_url has no annotation")
	}
	if ann.ReadOnlyHint {
		t.Fatal("create_watch_url is annotated read-only")
	}
}
