package httpserver

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/jupytertunnel"
)

// jupyterFakeSchedd is a queue for the JupyterLab handlers: it hands out
// cluster ids, keeps what was spooled, and answers status queries.
type jupyterFakeSchedd struct {
	mu          sync.Mutex
	nextCluster int
	status      map[int]int // cluster -> JobStatus
	spooled     map[int]fs.FS
	constraints []string
	submitted   []string
	submitErr   error
	spoolErr    error
}

func newJupyterFakeSchedd() *jupyterFakeSchedd {
	return &jupyterFakeSchedd{nextCluster: 4242, status: map[int]int{}, spooled: map[int]fs.FS{}}
}

func (f *jupyterFakeSchedd) SubmitRemote(_ context.Context, submitFile string) (int, []*classad.ClassAd, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.submitErr != nil {
		return 0, nil, f.submitErr
	}
	f.submitted = append(f.submitted, submitFile)
	cluster := f.nextCluster
	f.nextCluster++
	f.status[cluster] = 1
	ad := classad.New()
	_ = ad.Set("ClusterId", int64(cluster))
	_ = ad.Set("ProcId", int64(0))
	return cluster, []*classad.ClassAd{ad}, nil
}

func (f *jupyterFakeSchedd) SpoolJobFilesFromFS(_ context.Context, procAds []*classad.ClassAd, fsys fs.FS) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.spoolErr != nil {
		return f.spoolErr
	}
	cluster, _ := procAds[0].EvaluateAttrInt("ClusterId")
	f.spooled[int(cluster)] = fsys
	return nil
}

var jupyterFakeClusterTerm = regexp.MustCompile(`ClusterId == (\d+)`)

func (f *jupyterFakeSchedd) QueryWithOptions(_ context.Context, constraint string, _ *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.constraints = append(f.constraints, constraint)
	var out []*classad.ClassAd
	for _, m := range jupyterFakeClusterTerm.FindAllStringSubmatch(constraint, -1) {
		cluster, _ := strconv.Atoi(m[1])
		status, ok := f.status[cluster]
		if !ok {
			continue
		}
		ad := classad.New()
		_ = ad.Set("ClusterId", int64(cluster))
		_ = ad.Set("ProcId", int64(0))
		_ = ad.Set("JobStatus", int64(status))
		out = append(out, ad)
	}
	return out, &htcondor.PageInfo{}, nil
}

func (f *jupyterFakeSchedd) setStatus(cluster, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[cluster] = status
}

func (f *jupyterFakeSchedd) token(t *testing.T, cluster int) string {
	t.Helper()
	f.mu.Lock()
	fsys := f.spooled[cluster]
	f.mu.Unlock()
	if fsys == nil {
		t.Fatalf("nothing was spooled for cluster %d", cluster)
	}
	b, err := fs.ReadFile(fsys, "jupyter-token")
	if err != nil {
		t.Fatalf("spooled token: %v", err)
	}
	return string(b)
}

// queriedClusterZero reports whether any status query asked about cluster
// 0, which no job has.
func (f *jupyterFakeSchedd) queriedClusterZero() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.constraints {
		for _, m := range jupyterFakeClusterTerm.FindAllStringSubmatch(c, -1) {
			if m[1] == "0" {
				return true
			}
		}
	}
	return false
}

// newJupyterRestartHandler is one API server process: a fresh Handler, and
// so a fresh registry, over the application database at dbPath.
func newJupyterRestartHandler(t *testing.T, dbPath string, schedd *jupyterFakeSchedd) *Handler {
	t.Helper()
	db, err := appdb.Open(dbPath)
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := taggingHandler(t)
	h.db = db
	h.jupyterScheddOverride = schedd
	return h
}

// stubJupyterHelper stands in for the embedded helper binary, which a
// unit-test build does not carry.
func stubJupyterHelper(t *testing.T) {
	t.Helper()
	prev := jupyterHelperBytesFor
	jupyterHelperBytesFor = func(string, string) ([]byte, error) { return []byte("#!/bin/true\n"), nil }
	t.Cleanup(func() { jupyterHelperBytesFor = prev })
}

func jupyterRequest(t *testing.T, h *Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), method, path, body)
	r.Header.Set("X-Test-User", "alice")
	w := httptest.NewRecorder()
	h.handleJupyterPath(w, r)
	return w
}

func createJupyterSession(t *testing.T, h *Handler) JupyterCreateResponse {
	t.Helper()
	w := jupyterRequest(t, h, http.MethodPost, "/api/v1/jupyter/instances", strings.NewReader(`{}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created JupyterCreateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return created
}

func listJupyterSessions(t *testing.T, h *Handler) []JupyterInstanceSummary {
	t.Helper()
	w := jupyterRequest(t, h, http.MethodGet, "/api/v1/jupyter/instances", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Instances []JupyterInstanceSummary `json:"instances"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return out.Instances
}

// A session created by one process is still listed, still answers GET, and
// still serves requests after the API server restarts.
//
// The row was written before the job was submitted and never learned the
// cluster id, so the next process adopted every session as cluster 0, asked
// the schedd about a job that does not exist, and reaped it on the first
// list. The helper's redial then found nothing to attach to and ended the
// job.
func TestJupyterSessionSurvivesARestartWithItsJob(t *testing.T) {
	stubJupyterHelper(t)
	dbPath := filepath.Join(t.TempDir(), "app.db")
	schedd := newJupyterFakeSchedd()

	// --- the first process creates the session ---
	first := newJupyterRestartHandler(t, dbPath, schedd)
	created := createJupyterSession(t, first)
	cluster, err := strconv.Atoi(created.ClusterID)
	if err != nil || cluster <= 0 {
		t.Fatalf("create returned cluster %q", created.ClusterID)
	}
	schedd.setStatus(cluster, 2) // Running

	row, err := first.jupyterSessionStore().Get(context.Background(), created.InstanceID)
	if err != nil {
		t.Fatalf("stored session: %v", err)
	}
	if row.ClusterID != cluster {
		t.Errorf("stored cluster = %d, want %d; a restarted server cannot find this session's job", row.ClusterID, cluster)
	}

	// The helper dials the first process with the token spooled into the
	// job, and is handed the one it will use next.
	helper := startJupyterTestHelper(t, created.InstanceID, schedd.token(t, cluster))
	srv1 := httptest.NewServer(http.HandlerFunc(first.handleJupyterPath))
	next := helper.connect(t, srv1.URL)
	if got := proxyThrough(t, first, created.InstanceID); !strings.Contains(got, jupyterTestSentinel) {
		t.Fatalf("proxied request before the restart: %q", got)
	}
	// The token for the next dial has to last until the next restart,
	// not the thirty minutes a first dial gets.
	if exp := jupyterTokenExpiry(t, next); time.Until(exp) < 12*time.Hour {
		t.Errorf("the helper's next token expires in %s; a restart after that refuses the helper and ends the session",
			time.Until(exp).Round(time.Minute))
	}

	// --- the first process goes away; its tunnel with it ---
	reg1, _ := first.getOrCreateJupyterRegistry()
	reg1.CloseInstance(created.InstanceID)
	helper.waitDisconnected(t)
	srv1.Close()

	// --- a new process over the same database ---
	second := newJupyterRestartHandler(t, dbPath, schedd)

	// (a) still listed, with its job.
	list := listJupyterSessions(t, second)
	if len(list) != 1 {
		t.Fatalf("listed %d sessions after the restart, want 1 (queried: %v)", len(list), schedd.constraints)
	}
	if list[0].InstanceID != created.InstanceID {
		t.Errorf("listed %q, want %q", list[0].InstanceID, created.InstanceID)
	}
	if list[0].ClusterID != created.ClusterID {
		t.Errorf("listed cluster %q, want %q", list[0].ClusterID, created.ClusterID)
	}
	if list[0].JobStatus != 2 {
		t.Errorf("listed job status %d, want 2 (Running)", list[0].JobStatus)
	}
	if list[0].Image == "" {
		t.Error("the session's image was lost across the restart")
	}

	// (b) GET answers for it.
	w := jupyterRequest(t, second, http.MethodGet, "/api/v1/jupyter/instances/"+created.InstanceID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET after the restart: %d %s", w.Code, w.Body.String())
	}
	var got JupyterInstanceSummary
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if got.ClusterID != created.ClusterID {
		t.Errorf("GET cluster %q, want %q", got.ClusterID, created.ClusterID)
	}
	if schedd.queriedClusterZero() {
		t.Errorf("the schedd was asked about cluster 0: %v", schedd.constraints)
	}

	// (c) the helper comes back with its rolled token and requests flow.
	srv2 := httptest.NewServer(http.HandlerFunc(second.handleJupyterPath))
	defer srv2.Close()
	_ = helper.connect(t, srv2.URL)
	if got := proxyThrough(t, second, created.InstanceID); !strings.Contains(got, jupyterTestSentinel) {
		t.Errorf("proxied request after the restart: %q", got)
	}
}

// A row that never learned its job is dropped at adoption, and nothing asks
// the schedd about cluster 0.
//
// Create records the cluster before it spools the helper, so such a row is
// one whose job never got a helper: nothing will ever dial back for it.
func TestJupyterSessionWithoutAJobIsNotAdopted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "app.db")
	schedd := newJupyterFakeSchedd()

	// The first half of create -- the row is written, the job is not --
	// and then the process dies.
	first := newJupyterRestartHandler(t, dbPath, schedd)
	reg, err := first.getOrCreateJupyterRegistry()
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	id, _, err := reg.CreateInstance(jupytertunnel.CreateInstanceOptions{Owner: "alice"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	nonce, _ := reg.PendingNonce(id)
	store := first.jupyterSessionStore()
	if err := store.Put(context.Background(), jupyterSessionRow{
		InstanceID: id, Owner: "alice", NextNonce: nonce,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	second := newJupyterRestartHandler(t, dbPath, schedd)
	if list := listJupyterSessions(t, second); len(list) != 0 {
		t.Errorf("listed %d sessions; a session with no job can never connect", len(list))
	}
	if schedd.queriedClusterZero() {
		t.Errorf("the schedd was asked about cluster 0: %v", schedd.constraints)
	}
	if _, err := second.jupyterSessionStore().Get(context.Background(), id); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("the row with no job is still stored (err=%v); every later restart would trip on it", err)
	}
}

// An instance whose cluster is not known is not one whose job has gone.
// Querying for cluster 0 finds nothing, and the list and detail handlers
// read nothing as dead.
func TestJupyterInstanceWithoutAClusterIsNotReaped(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "app.db")
	schedd := newJupyterFakeSchedd()
	h := newJupyterRestartHandler(t, dbPath, schedd)
	reg, err := h.getOrCreateJupyterRegistry()
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, err := reg.AdoptInstance("00112233445566778899aabbccddeeff", "alice", time.Now(),
		map[string]string{"cluster_id": "0"}, false); err != nil {
		t.Fatalf("AdoptInstance: %v", err)
	}

	if list := listJupyterSessions(t, h); len(list) != 1 {
		t.Errorf("listed %d sessions, want 1: the list reaped an instance it could not look up", len(list))
	}
	w := jupyterRequest(t, h, http.MethodGet, "/api/v1/jupyter/instances/00112233445566778899aabbccddeeff", nil)
	if w.Code != http.StatusOK {
		t.Errorf("GET: %d %s", w.Code, w.Body.String())
	}
	if schedd.queriedClusterZero() {
		t.Errorf("the schedd was asked about cluster 0: %v", schedd.constraints)
	}
}

// A create that fails after the row is written leaves no row behind, or the
// next process adopts a session that can never connect.
func TestJupyterFailedCreateLeavesNoStoredSession(t *testing.T) {
	for _, tc := range []struct {
		name    string
		breakIt func(*jupyterFakeSchedd)
	}{
		{"submit", func(f *jupyterFakeSchedd) { f.submitErr = errors.New("schedd said no") }},
		{"spool", func(f *jupyterFakeSchedd) { f.spoolErr = errors.New("spool failed") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubJupyterHelper(t)
			schedd := newJupyterFakeSchedd()
			tc.breakIt(schedd)
			h := newJupyterRestartHandler(t, filepath.Join(t.TempDir(), "app.db"), schedd)

			w := jupyterRequest(t, h, http.MethodPost, "/api/v1/jupyter/instances", strings.NewReader(`{}`))
			if w.Code != http.StatusBadGateway {
				t.Fatalf("create: %d %s, want 502", w.Code, w.Body.String())
			}
			rows, err := h.jupyterSessionStore().Live(context.Background(), time.Now())
			if err != nil {
				t.Fatalf("Live: %v", err)
			}
			if len(rows) != 0 {
				t.Errorf("%d stored sessions after a failed create, want 0", len(rows))
			}
		})
	}
}

const jupyterTestSentinel = "fake-jupyter-OK"

// jupyterTestHelper runs the real helper loop in process against an HTTP
// server on a Unix socket standing in for JupyterLab.
type jupyterTestHelper struct {
	instanceID string
	socket     string
	tokenPath  string

	mu   sync.Mutex
	done chan error
}

func startJupyterTestHelper(t *testing.T, instanceID, token string) *jupyterTestHelper {
	t.Helper()
	// Under /tmp: a sun_path is about a hundred bytes, and t.TempDir on
	// macOS is most of that already.
	dir, err := os.MkdirTemp("/tmp", "jrt")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "j.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//nolint:gosec // G705: a test server echoing its own path back as text/plain
			_, _ = fmt.Fprintf(w, "%s path=%s", jupyterTestSentinel, r.URL.Path)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return &jupyterTestHelper{instanceID: instanceID, socket: sock, tokenPath: tokenPath}
}

// connect dials baseURL with the token on file and waits until the server
// has handed over the next one, which is when the connection is fully up.
// Returns that next token.
func (h *jupyterTestHelper) connect(t *testing.T, baseURL string) string {
	t.Helper()
	next, err := h.tryConnect(t, baseURL)
	if err != nil {
		t.Fatalf("the helper's dial ended before it was handed a token: %v", err)
	}
	return next
}

// tryConnect is connect, returning the error of a dial that was refused.
func (h *jupyterTestHelper) tryConnect(t *testing.T, baseURL string) (string, error) {
	t.Helper()
	tok, err := os.ReadFile(h.tokenPath)
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	next := make(chan string, 1)
	h.mu.Lock()
	h.done = done
	h.mu.Unlock()
	go func() {
		done <- jupytertunnel.RunHelperTunnel(ctx, jupytertunnel.HelperConfig{
			UpstreamURL: strings.Replace(baseURL, "http://", "ws://", 1) +
				"/api/v1/jupyter/instances/" + h.instanceID + "/tunnel",
			Token:       strings.TrimSpace(string(tok)),
			SocketPath:  h.socket,
			TokenPath:   h.tokenPath,
			OnNextToken: func(tok string) { next <- tok },
		})
	}()
	select {
	case tok := <-next:
		return tok, nil
	case err := <-done:
		if err == nil {
			err = errors.New("the tunnel closed before a token was handed over")
		}
		return "", err
	case <-time.After(10 * time.Second):
		t.Fatal("the helper was never handed its next token")
	}
	return "", nil
}

// useToken puts tok on file as the token the helper dials with next.
func (h *jupyterTestHelper) useToken(t *testing.T, tok string) {
	t.Helper()
	if err := os.WriteFile(h.tokenPath, []byte(tok), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
}

// jupyterTokenExpiry reads the expiry out of a tunnel token: base64url of
// a 16-byte instance id, then the expiry as big-endian Unix seconds.
func jupyterTokenExpiry(t *testing.T, tok string) time.Time {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) < 24 {
		t.Fatalf("not a tunnel token (%d bytes): %v", len(raw), err)
	}
	return time.Unix(int64(binary.BigEndian.Uint64(raw[16:24])), 0) //nolint:gosec // test decode of a value the server wrote
}

func (h *jupyterTestHelper) waitDisconnected(t *testing.T) {
	t.Helper()
	h.mu.Lock()
	done := h.done
	h.mu.Unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the helper never noticed its tunnel close")
	}
}

func proxyThrough(t *testing.T, h *Handler, instanceID string) string {
	t.Helper()
	w := jupyterRequest(t, h, http.MethodGet,
		"/api/v1/jupyter/instances/"+instanceID+"/proxy/lab", nil)
	if w.Code != http.StatusOK {
		return fmt.Sprintf("status %d: %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// Create stamps the cluster id on an instance the registry has already
// published, so list and GET can be reading it at that moment. Run with
// -race: the cluster id was written to a bare map, unsynchronized.
func TestJupyterCreateCompletesWhileListAndGetRead(t *testing.T) {
	stubJupyterHelper(t)
	schedd := newJupyterFakeSchedd()
	h := newJupyterRestartHandler(t, filepath.Join(t.TempDir(), "app.db"), schedd)
	reg, err := h.getOrCreateJupyterRegistry()
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	const creates = 20
	done := make(chan struct{})
	var readers sync.WaitGroup
	for range 2 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				_ = jupyterRequest(t, h, http.MethodGet, "/api/v1/jupyter/instances", nil)
				for _, inst := range reg.ListByOwner("alice") {
					_ = jupyterRequest(t, h, http.MethodGet, "/api/v1/jupyter/instances/"+inst.ID, nil)
				}
			}
		}()
	}
	for range creates {
		w := jupyterRequest(t, h, http.MethodPost, "/api/v1/jupyter/instances", strings.NewReader(`{}`))
		if w.Code != http.StatusCreated {
			t.Errorf("create: %d %s", w.Code, w.Body.String())
		}
	}
	close(done)
	readers.Wait()

	if got := len(listJupyterSessions(t, h)); got != creates {
		t.Errorf("listed %d sessions, want %d", got, creates)
	}
}
