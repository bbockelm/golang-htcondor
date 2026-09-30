package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/vscode"
)

func appAd(t *testing.T, src string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return ad
}

// TestAppStateDistinguishesWaitingFromBroken is the reason these states
// exist. A queued app and a dead one are identical through the proxy,
// which answers both with 502, and queue latency is the thing most
// likely to make somebody give up on this. It must not also look like a
// failure.
func TestAppStateDistinguishesWaitingFromBroken(t *testing.T) {
	batch := vscode.BatchName("abc123")
	cases := []struct {
		name      string
		ad        string
		wantState string
		wantURL   bool
		detailHas string
	}{
		{
			name:      "idle reads as waiting for a slot",
			ad:        `[ ClusterId = 12; ProcId = 0; JobStatus = 1; JobBatchName = "` + batch + `"; QDate = 1700000000 ]`,
			wantState: appStateWaiting,
			detailHas: "waiting for a slot",
		},
		{
			name:      "running carries somewhere to open",
			ad:        `[ ClusterId = 12; ProcId = 0; JobStatus = 2; JobBatchName = "` + batch + `" ]`,
			wantState: appStateRunning,
			wantURL:   true,
		},
		{
			name:      "held says why",
			ad:        `[ ClusterId = 12; ProcId = 0; JobStatus = 5; JobBatchName = "` + batch + `"; HoldReason = "no such image" ]`,
			wantState: appStateHeld,
			detailHas: "no such image",
		},
		{
			name:      "completed is ended",
			ad:        `[ ClusterId = 12; ProcId = 0; JobStatus = 4; JobBatchName = "` + batch + `" ]`,
			wantState: appStateEnded,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sum, ok := appSummaryFromAd(appAd(t, tc.ad), "alice@example.com")
			if !ok {
				t.Fatal("appSummaryFromAd refused one of our own jobs")
			}
			if sum.State != tc.wantState {
				t.Errorf("state = %q, want %q", sum.State, tc.wantState)
			}
			if tc.wantURL && sum.URL == "" {
				t.Error("a running app has nowhere to open")
			}
			if !tc.wantURL && sum.URL != "" {
				t.Errorf("URL = %q for a %s app; there is nothing to open", sum.URL, sum.State)
			}
			if tc.detailHas != "" && !strings.Contains(sum.Detail, tc.detailHas) {
				t.Errorf("detail = %q, want it to mention %q", sum.Detail, tc.detailHas)
			}
			if sum.ID != "abc123" {
				t.Errorf("id = %q, want it recovered from the batch name", sum.ID)
			}
		})
	}
}

// TestAppSummaryIgnoresOtherJobs: the queue is the registry, so a
// caller's ordinary jobs must not be reported as apps.
func TestAppSummaryIgnoresOtherJobs(t *testing.T) {
	for _, src := range []string{
		`[ ClusterId = 1; ProcId = 0; JobStatus = 2 ]`,
		`[ ClusterId = 1; ProcId = 0; JobStatus = 2; JobBatchName = "my-analysis" ]`,
		`[ ClusterId = 1; ProcId = 0; JobStatus = 2; JobBatchName = "htcondor-api-interactive-session-x" ]`,
	} {
		if _, ok := appSummaryFromAd(appAd(t, src), "alice@example.com"); ok {
			t.Errorf("a job that is not an app was reported as one: %s", src)
		}
	}
}

// TestAppProxyPathEndsInASlash: the app is served by stripping this
// prefix and emits relative URLs, so without the trailing slash every
// asset resolves one path component too high.
func TestAppProxyPathEndsInASlash(t *testing.T) {
	got := appProxyPath(12, 0)
	if !strings.HasSuffix(got, "/") {
		t.Errorf("appProxyPath = %q, which sends relative URLs one level too high", got)
	}
	if !strings.Contains(got, "/proxy/unix/"+vscode.SocketName+"/") {
		t.Errorf("appProxyPath = %q, want it to name the socket", got)
	}
	// It must be a path the proxy router actually accepts.
	rest := strings.TrimPrefix(got, "/api/v1/jobs/12.0/proxy/")
	target, _, err := parseProxyTarget(strings.Split(strings.Trim(rest, "/"), "/"))
	if err != nil {
		t.Fatalf("the proxy router rejects the URL we hand out: %v", err)
	}
	if target.Socket != vscode.SocketName {
		t.Errorf("router parsed socket %q, want %q", target.Socket, vscode.SocketName)
	}
}

// TestAppImagePrecedence: an operator who has pinned an image has
// decided, and this is the seam where that is enforced.
func TestAppImagePrecedence(t *testing.T) {
	operator := &Handler{vscodeImage: "osdf:///chtc/staging/b/alice/code-server.sif"}
	if got := operator.appImage("evil/image:1"); got != "osdf:///chtc/staging/b/alice/code-server.sif" {
		t.Errorf("a caller overrode the operator's image: %q", got)
	}

	open := &Handler{}
	if got := open.appImage("example/code-server:1"); got != "example/code-server:1" {
		t.Errorf("caller image = %q, want it honoured when the operator set none", got)
	}
	if got := open.appImage(""); got != vscode.RecommendedImage {
		t.Errorf("default = %q, want %q", got, vscode.RecommendedImage)
	}
}

func TestAppCreateRequestDefaultsAndValidation(t *testing.T) {
	var req AppCreateRequest
	req.applyDefaults()
	if req.Type != AppTypeCodeServer || req.Cpus < 1 || req.MemoryMB < 1 || req.DiskMB < 1 {
		t.Fatalf("defaults left an unusable request: %+v", req)
	}
	if err := req.validate(); err != nil {
		t.Errorf("the defaults do not validate: %v", err)
	}

	bad := AppCreateRequest{Type: "jupyter"}
	bad.Cpus, bad.MemoryMB, bad.DiskMB = 1, 1, 1
	if err := bad.validate(); err == nil {
		t.Error("an unimplemented app type was accepted")
	}

	// Submit lines that would redefine what the job is are refused, on
	// the same terms as the interactive terminals.
	hostile := AppCreateRequest{Type: AppTypeCodeServer, Cpus: 1, MemoryMB: 1, DiskMB: 1,
		SubmitLines: "executable = /bin/sh"}
	if err := hostile.validate(); err == nil {
		t.Error("submit_lines was allowed to redefine the executable")
	}
}

// TestAppsPathRouting: the collection and a single app are different
// paths, and anything deeper is not an endpoint.
func TestAppsPathRouting(t *testing.T) {
	h := &Handler{}
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPatch, "/api/v1/apps", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/v1/apps/abc123", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/apps/abc123/proxy", http.StatusNotFound},
	} {
		r := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		h.handleAppsPath(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
}
