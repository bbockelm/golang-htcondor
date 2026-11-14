// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/siteapps"
)

// What a caller types becomes part of the URL this server fetches, so
// the patterns are the boundary rather than a convenience.
func TestParseGitHubSourceAcceptsWhatIsOnTheClipboard(t *testing.T) {
	for _, in := range []string{
		"bbockelm/htcondor-site-app-template",
		"  bbockelm/htcondor-site-app-template  ",
		"https://github.com/bbockelm/htcondor-site-app-template",
		"https://github.com/bbockelm/htcondor-site-app-template/",
		"github.com/bbockelm/htcondor-site-app-template.git",
	} {
		got, err := parseGitHubSource(in, "", "")
		if err != nil {
			t.Errorf("parseGitHubSource(%q) = %v", in, err)
			continue
		}
		if got.Slug() != "bbockelm/htcondor-site-app-template" {
			t.Errorf("parseGitHubSource(%q) slug = %q", in, got.Slug())
		}
	}
}

func TestParseGitHubSourceRefuses(t *testing.T) {
	cases := []struct {
		name             string
		repo, tag, name2 string
	}{
		{"no slash", "bbockelm", "", ""},
		{"empty owner", "/repo", "", ""},
		{"empty repo", "owner/", "", ""},
		{"a URL that is not github", "https://evil.example/owner/repo", "", ""},
		{"an owner with a slash in it", "a/b/c", "", ""},
		{"traversal in the tag", "o/r", "../../secrets", ""},
		{"a slash in the tag", "o/r", "release/1.0", ""},
		{"a newline in the tag", "o/r", "v1\nHost: evil", ""},
		{"traversal in the asset", "o/r", "v1", "../../etc/passwd"},
		{"an owner that is not a name", "o w/r", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := parseGitHubSource(c.repo, c.tag, c.name2); err == nil {
				t.Fatalf("parseGitHubSource(%q,%q,%q) = %+v, want an error",
					c.repo, c.tag, c.name2, got)
			}
		})
	}
}

// "latest" is a question. What gets recorded has to be the answer, or
// the update check compares a row against itself forever.
func TestParseGitHubSourceTreatsLatestAsUnset(t *testing.T) {
	for _, tag := range []string{"", "latest", "LATEST", " Latest "} {
		got, err := parseGitHubSource("o/r", tag, "")
		if err != nil {
			t.Fatalf("parseGitHubSource(tag=%q) = %v", tag, err)
		}
		if got.Tag != "" {
			t.Errorf("parseGitHubSource(tag=%q).Tag = %q, want empty", tag, got.Tag)
		}
	}
}

// The redirect allow-list. A release asset lands on a storage host, so
// the suffix is what is pinned -- but only as a suffix, or
// `githubusercontent.com.evil.example` would pass.
func TestGitHubHostAllowed(t *testing.T) {
	for _, host := range []string{
		"github.com", "api.github.com", "codeload.github.com",
		"release-assets.githubusercontent.com",
		"objects.githubusercontent.com",
		"GitHub.com",
	} {
		if !githubHostAllowed(host) {
			t.Errorf("githubHostAllowed(%q) = false, want true", host)
		}
	}
	for _, host := range []string{
		"evil.example",
		"githubusercontent.com.evil.example",
		"github.com.evil.example",
		"notgithub.com",
		"localhost",
		"169.254.169.254",
		"",
	} {
		if githubHostAllowed(host) {
			t.Errorf("githubHostAllowed(%q) = true, want false", host)
		}
	}
}

func rel(assets ...githubAsset) githubRelease {
	return githubRelease{TagName: "v1.0", Assets: assets}
}

func TestPickGitHubAssets(t *testing.T) {
	zip := githubAsset{Name: "demos.zip", DownloadURL: "https://github.com/x"}
	sum := githubAsset{Name: "demos.zip.sha256", DownloadURL: "https://github.com/y"}
	other := githubAsset{Name: "notes.txt"}

	t.Run("the only zip, with its checksum", func(t *testing.T) {
		b, s, err := pickGitHubAssets(rel(zip, sum, other), "")
		if err != nil {
			t.Fatal(err)
		}
		if b.Name != "demos.zip" || s.Name != "demos.zip.sha256" {
			t.Fatalf("picked %q / %q", b.Name, s.Name)
		}
	})

	t.Run("no checksum is not an error", func(t *testing.T) {
		b, s, err := pickGitHubAssets(rel(zip), "")
		if err != nil {
			t.Fatal(err)
		}
		if b.Name != "demos.zip" || s.Name != "" {
			t.Fatalf("picked %q / %q", b.Name, s.Name)
		}
	})

	// Two bundles and no name means guessing, and a wrong guess
	// installs the other app under the id chosen for this one.
	t.Run("two zips is a refusal, naming both", func(t *testing.T) {
		second := githubAsset{Name: "tools.zip"}
		_, _, err := pickGitHubAssets(rel(zip, second), "")
		if err == nil {
			t.Fatal("two bundles were accepted without a name")
		}
		if !strings.Contains(err.Error(), "demos.zip") || !strings.Contains(err.Error(), "tools.zip") {
			t.Errorf("error does not name the candidates: %v", err)
		}
	})

	t.Run("an explicit name wins", func(t *testing.T) {
		second := githubAsset{Name: "tools.zip"}
		b, _, err := pickGitHubAssets(rel(zip, second), "tools.zip")
		if err != nil {
			t.Fatal(err)
		}
		if b.Name != "tools.zip" {
			t.Fatalf("picked %q", b.Name)
		}
	})

	t.Run("a release with no zip says what it does have", func(t *testing.T) {
		_, _, err := pickGitHubAssets(rel(other), "")
		if err == nil {
			t.Fatal("a release with no bundle was accepted")
		}
		if !strings.Contains(err.Error(), "notes.txt") {
			t.Errorf("error does not say what is attached: %v", err)
		}
	})
}

// stubGitHub serves a release and its assets the way GitHub does, and
// points the package's API base and host allow-list at itself.
type stubGitHub struct {
	server *httptest.Server
	// bundle is what the .zip asset serves.
	bundle []byte
	// sum is the .sha256 body; empty means the release has no sidecar.
	sum string
	// hits counts asset downloads.
	hits int
}

func newStubGitHub(t *testing.T, bundle []byte, sum string) *stubGitHub {
	t.Helper()
	s := &stubGitHub{bundle: bundle, sum: sum}
	mux := http.NewServeMux()
	s.server = httptest.NewServer(mux)

	mux.HandleFunc("/repos/acme/demos/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		assets := []githubAsset{{
			Name: "demos.zip", Size: int64(len(bundle)),
			DownloadURL: s.server.URL + "/dl/demos.zip",
		}}
		if sum != "" {
			assets = append(assets, githubAsset{
				Name: "demos.zip.sha256", Size: int64(len(sum)),
				DownloadURL: s.server.URL + "/dl/demos.zip.sha256",
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(githubRelease{TagName: "v2.3", Assets: assets})
	})
	mux.HandleFunc("/dl/demos.zip", func(w http.ResponseWriter, _ *http.Request) {
		s.hits++
		_, _ = w.Write(bundle)
	})
	mux.HandleFunc("/dl/demos.zip.sha256", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sum))
	})

	u, err := url.Parse(s.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	oldBase, oldAddr := githubAPIBase, githubStubAddr
	githubAPIBase, githubStubAddr = s.server.URL, u.Host
	t.Cleanup(func() {
		githubAPIBase, githubStubAddr = oldBase, oldAddr
		s.server.Close()
	})
	return s
}

// githubInstallRequest is the POST the admin page sends for an install
// from a release: the same endpoint as an upload, with a named source
// instead of a file part.
func githubInstallRequest(t *testing.T, id, repo, ref string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range map[string]string{
		"id": id, "groups": "jones_lab", "source": "github", "repo": repo, "ref": ref,
	} {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/site-apps", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// githubServer is a handler with uploads and GitHub installs both on.
func githubServer(t *testing.T, dir string) *Handler {
	t.Helper()
	h := siteAppServer(t, dir)
	h.siteAppUpload = true
	h.siteAppGitHub = true
	h.siteAppUploads = siteapps.NewUploadStore(h.db)
	h.siteApps.SetPolicySource(siteapps.Chain{
		h.siteAppConfig, siteapps.NewDBPolicy(h.db),
	})
	return h
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// The whole path: resolve the release, download the asset, check it
// against the checksum GitHub also published, publish it, and record
// where it came from.
func TestSiteAppInstallFromGitHub(t *testing.T) {
	dir := t.TempDir()
	bundle := uploadBundleZip(t, "Demos")
	// shasum's own output format, which is what the release workflow
	// attaches: the hash, two spaces, and a name that need not match
	// the id it is being installed under.
	stub := newStubGitHub(t, bundle, sha256Hex(bundle)+"  htcondor-site-app-template.zip\n")

	h := githubServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, githubInstallRequest(t, "demos", "acme/demos", ""))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if stub.hits != 1 {
		t.Errorf("the bundle was downloaded %d times, want once", stub.hits)
	}
	if _, ok := h.siteApps.Get("demos"); !ok {
		t.Fatal("the app is not published after the install returned")
	}

	ups, err := h.siteAppUploads.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 {
		t.Fatalf("uploads = %+v, want one", ups)
	}
	got := ups[0]
	if got.SourceRepo != "acme/demos" {
		t.Errorf("source repo = %q", got.SourceRepo)
	}
	// The RESOLVED tag, not the empty string that was asked for.
	if got.SourceRef != "v2.3" {
		t.Errorf("source ref = %q, want the tag that was resolved", got.SourceRef)
	}
	if got.SourceAsset != "demos.zip" {
		t.Errorf("source asset = %q", got.SourceAsset)
	}
	if got.Digest != sha256Hex(bundle) {
		t.Errorf("digest = %q, want the bundle's", got.Digest)
	}

	// The checksum is written beside the bundle, so the loader
	// re-verifies it on every scan rather than taking this one
	// download's word for it.
	//nolint:gosec // G304: dir is this test's own t.TempDir().
	side, err := os.ReadFile(filepath.Join(dir, "demos.zip.sha256"))
	if err != nil {
		t.Fatalf("no checksum was written beside the bundle: %v", err)
	}
	if !strings.HasPrefix(string(side), sha256Hex(bundle)) {
		t.Errorf("sidecar = %q", side)
	}
	e, _ := h.siteApps.Get("demos")
	if e.App.Digest == "" {
		t.Error("the app is published unattested although a checksum was verified and written")
	}
}

// A bundle whose bytes do not match the checksum must not become the
// file an app is served from -- not briefly, not at all.
func TestSiteAppInstallRefusesAMismatchedChecksum(t *testing.T) {
	dir := t.TempDir()
	bundle := uploadBundleZip(t, "Demos")
	wrong := sha256Hex([]byte("some other bundle entirely"))
	newStubGitHub(t, bundle, wrong+"  demos.zip\n")

	h := githubServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, githubInstallRequest(t, "demos", "acme/demos", ""))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", w.Code, w.Body.String())
	}
	if _, ok := h.siteApps.Get("demos"); ok {
		t.Error("an app was published from bytes that failed their checksum")
	}
	if _, err := os.Stat(filepath.Join(dir, "demos.zip")); !os.IsNotExist(err) {
		t.Error("the rejected bundle was left in the apps directory")
	}
	// The administrator is told what happened; "could not store the
	// bundle" would send them looking at the disk.
	//
	// Matched on "hashes to" rather than on "sha256": the asset is
	// NAMED demos.zip.sha256, so a substring check for that passes on
	// any error that happens to mention the file -- which is how this
	// test first passed while the download was failing for an
	// unrelated reason.
	if !strings.Contains(w.Body.String(), "hashes to") {
		t.Errorf("the refusal does not say the bytes disagree with the checksum: %s", w.Body.String())
	}
}

// Installing is publishing, so it is refused wherever uploading is.
func TestSiteAppInstallFollowsTheUploadGrant(t *testing.T) {
	dir := t.TempDir()
	newStubGitHub(t, uploadBundleZip(t, "Demos"), "")

	h := githubServer(t, dir)
	h.siteAppUpload = false
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, githubInstallRequest(t, "demos", "acme/demos", ""))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
	}
}

// ... and separately where the site has no egress, with a refusal that
// says what to do instead.
func TestSiteAppInstallCanBeTurnedOffOnItsOwn(t *testing.T) {
	dir := t.TempDir()
	newStubGitHub(t, uploadBundleZip(t, "Demos"), "")

	h := githubServer(t, dir)
	h.siteAppGitHub = false
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, githubInstallRequest(t, "demos", "acme/demos", ""))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "attach") {
		t.Errorf("the refusal does not say what to do instead: %s", w.Body.String())
	}
	// Uploading a file still works; only the fetch is off.
	w = httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "demos", "jones_lab", uploadBundleZip(t, "Demos")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// A redirect that leaves GitHub is an error, not a hop. This is the
// containment that makes fetching on a caller's behalf acceptable at
// all, so it is exercised against the real client rather than asserted
// about the allow-list alone.
func TestGitHubClientRefusesARedirectOffGitHub(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secrets"))
	}))
	defer elsewhere.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer redirector.Close()

	u, err := url.Parse(redirector.URL)
	if err != nil {
		t.Fatal(err)
	}
	old := githubStubAddr
	githubStubAddr = u.Host
	defer func() { githubStubAddr = old }()

	_, err = getGitHubAsset(context.Background(), newGitHubClient(), githubAsset{
		Name: "demos.zip", DownloadURL: redirector.URL + "/dl",
	})
	if err == nil {
		t.Fatal("a redirect to a host that is not GitHub was followed")
	}
	if !strings.Contains(err.Error(), "not a GitHub host") {
		t.Errorf("error = %v, want it to name the reason", err)
	}
}

// An asset whose download address is not on GitHub is refused before a
// request is made. The redirect policy only sees hops after the first
// one, so the first URL needs its own check.
func TestGetGitHubAssetChecksTheFirstAddressToo(t *testing.T) {
	_, err := getGitHubAsset(context.Background(), newGitHubClient(), githubAsset{
		Name: "demos.zip", DownloadURL: "https://evil.example/demos.zip",
	})
	if err == nil {
		t.Fatal("an asset hosted away from GitHub was fetched")
	}
	// Matched on the refusal and not merely on the host name: if the
	// check were removed this would try to resolve evil.example and
	// fail anyway, and a DNS error names the host too. The point is
	// that no request was made at all.
	if !strings.Contains(err.Error(), "which is not GitHub") {
		t.Errorf("error = %v, want the address refused rather than attempted", err)
	}
}

// Replacing a bundle has to take the old checksum with it. Left
// behind, it describes the bundle that is gone, the loader finds they
// disagree, and an app that is perfectly good is withdrawn.
func TestReplacingABundleClearsTheOldChecksum(t *testing.T) {
	dir := t.TempDir()
	first := uploadBundleZip(t, "Demos")
	stub := newStubGitHub(t, first, sha256Hex(first)+"  demos.zip\n")

	h := githubServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, githubInstallRequest(t, "demos", "acme/demos", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("install status = %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "demos.zip.sha256")); err != nil {
		t.Fatalf("the first install wrote no checksum: %v", err)
	}
	_ = stub

	// Now a plain file upload over the top, which carries no checksum.
	second := uploadBundleZip(t, "Demos II")
	w = httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "demos", "jones_lab", second))
	if w.Code != http.StatusOK {
		t.Fatalf("upload status = %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "demos.zip.sha256")); !os.IsNotExist(err) {
		t.Fatalf("the previous bundle's checksum is still there: %v", err)
	}
	// The app survives the replacement, which it would not if the
	// stale checksum were still being checked against it.
	if _, ok := h.siteApps.Get("demos"); !ok {
		t.Fatal("the app was withdrawn by replacing its bundle")
	}
}

// The listing carries provenance so the page can ask whether a newer
// release exists; an app uploaded as a file has none to carry.
func TestAdminListingReportsWhereAnAppCameFrom(t *testing.T) {
	dir := t.TempDir()
	bundle := uploadBundleZip(t, "Demos")
	newStubGitHub(t, bundle, "")

	h := githubServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, githubInstallRequest(t, "demos", "acme/demos", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("install status = %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "byhand", "jones_lab", uploadBundleZip(t, "ByHand")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload status = %d: %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.adminListSiteApps(w, httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/api/v1/admin/site-apps", nil))
	var resp AdminSiteAppsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if !resp.GitHubAllowed {
		t.Error("github_allowed is false although the server will fetch")
	}
	byID := map[string]AdminSiteApp{}
	for _, a := range resp.Apps {
		byID[a.ID] = a
	}
	installed, ok := byID["demos"]
	if !ok {
		t.Fatalf("the installed app is missing from %v", byID)
	}
	if installed.Source == nil {
		t.Fatal("the installed app reports no source")
	}
	if installed.Source.Repo != "acme/demos" || installed.Source.Ref != "v2.3" {
		t.Errorf("source = %+v", installed.Source)
	}
	if installed.Source.Kind != "github" {
		t.Errorf("source kind = %q", installed.Source.Kind)
	}
	if byHand, ok := byID["byhand"]; !ok {
		t.Fatal("the uploaded app is missing")
	} else if byHand.Source != nil {
		t.Errorf("an uploaded file reports a source: %+v", byHand.Source)
	}
}

// A release that does not exist, or a repository that is not public,
// gets one message: an unauthenticated caller genuinely cannot tell
// them apart, and a message that guessed would be wrong half the time.
func TestInstallFromAMissingReleaseSaysSo(t *testing.T) {
	dir := t.TempDir()
	newStubGitHub(t, uploadBundleZip(t, "Demos"), "")

	h := githubServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, githubInstallRequest(t, "otherapp", "acme/missing", ""))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "public") {
		t.Errorf("the message does not raise the obvious cause: %s", w.Body.String())
	}
}

func TestResolveGitHubReleaseBuildsTheTaggedPath(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		_ = json.NewEncoder(w).Encode(githubRelease{TagName: "v0.1"})
	}))
	defer srv.Close()
	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	src, err := parseGitHubSource("acme/demos", "v0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveGitHubRelease(context.Background(), newGitHubClient(), src); err != nil {
		t.Fatal(err)
	}
	if want := "/repos/acme/demos/releases/tags/v0.1"; asked != want {
		t.Errorf("asked for %q, want %q", asked, want)
	}
}

func TestResolveGitHubReleaseExplainsARateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limit exceeded", http.StatusForbidden)
	}))
	defer srv.Close()
	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	src, _ := parseGitHubSource("acme/demos", "", "")
	_, err := resolveGitHubRelease(context.Background(), newGitHubClient(), src)
	if err == nil {
		t.Fatal("a 403 was accepted")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("error = %v, want the rate limit named", err)
	}
}
