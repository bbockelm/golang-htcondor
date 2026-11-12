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
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/siteapps"
)

// uploadBundleZip is a minimal publishable bundle, in memory.
func uploadBundleZip(t *testing.T, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for entry, body := range map[string]string{
		"app.yaml":       "name: " + name + "\nversion: 1.2.3\n",
		"web/index.html": "<html><head></head><body>" + name + "</body></html>",
	} {
		w, err := zw.Create(entry)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// uploadRequest builds the multipart POST an administrator's browser sends.
func uploadRequest(t *testing.T, id, groups string, zipBytes []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("id", id); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("groups", groups); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("bundle", id+".zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(zipBytes); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/site-apps", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// Upload is refused unless the site turned it on, and the refusal says
// how to publish the app anyway. An uploaded app runs with the rights
// of everyone who opens it, so administering the server must not imply
// it -- and an administrator who is refused still needs to get their
// lab's app served.
func TestSiteAppUploadIsRefusedUnlessEnabled(t *testing.T) {
	dir := t.TempDir()
	h := siteAppServer(t, dir)
	h.siteAppUpload = false

	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "cryoem", "smith_lab", uploadBundleZip(t, "CryoEM")))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"HTTP_API_SITE_APPS_UPLOAD", dir} {
		if !bytes.Contains([]byte(body), []byte(want)) {
			t.Errorf("refusal does not mention %q: %s", want, body)
		}
	}
	// Nothing was written: a refused upload must not leave a bundle
	// behind for the next scan to find.
	if _, err := os.Stat(filepath.Join(dir, "cryoem.zip")); !os.IsNotExist(err) {
		t.Error("a refused upload left a bundle in the directory")
	}
}

// The configuration is the authority. An upload for an id it names is
// refused outright, naming the parameter -- rather than being accepted
// and then silently ignored by the chain, which would leave an
// administrator believing they had published something.
func TestSiteAppUploadRefusesAConfiguredID(t *testing.T) {
	dir := t.TempDir()
	publishSiteApp(t, dir, "cryoem", "smith_lab")
	h := siteAppServer(t, dir)
	h.siteAppUpload = true
	h.siteAppUploads = siteapps.NewUploadStore(h.db)

	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "cryoem", "everyone", uploadBundleZip(t, "Mine")))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("HTTP_API_SITE_APP_CRYOEM_GROUPS")) {
		t.Errorf("refusal does not name the parameter to edit: %s", w.Body.String())
	}
	// The configured bundle must be untouched. Overwriting it would
	// let an administrator replace the content of an app whose policy
	// they cannot change.
	if _, err := os.Stat(filepath.Join(dir, "cryoem.zip")); !os.IsNotExist(err) {
		t.Error("the refused upload wrote a bundle over a configured id")
	}
}

// An upload naming no groups publishes nothing, and says so, for the
// same reason an empty GROUPS does in the configuration: far more
// likely a mistake than a request to publish to nobody.
func TestSiteAppUploadRequiresGroups(t *testing.T) {
	dir := t.TempDir()
	h := siteAppServer(t, dir)
	h.siteAppUpload = true
	h.siteAppUploads = siteapps.NewUploadStore(h.db)

	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "cryoem", "   ", uploadBundleZip(t, "CryoEM")))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
}

// The happy path: a bundle goes up, the policy is recorded, and the
// app is being served by the time the response is written. Answering
// before the scan would make the page show the previous state and look
// like the upload had not worked.
func TestSiteAppUploadPublishesImmediately(t *testing.T) {
	dir := t.TempDir()
	h := siteAppServer(t, dir)
	h.siteAppUpload = true
	h.siteAppUploads = siteapps.NewUploadStore(h.db)
	h.siteApps.SetPolicySource(siteapps.Chain{
		h.siteAppConfig, siteapps.NewDBPolicy(h.db),
	})

	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "seqqc", "jones_lab", uploadBundleZip(t, "SeqQC")))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if _, ok := h.siteApps.Get("seqqc"); !ok {
		t.Fatal("the uploaded app is not published after the upload returned")
	}
	if _, err := os.Stat(filepath.Join(dir, "seqqc.zip")); err != nil {
		t.Errorf("the bundle was not stored: %v", err)
	}

	// The store holds who published it. An app that can run code in
	// other people's sessions has to be attributable.
	ups, err := h.siteAppUploads.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ups) != 1 || ups[0].AppID != "seqqc" {
		t.Fatalf("uploads = %+v, want the one just made", ups)
	}
	if ups[0].Digest == "" {
		t.Error("no digest was recorded for the uploaded bytes")
	}
	if ups[0].UploadedAt.After(time.Now().Add(time.Minute)) {
		t.Errorf("uploaded_at = %v, which is in the future", ups[0].UploadedAt)
	}
}

// Withdrawing an uploaded app unpublishes it and removes the bundle,
// so a later scan cannot bring it back.
func TestSiteAppWithdrawRemovesTheBundle(t *testing.T) {
	dir := t.TempDir()
	h := siteAppServer(t, dir)
	h.siteAppUpload = true
	h.siteAppUploads = siteapps.NewUploadStore(h.db)
	h.siteApps.SetPolicySource(siteapps.Chain{
		h.siteAppConfig, siteapps.NewDBPolicy(h.db),
	})

	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "seqqc", "jones_lab", uploadBundleZip(t, "SeqQC")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/admin/site-apps/seqqc", nil)
	h.adminWithdrawSiteApp(w, req, "seqqc")
	if w.Code != http.StatusOK {
		t.Fatalf("withdraw: %d %s", w.Code, w.Body.String())
	}
	if _, ok := h.siteApps.Get("seqqc"); ok {
		t.Error("the app is still published after being withdrawn")
	}
	if _, err := os.Stat(filepath.Join(dir, "seqqc.zip")); !os.IsNotExist(err) {
		t.Error("the bundle is still on disk, so the next scan could republish it")
	}
}

// A configured app cannot be withdrawn here either. The configuration
// decided it; this server refusing is what keeps that true.
func TestSiteAppWithdrawRefusesAConfiguredID(t *testing.T) {
	dir := t.TempDir()
	siteAppBundle(t, dir, "cryoem", "CryoEM", "smith_lab")
	h := siteAppServer(t, dir)
	h.siteAppUpload = true
	h.siteAppUploads = siteapps.NewUploadStore(h.db)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/admin/site-apps/cryoem", nil)
	h.adminWithdrawSiteApp(w, req, "cryoem")

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "cryoem.zip")); err != nil {
		t.Error("the refused withdrawal removed a configured app's bundle")
	}
}

// The listing says which decision published each app, and whether this
// server can change it. Both drive what the page offers, and getting
// Managed wrong would put a Withdraw button on an app the server will
// refuse to withdraw.
func TestSiteAppListingMarksConfiguredAppsUnmanaged(t *testing.T) {
	dir := t.TempDir()
	siteAppBundle(t, dir, "cryoem", "CryoEM", "smith_lab")
	h := siteAppServer(t, dir)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/admin/site-apps", nil)
	h.adminListSiteApps(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var got AdminSiteAppsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Apps) != 1 {
		t.Fatalf("apps = %+v, want the configured one", got.Apps)
	}
	if got.Apps[0].Managed {
		t.Error("a configured app is marked managed, which would offer a Withdraw the server refuses")
	}
	if got.Apps[0].Origin == "" {
		t.Error("no origin, so the page cannot say which decision published it")
	}
	if got.Apps[0].Digest == "" {
		t.Error("no digest: every zip is hashed whether or not a .sha256 came with it")
	}
}

// The body cap is the real bound, and this proves it rather than
// trusting the MaxBytesReader call to be in the right place.
//
// ParseMultipartForm's own argument sizes the in-memory part only;
// everything past it spills to temporary files, so without the reader
// cap an upload is bounded by the disk. gosec cannot see the mitigation
// and the suppression there says it exists -- so something has to check
// that it does.
func TestSiteAppUploadRefusesAnOversizedBody(t *testing.T) {
	dir := t.TempDir()
	h := siteAppServer(t, dir)
	h.siteAppUpload = true
	h.siteAppUploads = siteapps.NewUploadStore(h.db)

	// A body past the cap. The content is irrelevant: it must be
	// refused while being read, not parsed and then judged.
	huge := bytes.Repeat([]byte("x"), 64*1024)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("id", "big"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("groups", "lab"); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("bundle", "big.zip")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if _, err := fw.Write(huge); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/site-apps", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	// Cap it well below the body so the test does not have to build
	// half a gigabyte to find out whether the reader is wired up.
	prev := uploadBodyLimit
	uploadBodyLimit = 1 << 20
	t.Cleanup(func() { uploadBodyLimit = prev })

	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want the oversized body refused: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "big.zip")); !os.IsNotExist(err) {
		t.Error("an oversized upload left a bundle behind")
	}
}
