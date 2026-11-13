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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/siteapps"
)

// uploadingServer is a handler that accepts uploaded apps, with the
// chained policy source a real deployment has.
func uploadingServer(t *testing.T, dir string) *Handler {
	t.Helper()
	h := siteAppServer(t, dir)
	h.siteAppUpload = true
	h.siteAppUploads = siteapps.NewUploadStore(h.db)
	h.siteApps.SetPolicySource(siteapps.Chain{h.siteAppConfig, siteapps.NewDBPolicy(h.db)})
	return h
}

// getSiteAppConfig reads one app's settings through the handler.
func getSiteAppConfig(t *testing.T, h *Handler, id string) (*httptest.ResponseRecorder, AdminSiteAppConfigResponse) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/admin/site-apps/"+id+"/config", nil)
	h.adminSiteAppConfig(w, req, id)
	var got AdminSiteAppConfigResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return w, got
}

// putSiteAppConfig writes settings through the handler.
func putSiteAppConfig(t *testing.T, h *Handler, id string, settings map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(AdminSiteAppConfigRequest{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/v1/admin/site-apps/"+id+"/config", bytes.NewReader(body))
	h.adminSetSiteAppConfig(w, req, id)
	return w
}

func settingByName(t *testing.T, resp AdminSiteAppConfigResponse, name string) AdminSiteAppSetting {
	t.Helper()
	for _, s := range resp.Settings {
		if s.Setting == name {
			return s
		}
	}
	t.Fatalf("no %s setting in %+v", name, resp.Settings)
	return AdminSiteAppSetting{}
}

// The settings are the configuration's, named as the configuration
// names them. An administrator reading this page has to be able to put
// the same string into condor_config_val, so the key is the whole
// parameter name rather than a word this server invented for it.
func TestSiteAppConfigNamesTheConfigurationParameters(t *testing.T) {
	dir := t.TempDir()
	siteAppBundle(t, dir, "cryoem", "CryoEM", "smith_lab")
	h := siteAppServer(t, dir)

	w, got := getSiteAppConfig(t, h, "cryoem")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	groups := settingByName(t, got, "GROUPS")
	if groups.Key != "HTTP_API_SITE_APP_CRYOEM_GROUPS" {
		t.Errorf("GROUPS key = %q, want the configuration parameter name", groups.Key)
	}
	if groups.Value != "smith_lab" {
		t.Errorf("GROUPS value = %q, want what the configuration set", groups.Value)
	}
	// A configured app is not editable here whatever the upload
	// setting says: the configuration decided it, and a UI that let
	// one be typed over would be offering a change this server
	// refuses.
	if got.Editable || groups.Editable {
		t.Error("a configured app is reported editable")
	}
	if got.StoredHere {
		t.Error("a configured app is reported as stored by this server")
	}
	// The name comes from the bundle when no parameter overrides it,
	// and saying so is the difference between a setting to maintain
	// and a label the author chose.
	name := settingByName(t, got, "NAME")
	if name.Value != "" || name.Effective != "CryoEM" || name.EffectiveFrom != "bundle" {
		t.Errorf("NAME = %+v, want unset with the bundle's label in force", name)
	}
}

// A hyphen in an id becomes an underscore in the parameter name. The
// server builds the name for exactly this reason: a page that joined
// the id into the string itself would show
// HTTP_API_SITE_APP_MY-APP_GROUPS, which sets nothing.
func TestSiteAppConfigUsesTheMacroSpellingOfAHyphenatedID(t *testing.T) {
	dir := t.TempDir()
	siteAppBundle(t, dir, "my-app", "My App", "smith_lab")
	h := siteAppServer(t, dir)

	w, got := getSiteAppConfig(t, h, "my-app")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if key := settingByName(t, got, "GROUPS").Key; key != "HTTP_API_SITE_APP_MY_APP_GROUPS" {
		t.Errorf("GROUPS key = %q, want the hyphen as an underscore", key)
	}
}

// An uploaded app's settings are this server's own record, and a
// change to them takes effect on the rescan the write triggers.
func TestSiteAppConfigChangeTakesEffectWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	h := uploadingServer(t, dir)

	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "seqqc", "jones_lab", uploadBundleZip(t, "SeqQC")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	_, got := getSiteAppConfig(t, h, "seqqc")
	if !got.StoredHere || !got.Editable {
		t.Fatalf("an uploaded app is not editable: %+v", got)
	}

	w = putSiteAppConfig(t, h, "seqqc", map[string]string{
		"HTTP_API_SITE_APP_SEQQC_GROUPS": "jones_lab, smith_lab",
		"HTTP_API_SITE_APP_SEQQC_HOME":   "true",
		"HTTP_API_SITE_APP_SEQQC_NAME":   "Sequencing QC",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}

	// The library, not the database: the point of reloading before
	// answering is that the change is in force by the time the page
	// redraws.
	entry, ok := h.siteApps.Get("seqqc")
	if !ok {
		t.Fatal("the app is no longer published after a settings change")
	}
	if !entry.App.VisibleTo([]string{"smith_lab"}) {
		t.Error("the new group cannot see the app, so the change did not take effect")
	}
	if !entry.App.Home {
		t.Error("HOME did not take effect")
	}
	if entry.App.Name != "Sequencing QC" {
		t.Errorf("name = %q, want the override", entry.App.Name)
	}
	// And the response is the listing as it now stands, so the page
	// does not have to guess when the change landed.
	var listed AdminSiteAppsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	if len(listed.Apps) != 1 || listed.Apps[0].Name != "Sequencing QC" {
		t.Errorf("listing = %+v, want the changed app", listed.Apps)
	}
}

// The configuration is the authority here too. Letting the settings of
// an app it publishes be typed over on this page would be the way
// around the configuration that refusing the upload exists to prevent.
func TestSiteAppConfigRefusesAConfiguredID(t *testing.T) {
	dir := t.TempDir()
	siteAppBundle(t, dir, "cryoem", "CryoEM", "smith_lab")
	h := uploadingServer(t, dir)

	w := putSiteAppConfig(t, h, "cryoem", map[string]string{
		"HTTP_API_SITE_APP_CRYOEM_GROUPS": "everyone",
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("HTTP_API_SITE_APP_CRYOEM_GROUPS")) {
		t.Errorf("refusal does not name the parameter to edit: %s", w.Body.String())
	}
	if entry, ok := h.siteApps.Get("cryoem"); !ok || entry.App.VisibleTo([]string{"everyone"}) {
		t.Error("the refused change widened who may see a configured app")
	}
}

// A parameter name that is not this app's is refused rather than
// ignored. Ignoring it would read as a setting that does not work.
func TestSiteAppConfigRefusesAForeignParameter(t *testing.T) {
	dir := t.TempDir()
	h := uploadingServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "seqqc", "jones_lab", uploadBundleZip(t, "SeqQC")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	for _, key := range []string{
		"HTTP_API_SITE_APP_OTHER_GROUPS",  // another app's
		"HTTP_API_SITE_APP_SEQQC_WHATNOT", // not a setting
		"HTTP_API_WEBUI_ADMIN_GROUP",      // not a site app parameter at all
	} {
		w := putSiteAppConfig(t, h, "seqqc", map[string]string{key: "smith_lab"})
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400: %s", key, w.Code, w.Body.String())
		}
	}
	// Nothing was applied by any of them.
	entry, _ := h.siteApps.Get("seqqc")
	if entry.App.VisibleTo([]string{"smith_lab"}) {
		t.Error("a refused request changed who may see the app")
	}
}

// One bad parameter in a request changes nothing. Applying in map
// order would leave the app half-changed and the page reporting a
// failure.
func TestSiteAppConfigAppliesNothingWhenOneParameterIsBad(t *testing.T) {
	dir := t.TempDir()
	h := uploadingServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "seqqc", "jones_lab", uploadBundleZip(t, "SeqQC")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	w = putSiteAppConfig(t, h, "seqqc", map[string]string{
		"HTTP_API_SITE_APP_SEQQC_NAME": "Sequencing QC",
		"HTTP_API_SITE_APP_SEQQC_HOME": "sometimes",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	entry, _ := h.siteApps.Get("seqqc")
	if entry.App.Name == "Sequencing QC" {
		t.Error("the valid half of a refused request was applied")
	}
}

// An empty GROUPS is a mistake, not a request to publish to nobody --
// the same reading the configuration gives it.
func TestSiteAppConfigRefusesEmptyGroups(t *testing.T) {
	dir := t.TempDir()
	h := uploadingServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "seqqc", "jones_lab", uploadBundleZip(t, "SeqQC")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	w = putSiteAppConfig(t, h, "seqqc", map[string]string{"HTTP_API_SITE_APP_SEQQC_GROUPS": " , "})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if entry, ok := h.siteApps.Get("seqqc"); !ok || !entry.App.VisibleTo([]string{"jones_lab"}) {
		t.Error("the refused change unpublished the app")
	}
}

// ENABLED is shown and not settable. An app it disables is not in the
// listing this page draws, so setting it here would make the app
// vanish with no way back; withdrawing is the operation that means
// "stop serving this".
func TestSiteAppConfigWillNotDisableAnApp(t *testing.T) {
	dir := t.TempDir()
	h := uploadingServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "seqqc", "jones_lab", uploadBundleZip(t, "SeqQC")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	_, got := getSiteAppConfig(t, h, "seqqc")
	if enabled := settingByName(t, got, "ENABLED"); enabled.Editable {
		t.Error("ENABLED is offered as editable")
	}
	w = putSiteAppConfig(t, h, "seqqc", map[string]string{"HTTP_API_SITE_APP_SEQQC_ENABLED": "false"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if _, ok := h.siteApps.Get("seqqc"); !ok {
		t.Fatal("the app was unpublished by a request that should have been refused")
	}
}

// Settings cannot be changed from here when the server does not manage
// site apps through the web interface at all.
func TestSiteAppConfigRefusedWhenUploadsAreOff(t *testing.T) {
	dir := t.TempDir()
	h := uploadingServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "seqqc", "jones_lab", uploadBundleZip(t, "SeqQC")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	h.siteAppUpload = false

	_, got := getSiteAppConfig(t, h, "seqqc")
	if got.Editable {
		t.Error("settings are reported editable with uploads off")
	}
	if w := putSiteAppConfig(t, h, "seqqc", map[string]string{
		"HTTP_API_SITE_APP_SEQQC_GROUPS": "smith_lab",
	}); w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
	}
}

// The listing says when an uploaded app was published and by whom.
// Re-publishing an app that is already in the table changes nothing
// visible about the row, so without this there is no way to tell from
// the page that the new bundle took.
func TestSiteAppListingSaysWhenAnUploadWasPublished(t *testing.T) {
	dir := t.TempDir()
	h := uploadingServer(t, dir)
	w := httptest.NewRecorder()
	h.adminUploadSiteApp(w, uploadRequest(t, "seqqc", "jones_lab", uploadBundleZip(t, "SeqQC")))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	var got AdminSiteAppsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Apps) != 1 {
		t.Fatalf("apps = %+v, want the uploaded one", got.Apps)
	}
	if got.Apps[0].UploadedAt == nil || got.Apps[0].UploadedAt.IsZero() {
		t.Error("no uploaded_at, so the page cannot say when this version was published")
	}
	if got.Apps[0].SizeBytes == 0 {
		t.Error("no size_bytes for an uploaded zip")
	}
}
