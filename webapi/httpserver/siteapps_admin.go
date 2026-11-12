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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/siteapps"
)

// The administrator's view of site apps: what is published now, what
// has been published before, and -- where the site allows it -- a way
// to publish one without touching the configuration.
//
// Reading is available wherever the admin pages are. Publishing is
// not: an uploaded app is served same-origin to its groups and runs
// with the full rights of whoever opens it, so "may administer this
// server" and "may run code in another user's session" are kept as
// separate grants. HTTP_API_SITE_APPS_UPLOAD turns the second one on,
// and it is off until an operator says otherwise.

// maxSiteAppBundleBytes bounds an uploaded bundle. The loader refuses a
// bundle over 512 MiB anyway; this refuses it before it is written.
const maxSiteAppBundleBytes = 512 << 20

// AdminSiteApp is one app as the admin page shows it.
type AdminSiteApp struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Icon        string   `json:"icon,omitempty"`
	Groups      []string `json:"groups"`
	Home        bool     `json:"home"`
	Version     string   `json:"version,omitempty"`
	Revision    string   `json:"revision,omitempty"`
	Digest      string   `json:"digest,omitempty"`
	// Attested is whether a .sha256 accompanied the bundle and matched.
	Attested bool `json:"attested"`
	// Origin says who decided this app is published: a configuration
	// parameter name, or that it was uploaded.
	Origin string `json:"origin,omitempty"`
	// Managed is whether this server can change it. An app the
	// configuration publishes is not editable here at all.
	Managed bool `json:"managed"`
	// URL is where it is served.
	URL string `json:"url"`
}

// AdminSiteAppsResponse is GET /api/v1/admin/site-apps.
type AdminSiteAppsResponse struct {
	// Enabled is whether site apps are configured at all.
	Enabled bool `json:"enabled"`
	// UploadAllowed is whether this server accepts uploaded bundles.
	UploadAllowed bool `json:"upload_allowed"`
	// Directory is where bundles live, so an administrator who cannot
	// upload knows where to put one.
	Directory string         `json:"directory,omitempty"`
	Apps      []AdminSiteApp `json:"apps"`
}

// AdminSiteAppHistoryEntry is one period an app was served.
type AdminSiteAppHistoryEntry struct {
	Digest    string    `json:"digest,omitempty"`
	Attested  bool      `json:"attested"`
	Version   string    `json:"version,omitempty"`
	Revision  string    `json:"revision,omitempty"`
	Groups    []string  `json:"groups"`
	Home      bool      `json:"home"`
	Origin    string    `json:"origin,omitempty"`
	SizeBytes int64     `json:"size_bytes,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// AdminSiteAppHistoryResponse is GET /api/v1/admin/site-apps/{id}/history.
type AdminSiteAppHistoryResponse struct {
	ID      string                     `json:"id"`
	History []AdminSiteAppHistoryEntry `json:"history"`
}

// handleAdminSiteApps serves /api/v1/admin/site-apps and, with a
// trailing id, that app.
func (s *Handler) handleAdminSiteApps(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/admin/site-apps"), "/")
	switch {
	case rest == "":
		switch r.Method {
		case http.MethodGet:
			s.adminListSiteApps(w, r)
		case http.MethodPost:
			s.adminUploadSiteApp(w, r)
		default:
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	case strings.HasSuffix(rest, "/history"):
		if r.Method != http.MethodGet {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		s.adminSiteAppHistory(w, r, strings.TrimSuffix(rest, "/history"))
		return
	}
	if strings.Contains(rest, "/") {
		s.writeError(w, http.StatusNotFound, "Not found")
		return
	}
	if r.Method != http.MethodDelete {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	s.adminWithdrawSiteApp(w, r, rest)
}

// adminListSiteApps answers what is published now.
func (s *Handler) adminListSiteApps(w http.ResponseWriter, r *http.Request) {
	resp := AdminSiteAppsResponse{Apps: []AdminSiteApp{}}
	if s.siteApps == nil {
		s.writeJSON(w, http.StatusOK, resp)
		return
	}
	resp.Enabled = true
	resp.UploadAllowed = s.siteAppUploadAllowed()
	resp.Directory = s.siteApps.Dir()
	for _, e := range s.siteApps.All() {
		resp.Apps = append(resp.Apps, AdminSiteApp{
			ID: e.App.ID, Name: e.App.Name, Description: e.App.Description,
			Icon: e.App.Icon, Groups: e.App.Groups, Home: e.App.Home,
			Version: e.App.Version, Revision: e.App.Revision,
			Digest: e.ContentDigest(), Attested: e.App.Digest != "",
			Origin: e.App.Origin, Managed: e.App.Origin == siteapps.OriginUpload,
			URL: siteapps.MountPath(e.App.ID),
		})
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// adminSiteAppHistory answers what has been served under an id.
func (s *Handler) adminSiteAppHistory(w http.ResponseWriter, r *http.Request, id string) {
	if err := siteapps.ValidateID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"No application database is configured, so nothing has been recorded")
		return
	}
	rows, err := siteapps.History(r.Context(), s.db, id)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "site app history", "app", id, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not read the history")
		return
	}
	out := AdminSiteAppHistoryResponse{ID: id, History: []AdminSiteAppHistoryEntry{}}
	for _, h := range rows {
		out.History = append(out.History, AdminSiteAppHistoryEntry{
			Digest: h.Digest, Attested: h.DigestKnown, Version: h.Version, Revision: h.Revision,
			Groups: h.Groups, Home: h.Home, Origin: h.Origin, SizeBytes: h.SizeBytes,
			FirstSeen: h.FirstSeen, LastSeen: h.LastSeen,
		})
	}
	s.writeJSON(w, http.StatusOK, out)
}

// siteAppUploadAllowed reports whether this server accepts uploads.
func (s *Handler) siteAppUploadAllowed() bool {
	return s.siteApps != nil && s.siteAppUploads != nil && s.siteAppUpload
}

// adminUploadSiteApp publishes a bundle sent through the web interface.
//
// Refused unless the site turned it on. An uploaded app is served
// same-origin to the groups it names and can do anything its visitor
// can, so this grant is deliberately not implied by administering the
// server.
func (s *Handler) adminUploadSiteApp(w http.ResponseWriter, r *http.Request) {
	if s.siteApps == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"Site apps are not configured; set HTTP_API_SITE_APPS_DIR")
		return
	}
	if !s.siteAppUploadAllowed() {
		s.writeError(w, http.StatusForbidden,
			"This server does not accept uploaded site apps. An uploaded app runs with the "+
				"rights of everyone who opens it, so it is a separate grant: set "+
				"HTTP_API_SITE_APPS_UPLOAD = true to allow it. Otherwise copy the bundle into "+
				s.siteApps.Dir()+" and name its groups in the configuration.")
		return
	}
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid upload: %v", err))
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if err := siteapps.ValidateID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	groups := siteapps.ParseGroupList(r.FormValue("groups"))
	if len(groups) == 0 {
		s.writeError(w, http.StatusBadRequest,
			"Name the groups that may see this app, or * for every authenticated user")
		return
	}
	// The configuration is the authority. An id it names is refused
	// here rather than quietly ignored by the chain, so that an
	// administrator who expected to publish something is told they did
	// not.
	if _, declared := s.siteAppConfigPolicy().Policy(id); declared {
		s.writeError(w, http.StatusConflict, fmt.Sprintf(
			"%q is published by this access point's configuration (%s), which takes precedence. "+
				"Change it there, or choose another id.", id, siteapps.ConfigKey(id, "GROUPS")))
		return
	}

	file, header, err := r.FormFile("bundle")
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Attach the bundle as the 'bundle' field")
		return
	}
	defer func() { _ = file.Close() }()
	if header.Size > maxSiteAppBundleBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("The bundle is larger than %d bytes", int64(maxSiteAppBundleBytes)))
		return
	}

	digest, size, err := s.writeUploadedBundle(id, file)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "site app upload", "app", id, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not store the bundle")
		return
	}

	// requireAdmin has already established a session on the routed
	// path, but this does not dereference what it was handed without
	// checking: an unattributed upload is worth recording as such, and
	// a nil here would take the request down instead.
	by := sessionUsername(s, r)
	up := siteapps.Upload{
		AppID: id, Groups: groups, Enabled: true,
		Home:        r.FormValue("home") == "true",
		Name:        strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")),
		Icon:        strings.TrimSpace(r.FormValue("icon")),
		UploadedBy:  by, UploadedAt: time.Now(),
		Digest: digest, SizeBytes: size,
	}
	if err := s.siteAppUploads.Put(r.Context(), up); err != nil {
		s.logger.Error(logging.DestinationHTTP, "site app upload", "app", id, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not record the app")
		return
	}
	// Recorded as well as answered: this is a grant of code execution
	// in other people's sessions, and the access log alone does not say
	// who it was granted to.
	s.logger.Info(logging.DestinationHTTP, "Site app uploaded",
		"app", id, "by", by, "groups", strings.Join(groups, ","),
		"digest", digest, "bytes", size)

	s.logSiteAppReload(s.siteApps.Reload())
	s.adminListSiteApps(w, r)
}

// writeUploadedBundle stores the bundle as <id>.zip, atomically.
//
// Written to a temporary name in the same directory and renamed over
// the target, because the loader is reading that directory on its own
// schedule: a partially-written <id>.zip is an archive that opens and
// serves half an app.
func (s *Handler) writeUploadedBundle(id string, src io.Reader) (digest string, size int64, err error) {
	dir := s.siteApps.Dir()
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return "", 0, err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	h := sha256.New()
	size, err = io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, maxSiteAppBundleBytes+1))
	if err != nil {
		return "", 0, err
	}
	if size > maxSiteAppBundleBytes {
		return "", 0, fmt.Errorf("bundle is larger than %d bytes", int64(maxSiteAppBundleBytes))
	}
	if err = tmp.Sync(); err != nil {
		return "", 0, err
	}
	if err = tmp.Close(); err != nil {
		return "", 0, err
	}
	if err = os.Chmod(tmpName, 0o600); err != nil {
		return "", 0, err
	}
	if err = os.Rename(tmpName, filepath.Join(dir, id+".zip")); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// adminWithdrawSiteApp removes an uploaded app.
//
// The policy row goes first and the bundle second: a failure in
// between leaves a bundle nothing publishes, which is inert, rather
// than a published app with no record of who put it there.
func (s *Handler) adminWithdrawSiteApp(w http.ResponseWriter, r *http.Request, id string) {
	if !s.siteAppUploadAllowed() {
		s.writeError(w, http.StatusForbidden, "This server does not manage site apps through the web interface")
		return
	}
	if err := siteapps.ValidateID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, declared := s.siteAppConfigPolicy().Policy(id); declared {
		s.writeError(w, http.StatusConflict, fmt.Sprintf(
			"%q is published by this access point's configuration; remove %s there",
			id, siteapps.ConfigKey(id, "GROUPS")))
		return
	}
	if err := s.siteAppUploads.Delete(r.Context(), id); err != nil {
		s.logger.Error(logging.DestinationHTTP, "site app withdraw", "app", id, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not withdraw the app")
		return
	}
	if err := os.Remove(filepath.Join(s.siteApps.Dir(), id+".zip")); err != nil && !errors.Is(err, os.ErrNotExist) {
		// The app is already unpublished; the leftover file is inert
		// and worth a log line rather than an error to the caller.
		s.logger.Warn(logging.DestinationHTTP, "site app bundle left behind", "app", id, "error", err)
	}
	s.logger.Info(logging.DestinationHTTP, "Site app withdrawn", "app", id, "by", sessionUsername(s, r))
	s.logSiteAppReload(s.siteApps.Reload())
	s.adminListSiteApps(w, r)
}

// sessionUsername is the caller's name, or "" when there is no
// session to ask. Never panics on a request that reached here without
// one.
func sessionUsername(s *Handler, r *http.Request) string {
	if session, ok := s.getSessionFromRequest(r); ok && session != nil {
		return session.Username
	}
	return ""
}

// siteAppConfigPolicy is the configuration-backed source alone, for
// deciding whether the configuration has already spoken about an id.
func (s *Handler) siteAppConfigPolicy() siteapps.PolicySource {
	if s.siteAppConfig == nil {
		return siteapps.NewConfigPolicy(nil)
	}
	return s.siteAppConfig
}
