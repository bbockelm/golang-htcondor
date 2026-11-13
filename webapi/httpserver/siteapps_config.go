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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/siteapps"
)

// An app's settings, named as the configuration names them.
//
// There is no second vocabulary here on purpose. "Who may see this
// app" is HTTP_API_SITE_APP_<ID>_GROUPS, and an administrator reading
// this page should be able to put the same words into
// condor_config_val, a configuration file, or a question to someone
// else. The server builds the names rather than the browser because
// the mapping from an id to a parameter name is not the identity --
// a hyphen becomes an underscore (siteapps.MacroID) -- and a second
// implementation of that rule in the frontend is a second thing to get
// wrong.
//
// What can be changed from here is narrower than what can be set in
// the configuration, and the response says which is which rather than
// leaving the page to guess:
//
//   - An app the configuration publishes is read-only. The values
//     shown are the ones the server read at startup or at the last
//     condor_reconfig, and changing them means editing the
//     configuration and reconfiguring.
//   - An app uploaded here keeps its settings in this server's own
//     database, and a change takes effect on the rescan the write
//     triggers -- no restart.

// siteAppSettableSettings are the settings an uploaded app's policy
// may be changed through this page, in the order they are shown.
//
// ENABLED is deliberately absent. An app it disables is not published,
// and an unpublished app is not in the listing this page draws, so
// setting it from here would make the app disappear with no way back.
// Withdraw is the operation that means "stop serving this".
var siteAppSettableSettings = []string{"GROUPS", "HOME", "NAME", "DESCRIPTION", "ICON"}

// siteAppAllSettings is every setting shown, settable or not.
var siteAppAllSettings = []string{"GROUPS", "HOME", "ENABLED", "NAME", "DESCRIPTION", "ICON"}

// AdminSiteAppSetting is one configuration parameter of one app.
type AdminSiteAppSetting struct {
	// Key is the full parameter name, e.g.
	// HTTP_API_SITE_APP_CRYOEM_GROUPS.
	Key string `json:"key"`
	// Setting is the part after the id: GROUPS, HOME, and so on.
	Setting string `json:"setting"`
	// Value is what is set, written the way a configuration file would
	// write it. Empty means nothing is set.
	Value string `json:"value"`
	// Effective is what is in force when that is not Value -- the
	// bundle's own label, or the default for a flag. Empty when Value
	// is what applies.
	Effective string `json:"effective,omitempty"`
	// EffectiveFrom says where Effective came from: "bundle" for a
	// label in the bundle's app.yaml, "default" for a flag nobody set.
	EffectiveFrom string `json:"effective_from,omitempty"`
	// Editable is whether a PUT to this endpoint may change it.
	Editable bool `json:"editable"`
}

// AdminSiteAppConfigResponse is GET /api/v1/admin/site-apps/{id}/config.
type AdminSiteAppConfigResponse struct {
	ID string `json:"id"`
	// Origin is which decision published the app: a parameter name, or
	// that it was uploaded here.
	Origin string `json:"origin,omitempty"`
	// StoredHere is whether these values are this server's own record
	// of an uploaded app rather than the HTCondor configuration. It is
	// the difference between a change that takes effect now and one
	// that needs condor_reconfig.
	StoredHere bool `json:"stored_here"`
	// Editable is whether this server will accept a PUT for this app.
	Editable bool                  `json:"editable"`
	Settings []AdminSiteAppSetting `json:"settings"`
}

// AdminSiteAppConfigRequest is PUT /api/v1/admin/site-apps/{id}/config.
//
// Keyed by the full parameter name, which is what the page shows. A
// key that is not one of this app's parameters is refused rather than
// ignored: a typo that silently changed nothing would read as a
// setting that does not work.
type AdminSiteAppConfigRequest struct {
	Settings map[string]string `json:"settings"`
}

// adminSiteAppConfig answers an app's settings and where they come from.
func (s *Handler) adminSiteAppConfig(w http.ResponseWriter, r *http.Request, id string) {
	if err := siteapps.ValidateID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.siteApps == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"Site apps are not configured; set HTTP_API_SITE_APPS_DIR")
		return
	}
	entry, ok := s.siteApps.Get(id)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("No site app %q is published", id))
		return
	}

	resp := AdminSiteAppConfigResponse{ID: id, Origin: entry.App.Origin}
	// The values as they were SET, before the bundle's own labels fill
	// in the blanks. The merged app cannot answer this: an empty NAME
	// and a NAME that happens to equal the bundle's look the same once
	// they are merged, and only one of them is a parameter an
	// administrator has to maintain.
	var set siteapps.Policy
	if p, declared := s.siteAppConfigPolicy().Policy(id); declared {
		set = p
	} else if s.siteAppUploads != nil {
		u, found, err := s.siteAppUploads.Get(r.Context(), id)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "site app config", "app", id, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Could not read this app's settings")
			return
		}
		if found {
			resp.StoredHere = true
			resp.Editable = s.siteAppUploadAllowed()
			home, enabled := u.Home, u.Enabled
			set = siteapps.Policy{
				Groups: u.Groups, Home: &home, Enabled: &enabled,
				Name: u.Name, Description: u.Description, Icon: u.Icon,
			}
		}
	}
	resp.Settings = siteAppSettingRows(id, set, entry.App, resp.Editable)
	s.writeJSON(w, http.StatusOK, resp)
}

// siteAppSettingRows renders one app's settings for the page.
func siteAppSettingRows(id string, set siteapps.Policy, app siteapps.App, editable bool) []AdminSiteAppSetting {
	settable := map[string]bool{}
	if editable {
		for _, name := range siteAppSettableSettings {
			settable[name] = true
		}
	}
	out := make([]AdminSiteAppSetting, 0, len(siteAppAllSettings))
	for _, name := range siteAppAllSettings {
		row := AdminSiteAppSetting{
			Key:      siteapps.ConfigKey(id, name),
			Setting:  name,
			Editable: settable[name],
		}
		switch name {
		case "GROUPS":
			row.Value = strings.Join(set.Groups, ", ")
		case "HOME":
			row.Value = boolSettingValue(set.Home)
			row.Effective, row.EffectiveFrom = boolString(app.Home), "default"
		case "ENABLED":
			row.Value = boolSettingValue(set.Enabled)
			// Everything in the listing is published, so the effective
			// answer here is always true; saying so is what keeps an
			// unset ENABLED from reading as "off".
			row.Effective, row.EffectiveFrom = "true", "default"
		case "NAME":
			row.Value, row.Effective, row.EffectiveFrom = set.Name, app.Name, "bundle"
		case "DESCRIPTION":
			row.Value, row.Effective, row.EffectiveFrom = set.Description, app.Description, "bundle"
		case "ICON":
			row.Value, row.Effective, row.EffectiveFrom = set.Icon, app.Icon, "bundle"
		}
		if row.Effective == row.Value {
			row.Effective, row.EffectiveFrom = "", ""
		}
		out = append(out, row)
	}
	return out
}

// boolSettingValue is a tri-state flag as a configuration file writes
// it: "true", "false", or nothing at all when it was never set.
func boolSettingValue(b *bool) string {
	if b == nil {
		return ""
	}
	return boolString(*b)
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// adminSetSiteAppConfig changes an uploaded app's settings.
//
// Only an uploaded app: the configuration is the authority, and an id
// it names is refused here for the same reason an upload for one is --
// otherwise this page would be a way around the decision the
// configuration already made.
func (s *Handler) adminSetSiteAppConfig(w http.ResponseWriter, r *http.Request, id string) {
	if err := siteapps.ValidateID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.siteAppUploadAllowed() {
		s.writeError(w, http.StatusForbidden,
			"This server does not manage site apps through the web interface. An app's settings "+
				"are its HTTP_API_SITE_APP_* parameters; edit them in the configuration and run "+
				"condor_reconfig.")
		return
	}
	if _, declared := s.siteAppConfigPolicy().Policy(id); declared {
		s.writeError(w, http.StatusConflict, fmt.Sprintf(
			"%q is published by this access point's configuration (%s), which takes precedence. "+
				"Change its settings there and run condor_reconfig.",
			id, siteapps.ConfigKey(id, "GROUPS")))
		return
	}

	var req AdminSiteAppConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(req.Settings) == 0 {
		s.writeError(w, http.StatusBadRequest, "No settings were given")
		return
	}

	up, found, err := s.siteAppUploads.Get(r.Context(), id)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "site app config", "app", id, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not read this app's settings")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf(
			"%q was not published through this page, so its settings are not kept here", id))
		return
	}

	// Applied to a copy and written once at the end, so a request with
	// one bad parameter in it changes nothing at all rather than
	// half-applying in map order.
	prefix := siteapps.ConfigKey(id, "")
	for rawKey, value := range req.Settings {
		key := strings.ToUpper(strings.TrimSpace(rawKey))
		setting, ok := strings.CutPrefix(key, prefix)
		if !ok || setting == "" {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf(
				"%q is not a parameter of site app %q; its parameters are named %s and the like",
				rawKey, id, siteapps.ConfigKey(id, "GROUPS")))
			return
		}
		switch setting {
		case "GROUPS":
			groups := siteapps.ParseGroupList(value)
			if len(groups) == 0 {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf(
					"%s names no groups. Name the groups that may see this app, or * for every "+
						"authenticated user; withdraw it to stop serving it.",
					siteapps.ConfigKey(id, "GROUPS")))
				return
			}
			up.Groups = groups
		case "HOME":
			b, ok := config.StringIsBooleanParam(strings.TrimSpace(value))
			if !ok {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf(
					"%s = %q is not a boolean; set it to true or false",
					siteapps.ConfigKey(id, "HOME"), value))
				return
			}
			up.Home = b
		case "NAME":
			up.Name = strings.TrimSpace(value)
		case "DESCRIPTION":
			up.Description = strings.TrimSpace(value)
		case "ICON":
			up.Icon = strings.TrimSpace(value)
		case "ENABLED":
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf(
				"%s cannot be set from here: an app it disables leaves this page with no way "+
					"back. Withdraw the app to stop serving it.", siteapps.ConfigKey(id, "ENABLED")))
			return
		default:
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf(
				"%q is not a setting this page can change; it changes %s",
				rawKey, strings.Join(siteAppSettableSettings, ", ")))
			return
		}
	}

	if err := s.siteAppUploads.Put(r.Context(), up); err != nil {
		s.logger.Error(logging.DestinationHTTP, "site app config", "app", id, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Could not record the change")
		return
	}
	// Worth a log line for the same reason the upload is: who may see
	// an app that runs in their session is a grant, and the access log
	// alone does not say what it was changed to.
	s.logger.Info(logging.DestinationHTTP, "Site app settings changed",
		"app", id, "by", sessionUsername(s, r), "groups", strings.Join(up.Groups, ","),
		"home", up.Home)

	// Reloaded before answering, so the listing in the response is the
	// state the change produced rather than the one before it.
	s.logSiteAppReload(s.siteApps.Reload())
	s.adminListSiteApps(w, r)
}
