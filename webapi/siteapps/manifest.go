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

// Package siteapps serves site-authored static web apps from zip
// bundles, scoped to authorization groups.
//
// A site app is somebody else's web application -- a lab's submission
// interface, a facility's dashboard -- served by this server, at
// /site/<id>/, to the groups an operator names. The server does not
// build it, run it, or know anything about it beyond where it lives
// and who may see it.
//
// The deployment unit is one zip file dropped into a directory, which
// is the WAR file's idea: copying a directory tree into a live
// server's content root is a sequence of non-atomic operations with a
// window in the middle where index.html is new and half the chunks it
// references are old. A rename over one file has no such window.
package siteapps

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// BundleManifest is app.yaml INSIDE the bundle, written by the app's
// author. It describes what the app is.
//
// It deliberately has no Groups field and no ID. See SiteManifest for
// groups; the id comes from the bundle's file name.
type BundleManifest struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Icon        string `yaml:"icon"`
}

// SiteManifest is <id>.yaml BESIDE the bundle, written by the
// operator. It decides what the app is allowed to be.
//
// Pointer fields distinguish "the operator wrote false" from "the
// operator wrote nothing", which matters for Enabled: the zero value
// of a bool would make every manifest that omits it mean "disabled".
type SiteManifest struct {
	// Groups may see the app. "*" means every authenticated user.
	//
	// Operator-only and required: see Merge.
	Groups []string `yaml:"groups"`
	// Home sends members here instead of the dashboard.
	Home *bool `yaml:"home"`
	// Enabled defaults to true when absent.
	Enabled *bool `yaml:"enabled"`
	// Name and Description override the bundle's, for a site that wants
	// to call an app something else in its own users' terms.
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Icon        string `yaml:"icon"`
}

// App is one loaded, publishable site app.
type App struct {
	// ID is the bundle's file name without its extension, and the path
	// segment it is served under.
	ID          string
	Name        string
	Description string
	Icon        string
	Groups      []string
	Home        bool
	// Digest is the bundle's SHA-256, when a .sha256 sidecar was
	// present and verified. Empty when the bundle was loaded
	// unverified or is a directory.
	Digest string
}

// wildcardGroup in a site manifest's Groups means every authenticated
// user, as distinct from an empty list, which means nobody.
const wildcardGroup = "*"

// Merge combines the two manifests into a publishable App.
//
// The site manifest wins key by key, so an operator who only needs to
// set Groups writes only Groups and inherits the author's name and
// description.
//
// Groups is the exception that gives this package its shape: it is
// read ONLY from the site manifest, and a bundle that names groups is
// ignored rather than merged. The app's author ships a manifest and
// has no idea which groups exist at a given site; their natural
// placeholder is "everyone". If groups were inheritable, an operator
// who dropped a bundle in and forgot the policy file would publish
// whatever the author happened to write. Making it operator-only means
// that failure cannot happen, rather than being documented against.
//
// An empty Groups is an error, not "nobody": a site manifest that
// names no groups is far more likely to be a mistake than a deliberate
// request to publish an app to no one, and failing loudly at load is
// how the operator finds out.
func Merge(id string, bundle BundleManifest, site SiteManifest) (App, error) {
	if err := ValidateID(id); err != nil {
		return App{}, err
	}

	groups := make([]string, 0, len(site.Groups))
	for _, g := range site.Groups {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	if len(groups) == 0 {
		return App{}, fmt.Errorf("site app %q: its policy file names no groups; "+
			"write groups: [\"*\"] to publish it to every authenticated user", id)
	}

	app := App{
		ID:          id,
		Name:        firstNonEmpty(site.Name, bundle.Name, id),
		Description: firstNonEmpty(site.Description, bundle.Description),
		Icon:        firstNonEmpty(site.Icon, bundle.Icon),
		Groups:      groups,
	}
	if site.Home != nil {
		app.Home = *site.Home
	}
	return app, nil
}

// Enabled reports whether the site manifest publishes the app. Absent
// means enabled: an operator who wrote a policy file at all meant to
// publish the app, and should not have to say so twice.
func (s SiteManifest) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// VisibleTo reports whether a caller holding these groups may see the
// app.
//
// Comparison is case-insensitive because the group sources are not
// consistent with each other: a Unix group, a file, and an OIDC claim
// disagree about case often enough that an operator typing the group
// name the way their IdP shows it should not silently publish nothing.
func (a App) VisibleTo(callerGroups []string) bool {
	for _, want := range a.Groups {
		if want == wildcardGroup {
			return true
		}
		for _, have := range callerGroups {
			if strings.EqualFold(want, have) {
				return true
			}
		}
	}
	return false
}

// ParseBundleManifest reads app.yaml from inside a bundle.
//
// Unknown fields are refused. The most likely unknown field is
// "groups", written by an author who assumed it would work; failing
// loudly tells them it does not, where ignoring it would leave them
// believing their app is scoped when the site manifest alone decides.
func ParseBundleManifest(data []byte) (BundleManifest, error) {
	var m BundleManifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil && !errors.Is(err, io.EOF) {
		// io.EOF is an empty document, not a parse failure. Letting it
		// through means an empty file falls to the name check below and
		// gets an error about what is missing, rather than "EOF".
		if strings.Contains(err.Error(), "field groups not found") {
			return BundleManifest{}, fmt.Errorf("app.yaml names groups, which a bundle cannot set: "+
				"who may see an app is the site's decision, written in its policy file beside the bundle (%w)", err)
		}
		return BundleManifest{}, fmt.Errorf("app.yaml: %w", err)
	}
	if strings.TrimSpace(m.Name) == "" {
		return BundleManifest{}, fmt.Errorf("app.yaml names no app")
	}
	return m, nil
}

// ParseSiteManifest reads the operator's <id>.yaml.
func ParseSiteManifest(data []byte) (SiteManifest, error) {
	var m SiteManifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	// io.EOF means the file is empty. That is a policy file naming no
	// groups, which Merge refuses with a message saying what to write
	// -- a better answer for `touch cryoem.yaml` than "EOF".
	if err := dec.Decode(&m); err != nil && !errors.Is(err, io.EOF) {
		return SiteManifest{}, fmt.Errorf("policy file: %w", err)
	}
	return m, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
