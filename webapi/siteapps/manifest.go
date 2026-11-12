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
// It deliberately has no Groups field and no ID. Who may see an app is
// the site's decision, made in the site's configuration (see Policy);
// the id comes from the bundle's file name.
type BundleManifest struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Icon        string `yaml:"icon"`
	// Version and Revision are the author's own labels for this build
	// -- a release number and whatever identifies the source it came
	// from, typically a git describe or commit. Both are free-form and
	// both are optional: an older bundle has neither.
	//
	// Nothing in the server reads them. They exist to be recorded, so
	// that "which build of this app was running in October?" is
	// answerable from the audit trail without having kept the
	// artifacts. A digest identifies a build uniquely but tells a
	// human nothing.
	Version  string `yaml:"version"`
	Revision string `yaml:"revision"`
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
	// Version and Revision are the bundle's own labels, carried
	// through for the audit trail.
	Version  string
	Revision string
	// Origin names where the policy that published this app came
	// from, for the audit trail and for an administrator asking why
	// an app is visible.
	Origin string
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
func Merge(id string, bundle BundleManifest, policy Policy) (App, error) {
	if err := ValidateID(id); err != nil {
		return App{}, err
	}

	groups := make([]string, 0, len(policy.Groups))
	for _, g := range policy.Groups {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	if len(groups) == 0 {
		return App{}, fmt.Errorf("site app %q: %s names no groups; set it to the groups "+
			"that may see the app, or to * for every authenticated user",
			id, firstNonEmpty(policy.Origin, ConfigKey(id, "GROUPS")))
	}

	app := App{
		ID:          id,
		Name:        firstNonEmpty(policy.Name, bundle.Name, id),
		Description: firstNonEmpty(policy.Description, bundle.Description),
		Icon:        firstNonEmpty(policy.Icon, bundle.Icon),
		Groups:      groups,
		Version:     strings.TrimSpace(bundle.Version),
		Revision:    strings.TrimSpace(bundle.Revision),
		Origin:      policy.Origin,
	}
	if policy.Home != nil {
		app.Home = *policy.Home
	}
	return app, nil
}

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
				"who may see an app is the site's decision, made in the site's configuration (%w)", err)
		}
		return BundleManifest{}, fmt.Errorf("app.yaml: %w", err)
	}
	if strings.TrimSpace(m.Name) == "" {
		return BundleManifest{}, fmt.Errorf("app.yaml names no app")
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
