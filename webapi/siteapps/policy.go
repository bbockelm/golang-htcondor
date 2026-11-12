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

package siteapps

import (
	"fmt"
	"sort"
	"strings"
)

// Who may see a site app is the site's decision, and it is made in the
// site's configuration rather than in a file beside the bundle.
//
// Every other group gate this server has -- HTTP_API_WEBUI_ACCESS_GROUP,
// HTTP_API_WEBUI_ADMIN_GROUP, HTTP_API_SUPERUSER_GROUP, the MCP ones --
// is an HTTP_API_* parameter. An administrator asked "who can see what
// here?" should be able to answer it from the configuration they
// already audit, with condor_config_val, rather than by reading a
// directory of YAML files. This feature's worst outcome is serving one
// group's science to another, so it is the last place to keep a private
// configuration mechanism.
//
// The bundle still carries app.yaml -- the author's name, description
// and icon. That is a description of what the app is, which its author
// knows; it is not a decision about who may see it, which they cannot.

// PolicySource answers the operator's decision about an app.
//
// It is an interface because the decision has more than one possible
// home. Today the only implementation reads the HTCondor configuration
// (ConfigPolicy), which is the right home for an access point
// provisioned by configuration management. An administrator uploading a
// bundle through the web interface would need somewhere writable --
// a database -- and that is a second implementation of this interface
// rather than a change to the loader.
//
// Where two sources ever disagree about an id, configuration wins:
// otherwise an upload becomes a way around the configuration.
type PolicySource interface {
	// Policy returns the operator's decision for an app id, and whether
	// one was made at all. A bundle whose id has no policy is not
	// published -- see Library.Reload.
	Policy(id string) (Policy, bool)
	// DeclaredIDs lists the ids this source has a policy for, so the
	// loader can report a policy that names no bundle. The strings are
	// in whatever spelling the source uses to identify an app; see
	// ConfigPolicy.DeclaredIDs for what that means there.
	DeclaredIDs() []string
}

// Policy is the operator's decision about one app.
//
// Pointer fields distinguish "the operator set this to false" from "the
// operator said nothing", which matters for Enabled: a plain bool's
// zero value would make every app that does not mention it disabled.
type Policy struct {
	// Groups may see the app. "*" means every authenticated user.
	Groups []string
	// Home sends members of an app-only group here rather than to the
	// dashboard.
	Home *bool
	// Enabled defaults to true when the operator says nothing.
	Enabled *bool
	// Name, Description and Icon override what the bundle calls itself,
	// for a site that wants its own wording.
	Name        string
	Description string
	Icon        string
	// Origin names where this policy came from, for a log line or an
	// administrator asking why an app is visible.
	Origin string
}

// IsEnabled reports whether the policy publishes the app. Saying
// nothing means enabled: an operator who named groups at all meant to
// publish the app, and should not have to say so twice.
func (p Policy) IsEnabled() bool { return p.Enabled == nil || *p.Enabled }

// ParseGroupList splits a configured group list.
//
// Commas separate; surrounding whitespace is trimmed, because a list
// written to be read by a human ("smith_lab, jones_lab") should mean
// what it looks like. Empty entries are dropped, so a trailing comma is
// not a group named "".
//
// This is the rule every other configured group list in this server
// follows; httpserver.parseGroupList calls through to it so there is
// one implementation rather than two that can drift.
func ParseGroupList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	groups := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			groups = append(groups, p)
		}
	}
	if len(groups) == 0 {
		return nil
	}
	return groups
}

// configPrefix is where an app's parameters live. An app "cryoem" is
// configured by HTTP_API_SITE_APP_CRYOEM_GROUPS and its siblings.
const configPrefix = "HTTP_API_SITE_APP_"

// MacroID is the id as it appears inside a configuration parameter
// name: upper-cased, with hyphens turned into underscores.
//
// Both substitutions are forced on us. HTCondor parameter names are
// case-insensitive, and a hyphen inside one is legal to set but reads
// as subtraction wherever a name is used in an expression. An id is
// already restricted to lowercase letters, digits, hyphen and
// underscore (ValidateID), so this mapping is total.
//
// It is not injective: "my-app" and "my_app" are different bundles and
// the same parameter name. Library.Reload refuses both rather than
// letting one silently take the other's policy -- see MacroCollision.
func MacroID(id string) string {
	return strings.ToUpper(strings.ReplaceAll(id, "-", "_"))
}

// ConfigKey is the full parameter name for one of an app's settings,
// e.g. ConfigKey("cryoem", "GROUPS").
func ConfigKey(id, setting string) string {
	return configPrefix + MacroID(id) + "_" + setting
}

// MacroCollision reports ids that share a configuration parameter name,
// keyed by that shared name. An empty result means every id maps to a
// name of its own.
//
// Two bundles whose ids differ only by hyphen-versus-underscore are a
// configuration the operator cannot express: there is one
// HTTP_API_SITE_APP_MY_APP_GROUPS and two apps wanting it. Refusing
// both is the fail-closed answer -- publishing either would be
// publishing it under a policy that might have been written for the
// other.
func MacroCollision(ids []string) map[string][]string {
	byMacro := map[string][]string{}
	for _, id := range ids {
		m := MacroID(id)
		byMacro[m] = append(byMacro[m], id)
	}
	out := map[string][]string{}
	for m, group := range byMacro {
		if len(group) > 1 {
			sort.Strings(group)
			out[m] = group
		}
	}
	return out
}

// Params is the part of the HTCondor configuration this package reads.
// *config.Config satisfies it.
//
// An interface rather than the concrete type so the loader's tests can
// state a configuration as a map, and so a reconfigure can install a
// freshly-read configuration without this package knowing how one is
// loaded.
type Params interface {
	Get(key string) (string, bool)
	GetBool(key string, def bool) bool
	Keys() []string
}

// ConfigPolicy reads app policy from the HTCondor configuration.
//
//	HTTP_API_SITE_APP_CRYOEM_GROUPS      = smith_lab, jones_lab
//	HTTP_API_SITE_APP_CRYOEM_HOME        = true
//	HTTP_API_SITE_APP_CRYOEM_ENABLED     = false
//	HTTP_API_SITE_APP_CRYOEM_NAME        = CryoEM pipeline
//	HTTP_API_SITE_APP_CRYOEM_DESCRIPTION = Submit a reconstruction
//	HTTP_API_SITE_APP_CRYOEM_ICON        = microscope
//
// GROUPS is what makes an app exist as far as this source is concerned.
// The others are modifiers on an app that is already declared, so a
// stray HTTP_API_SITE_APP_TYPO_HOME publishes nothing.
type ConfigPolicy struct{ params Params }

// NewConfigPolicy reads policy from a configuration. A nil params
// yields a source that declares nothing, which publishes no apps --
// the same answer as a configuration that mentions none.
func NewConfigPolicy(params Params) *ConfigPolicy { return &ConfigPolicy{params: params} }

// Policy implements PolicySource.
func (c *ConfigPolicy) Policy(id string) (Policy, bool) {
	if c == nil || c.params == nil {
		return Policy{}, false
	}
	key := ConfigKey(id, "GROUPS")
	raw, ok := c.params.Get(key)
	if !ok || strings.TrimSpace(raw) == "" {
		// An empty GROUPS is not "nobody": far more likely a mistake,
		// and treating it as undeclared means Library.Reload reports it
		// the same way it reports a bundle nobody has configured.
		return Policy{}, false
	}
	p := Policy{
		Groups: ParseGroupList(raw),
		Origin: key,
	}
	if home := c.params.GetBool(ConfigKey(id, "HOME"), false); home {
		p.Home = &home
	}
	if _, set := c.params.Get(ConfigKey(id, "ENABLED")); set {
		enabled := c.params.GetBool(ConfigKey(id, "ENABLED"), true)
		p.Enabled = &enabled
	}
	p.Name = configString(c.params, ConfigKey(id, "NAME"))
	p.Description = configString(c.params, ConfigKey(id, "DESCRIPTION"))
	p.Icon = configString(c.params, ConfigKey(id, "ICON"))
	return p, true
}

// DeclaredIDs implements PolicySource. The strings are macro ids --
// CRYOEM, not cryoem -- because a parameter name cannot be turned back
// into a file name: HTTP_API_SITE_APP_MY_APP_GROUPS could have been
// written for "my-app" or "my_app". The loader compares them against
// MacroID of each bundle it found, and reports what the operator typed.
func (c *ConfigPolicy) DeclaredIDs() []string {
	if c == nil || c.params == nil {
		return nil
	}
	var out []string
	for _, k := range c.params.Keys() {
		up := strings.ToUpper(k)
		if !strings.HasPrefix(up, configPrefix) || !strings.HasSuffix(up, "_GROUPS") {
			continue
		}
		macro := strings.TrimSuffix(strings.TrimPrefix(up, configPrefix), "_GROUPS")
		if macro == "" || !plausibleMacroID(macro) {
			// Not a name MacroID could ever produce, so it names no
			// app that could exist. Reporting it as a policy without a
			// bundle would send the operator looking for a file that
			// was never the point.
			continue
		}
		if raw, ok := c.params.Get(k); !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		out = append(out, macro)
	}
	sort.Strings(out)
	return out
}

// UnconfiguredMessage is what an operator is told about a bundle with
// no policy: the exact line to add, rather than a description of it.
func UnconfiguredMessage(id, bundle string) error {
	return fmt.Errorf("site app %q: %s is present but no configuration names who may see it; "+
		"not published. Set %s to the groups that may see it, or to * for every "+
		"authenticated user, then run condor_reconfig",
		id, bundle, ConfigKey(id, "GROUPS"))
}

func configString(p Params, key string) string {
	v, ok := p.Get(key)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// plausibleMacroID reports whether a macro name could have come from a
// valid app id -- that is, whether MacroID of some id ValidateID
// accepts produces it. Ids are lowercase letters, digits, hyphen and
// underscore, so their macro names hold only upper-case letters,
// digits and underscore.
func plausibleMacroID(macro string) bool {
	for _, r := range macro {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}
