package connectors

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/oauth2"
)

// Reading connector definitions out of the HTCondor configuration.
//
// Nothing here is snapshotted into a struct of its own: a ConfigSource
// holds the Params and reads on each lookup, as siteapps.ConfigPolicy
// does, so there is one copy of the answer and no second one to go
// stale. A reconfigure replaces the whole source rather than mutating
// it -- see SetConnectorConfig in the HTTP server.

// Params is the part of the HTCondor configuration this package reads.
// *config.Config satisfies it.
//
// An interface rather than the concrete type so tests can state a
// configuration as a map, and so a reconfigure can install a
// freshly-read configuration without this package knowing how one is
// loaded.
type Params interface {
	Get(key string) (string, bool)
	GetBool(key string, def bool) bool
	Keys() []string
}

// Definition is one connector as this server will act on it: the shipped
// definition where there is one, with the operator's settings applied.
type Definition struct {
	ID   ID
	Kind Kind

	ClientID string
	// ClientSecretFile is where the bytes are. The bytes are NOT here
	// and never travel with a Definition: configuration values are
	// public, which is the whole reason the secret is a path.
	ClientSecretFile string

	AuthorizationURL string
	TokenURL         string
	Scopes           []string

	// Groups may use this connector. Empty means nobody, which is what
	// an absent setting means; "*" means every authenticated user.
	Groups []string

	Transfer Transfer
	Enabled  bool

	// Service is the credd service name this connector's credentials are
	// stored under. See ID.Service.
	Service string

	// Origin is the configuration parameter that declared this
	// connector, for the admin page to show and for an operator to grep
	// for afterwards.
	Origin string

	// AuthStyle is how client credentials go on a token request. The
	// zero value means probe; see BuiltinDef.AuthStyle for why that is
	// worth avoiding where the provider is known.
	AuthStyle oauth2.AuthStyle
}

// ClientSecret reads the secret from disk.
//
// A method rather than a field, deliberately. The bytes are re-read on
// each use so a rotated secret at an unchanged path takes effect without
// a restart -- a diff of the configuration cannot see an edit to a file
// the configuration merely names.
func (d Definition) ClientSecret() ([]byte, error) {
	if d.ClientSecretFile == "" {
		return nil, fmt.Errorf("connector %s has no %s", d.ID, d.ID.ConfigKey("CLIENT_SECRET_FILE"))
	}
	b, err := os.ReadFile(d.ClientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("connector %s: reading %s: %w",
			d.ID, d.ID.ConfigKey("CLIENT_SECRET_FILE"), err)
	}
	return []byte(strings.TrimSpace(string(b))), nil
}

// Permits reports whether a caller in these groups may use the
// connector.
//
// Evaluated against CURRENT membership every time, never against a list
// snapshotted when the credential was granted: a snapshot catches an
// operator changing the policy and misses a user being removed from the
// group, which is the half that matters for taking access away.
func (d Definition) Permits(memberOf []string) bool {
	if len(d.Groups) == 0 {
		return false
	}
	for _, g := range d.Groups {
		if g == wildcardGroup {
			return true
		}
		for _, has := range memberOf {
			if strings.EqualFold(g, has) {
				return true
			}
		}
	}
	return false
}

// wildcardGroup in a connector's group list means every authenticated
// user. Spelled the same as site apps spells it.
const wildcardGroup = "*"

// ConfigSource reads connector definitions from the HTCondor
// configuration.
type ConfigSource struct {
	params Params
	prefix string
}

// NewConfigSource builds a source over a configuration.
//
// The nil check on params is load-bearing, exactly as it is in
// siteapps.configPolicyFor: a nil *config.Config placed in a Params
// interface makes an interface that is NOT nil, so every lookup would
// call a method on a nil pointer rather than finding nothing. A server
// with no HTCondor configuration declares no connectors instead.
func NewConfigSource(params Params) *ConfigSource {
	src := &ConfigSource{params: params, prefix: DefaultServicePrefix}
	if params != nil {
		if v, ok := params.Get("HTTP_API_CONNECTOR_PREFIX"); ok && strings.TrimSpace(v) != "" {
			src.prefix = strings.TrimSpace(v)
		}
	}
	return src
}

// ServicePrefix is the credd service-name prefix in force.
func (c *ConfigSource) ServicePrefix() string {
	if c == nil || c.prefix == "" {
		return DefaultServicePrefix
	}
	return c.prefix
}

// IDs lists the connectors the configuration declares, in a fixed order.
//
// Driven by HTTP_API_CONNECTORS rather than by scanning for parameter
// names, so a half-written connector -- a CLIENT_ID typed but the
// connector not yet listed -- is not picked up. The listing is the
// operator saying "this one is ready".
func (c *ConfigSource) IDs() []ID {
	if c == nil || c.params == nil {
		return nil
	}
	raw, ok := c.params.Get("HTTP_API_CONNECTORS")
	if !ok {
		return nil
	}
	var out []ID
	seen := map[string]bool{}
	for _, tok := range splitList(raw) {
		id, err := ParseID(tok)
		if err != nil {
			// A malformed entry is skipped here and reported by
			// Validate, which has somewhere to put the message.
			continue
		}
		if seen[id.String()] {
			continue
		}
		seen[id.String()] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Definition returns the configuration's definition of one connector,
// and whether the configuration declares it at all.
func (c *ConfigSource) Definition(id ID) (Definition, bool) {
	if c == nil || c.params == nil {
		return Definition{}, false
	}
	declared := false
	for _, got := range c.IDs() {
		if got == id {
			declared = true
			break
		}
	}
	if !declared {
		return Definition{}, false
	}

	d := Definition{
		ID:       id,
		Enabled:  true,
		Transfer: TransferSpool,
		Service:  id.Service(c.ServicePrefix()),
		Origin:   "HTTP_API_CONNECTORS",
	}

	// A builtin supplies everything the operator should not have to
	// know. A site connector supplies nothing and must say all of it.
	if def, ok := Lookup(id); ok {
		d.Kind = def.Kind
		d.AuthorizationURL = def.AuthorizationURL
		d.TokenURL = def.TokenURL
		d.Scopes = append([]string(nil), def.DefaultScopes...)
		d.AuthStyle = def.AuthStyle
	}

	if v, ok := c.get(id, "KIND"); ok {
		d.Kind = Kind(strings.ToLower(v))
	}
	if v, ok := c.get(id, "CLIENT_ID"); ok {
		d.ClientID = v
	}
	if v, ok := c.get(id, "CLIENT_SECRET_FILE"); ok {
		d.ClientSecretFile = v
	}
	if v, ok := c.get(id, "AUTHORIZATION_URL"); ok {
		d.AuthorizationURL = v
	}
	if v, ok := c.get(id, "TOKEN_URL"); ok {
		d.TokenURL = v
	}
	if v, ok := c.get(id, "SCOPES"); ok {
		d.Scopes = splitList(v)
	}
	if v, ok := c.get(id, "GROUPS"); ok {
		d.Groups = splitList(v)
	}
	if v, ok := c.get(id, "TRANSFER"); ok {
		d.Transfer = Transfer(strings.ToLower(strings.TrimSpace(v)))
	}
	d.Enabled = c.params.GetBool(id.ConfigKey("ENABLED"), true)

	return d, true
}

// get reads one of a connector's settings, treating a value that
// expands to nothing as unset.
func (c *ConfigSource) get(id ID, setting string) (string, bool) {
	v, ok := c.params.Get(id.ConfigKey(setting))
	if !ok {
		return "", false
	}
	if v = strings.TrimSpace(v); v == "" {
		return "", false
	}
	return v, true
}

// splitList reads a comma-separated or JSON-array list, the way site
// apps reads a group list. Whitespace around an item is not part of it.
func splitList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if items, ok := parseJSONList(raw); ok {
		return items
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
