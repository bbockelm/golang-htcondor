package connectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeParams is a configuration stated as a map.
type fakeParams map[string]string

func (f fakeParams) Get(key string) (string, bool) {
	v, ok := f[strings.ToUpper(key)]
	return v, ok
}

func (f fakeParams) GetBool(key string, def bool) bool {
	v, ok := f.Get(key)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return def
}

func (f fakeParams) Keys() []string {
	out := make([]string, 0, len(f))
	for k := range f {
		out = append(out, k)
	}
	return out
}

func TestConfigSourceListsOnlyWhatIsListed(t *testing.T) {
	// A CLIENT_ID typed for a connector that is not in HTTP_API_CONNECTORS
	// is a half-written configuration, not a connector. The listing is
	// the operator saying it is ready.
	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS":                        "builtin:gdrive",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_GROUPS":   "smith_lab",
		"HTTP_API_CONNECTOR_SITE_HALFDONE_CLIENT_ID": "abc",
	})

	ids := src.IDs()
	if len(ids) != 1 || ids[0].String() != "builtin:gdrive" {
		t.Fatalf("IDs() = %v, want only builtin:gdrive", ids)
	}
	if _, ok := src.Definition(ID{Site, "halfdone"}); ok {
		t.Error("a connector that is not listed was defined anyway")
	}
}

func TestBuiltinSuppliesWhatTheOperatorShouldNotKnow(t *testing.T) {
	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS":                         "builtin:gdrive",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_CLIENT_ID": "1234.apps.googleusercontent.com",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_GROUPS":    "smith_lab",
	})

	d, ok := src.Definition(MustParse("builtin:gdrive"))
	if !ok {
		t.Fatal("builtin:gdrive was not defined")
	}
	if d.Kind != KindOAuth2 {
		t.Errorf("Kind = %q, want oauth2", d.Kind)
	}
	if d.AuthorizationURL == "" || d.TokenURL == "" {
		t.Error("a builtin must supply its own endpoints")
	}
	if len(d.Scopes) != 1 || !strings.HasSuffix(d.Scopes[0], "/drive.file") {
		t.Errorf("Scopes = %v, want the narrow drive.file default", d.Scopes)
	}
	if d.Service != "webapi_builtin_gdrive" {
		t.Errorf("Service = %q, want webapi_builtin_gdrive", d.Service)
	}
	// spool is the default because it needs nothing deployed anywhere
	// and keeps third-party tokens off execute nodes.
	if d.Transfer != TransferSpool {
		t.Errorf("Transfer = %q, want spool by default", d.Transfer)
	}
}

func TestOperatorOverridesTheBuiltinScopes(t *testing.T) {
	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS":                      "builtin:gdrive",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_SCOPES": "https://www.googleapis.com/auth/drive.readonly",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_GROUPS": "*",
	})
	d, _ := src.Definition(MustParse("builtin:gdrive"))
	if len(d.Scopes) != 1 || !strings.HasSuffix(d.Scopes[0], "drive.readonly") {
		t.Errorf("Scopes = %v, want the operator's override", d.Scopes)
	}
}

func TestSiteConnectorSuppliesEverything(t *testing.T) {
	src := NewConfigSource(fakeParams{ //nolint:gosec // G101: test endpoints, not credentials
		"HTTP_API_CONNECTORS":                              "site:cryoem",
		"HTTP_API_CONNECTOR_SITE_CRYOEM_KIND":              "oauth2",
		"HTTP_API_CONNECTOR_SITE_CRYOEM_AUTHORIZATION_URL": "https://example.org/auth",
		"HTTP_API_CONNECTOR_SITE_CRYOEM_TOKEN_URL":         "https://example.org/token",
		"HTTP_API_CONNECTOR_SITE_CRYOEM_SCOPES":            "read, write",
		"HTTP_API_CONNECTOR_SITE_CRYOEM_GROUPS":            `["smith_lab","jones_lab"]`,
	})
	d, ok := src.Definition(MustParse("site:cryoem"))
	if !ok {
		t.Fatal("site:cryoem was not defined")
	}
	if d.Kind != KindOAuth2 || d.TokenURL != "https://example.org/token" {
		t.Errorf("definition = %+v, want the operator's values", d)
	}
	if len(d.Scopes) != 2 {
		t.Errorf("Scopes = %v, want both", d.Scopes)
	}
	// A group list may be a JSON array or a comma list; both forms read
	// the same, as they do for site apps.
	if len(d.Groups) != 2 || d.Groups[0] != "smith_lab" {
		t.Errorf("Groups = %v, want the JSON array parsed", d.Groups)
	}
	// A site connector gets no builtin's endpoints by accident.
	if d.Service != "webapi_site_cryoem" {
		t.Errorf("Service = %q", d.Service)
	}
}

func TestServicePrefixIsConfigurable(t *testing.T) {
	// Two API servers in front of one access point would otherwise
	// collide with each other, having both avoided the administrator.
	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS":       "builtin:gdrive",
		"HTTP_API_CONNECTOR_PREFIX": "api2",
	})
	d, _ := src.Definition(MustParse("builtin:gdrive"))
	if d.Service != "api2_builtin_gdrive" {
		t.Errorf("Service = %q, want the configured prefix", d.Service)
	}
}

// --- groups -----------------------------------------------------------

func TestAbsentGroupsMeansNobody(t *testing.T) {
	// Not "everyone". A connector puts a consent screen in front of a
	// user and carries a client registration; a missing line must not
	// offer that to the whole access point.
	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS": "builtin:gdrive",
	})
	d, ok := src.Definition(MustParse("builtin:gdrive"))
	if !ok {
		t.Fatal("not defined")
	}
	if len(d.Groups) != 0 {
		t.Fatalf("Groups = %v, want none", d.Groups)
	}
	if d.Permits([]string{"smith_lab"}) {
		t.Error("a connector with no groups admitted somebody")
	}
	if d.Permits(nil) {
		t.Error("a connector with no groups admitted a caller in no groups")
	}
}

func TestEmptyGroupsMeansNobody(t *testing.T) {
	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS":                      "builtin:gdrive",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_GROUPS": "   ",
	})
	d, _ := src.Definition(MustParse("builtin:gdrive"))
	if d.Permits([]string{"smith_lab"}) {
		t.Error("an empty group list admitted somebody")
	}
}

func TestGroupsAdmitAndRefuse(t *testing.T) {
	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS":                      "builtin:gdrive",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_GROUPS": "smith_lab, jones_lab",
	})
	d, _ := src.Definition(MustParse("builtin:gdrive"))

	if !d.Permits([]string{"jones_lab"}) {
		t.Error("a member of a listed group was refused")
	}
	if !d.Permits([]string{"other", "SMITH_LAB"}) {
		t.Error("group matching should not depend on case")
	}
	if d.Permits([]string{"other"}) {
		t.Error("a caller in no listed group was admitted")
	}
	if d.Permits(nil) {
		t.Error("a caller in no groups at all was admitted")
	}
}

func TestWildcardGroupAdmitsEveryAuthenticatedUser(t *testing.T) {
	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS":                      "builtin:gdrive",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_GROUPS": "*",
	})
	d, _ := src.Definition(MustParse("builtin:gdrive"))
	if !d.Permits([]string{"anything"}) || !d.Permits(nil) {
		t.Error(`"*" should admit every authenticated caller`)
	}
}

// --- the secret -------------------------------------------------------

func TestClientSecretIsReadFromDiskNotConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gdrive.secret")
	if err := os.WriteFile(path, []byte("  s3cret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS": "builtin:gdrive",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_CLIENT_SECRET_FILE": path,
	})
	d, _ := src.Definition(MustParse("builtin:gdrive"))

	got, err := d.ClientSecret()
	if err != nil {
		t.Fatalf("ClientSecret: %v", err)
	}
	if string(got) != "s3cret" {
		t.Errorf("ClientSecret = %q, want the file's contents trimmed", got)
	}
}

func TestClientSecretIsRereadSoRotationTakesEffect(t *testing.T) {
	// The path is in the configuration; the bytes are not. A diff of the
	// configuration cannot see an edit to the file, so the only way a
	// rotated secret takes effect without a restart is to re-read it.
	dir := t.TempDir()
	path := filepath.Join(dir, "s")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	src := NewConfigSource(fakeParams{
		"HTTP_API_CONNECTORS": "builtin:gdrive",
		"HTTP_API_CONNECTOR_BUILTIN_GDRIVE_CLIENT_SECRET_FILE": path,
	})
	d, _ := src.Definition(MustParse("builtin:gdrive"))

	if got, _ := d.ClientSecret(); string(got) != "old" {
		t.Fatalf("first read = %q", got)
	}
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := d.ClientSecret()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("after rotation ClientSecret = %q, want %q -- the secret is cached", got, "new")
	}
}

func TestMissingSecretFileNamesTheParameter(t *testing.T) {
	src := NewConfigSource(fakeParams{"HTTP_API_CONNECTORS": "builtin:gdrive"})
	d, _ := src.Definition(MustParse("builtin:gdrive"))
	_, err := d.ClientSecret()
	if err == nil {
		t.Fatal("a connector with no secret file returned one anyway")
	}
	if !strings.Contains(err.Error(), "CLIENT_SECRET_FILE") {
		t.Errorf("error = %q, want it to name the parameter to set", err)
	}
}

// --- the nil trap -----------------------------------------------------

// A nil *config.Config placed in a Params interface makes an interface
// that is NOT nil, so every lookup would call a method on a nil pointer.
// A server with no HTCondor configuration must declare no connectors
// instead of panicking.
func TestNoConfigurationDeclaresNoConnectors(t *testing.T) {
	src := NewConfigSource(nil)
	if ids := src.IDs(); len(ids) != 0 {
		t.Errorf("IDs() = %v, want none", ids)
	}
	if _, ok := src.Definition(MustParse("builtin:gdrive")); ok {
		t.Error("a connector was defined with no configuration at all")
	}
	if src.ServicePrefix() != DefaultServicePrefix {
		t.Errorf("ServicePrefix() = %q", src.ServicePrefix())
	}
}

func TestNilSourceIsSafe(t *testing.T) {
	var src *ConfigSource
	if ids := src.IDs(); len(ids) != 0 {
		t.Errorf("IDs() on a nil source = %v", ids)
	}
	if _, ok := src.Definition(MustParse("builtin:gdrive")); ok {
		t.Error("a nil source defined a connector")
	}
}
