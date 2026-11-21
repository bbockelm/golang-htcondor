package connectors

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseID(t *testing.T) {
	tests := []struct {
		in      string
		want    ID
		wantErr string // a substring; "" means it should parse
	}{
		{in: "builtin:gdrive", want: ID{Builtin, "gdrive"}},
		{in: "site:cryoem", want: ID{Site, "cryoem"}},
		{in: "site:my-app", want: ID{Site, "my-app"}},
		{in: "site:my_app", want: ID{Site, "my_app"}},
		{in: "site:a1", want: ID{Site, "a1"}},

		{in: "gdrive", wantErr: "no namespace"},
		{in: "", wantErr: "no namespace"},
		{in: ":gdrive", wantErr: "no namespace"},
		{in: "nope:gdrive", wantErr: "not one of"},
		{in: "BUILTIN:gdrive", wantErr: "not one of"},
		{in: "builtin:", wantErr: "is empty"},
		{in: "builtin:GDrive", wantErr: "begin and end"},
		{in: "builtin:g drive", wantErr: "may use only"},
		{in: "builtin:a/b", wantErr: "may use only"},
		// Split on the FIRST colon, so a second one is reported as a bad
		// character rather than swallowed into the name.
		{in: "builtin:a:b", wantErr: "may use only"},
		{in: "site:-lead", wantErr: "begin and end"},
		{in: "site:trail-", wantErr: "begin and end"},
		{in: "site:_lead", wantErr: "begin and end"},
		{in: "site:" + strings.Repeat("a", maxNameLen+1), wantErr: "longer than"},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseID(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseID(%q) = %v, want an error containing %q", tc.in, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("ParseID(%q) error = %q, want it to contain %q", tc.in, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseID(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseID(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
			if got.String() != tc.in {
				t.Errorf("round trip: %q -> %+v -> %q", tc.in, got, got.String())
			}
		})
	}
}

// An unknown namespace is refused rather than passed through.
//
// The closedness of `builtin` is what lets a shipped definition be
// corrected in a release. A namespace nobody declared would quietly
// become a third kind of connector with no rules attached to it.
func TestUnknownNamespaceIsRefused(t *testing.T) {
	for _, ns := range []string{"vendor", "catalogue", "Builtin", "site "} {
		if _, err := ParseID(ns + ":thing"); err == nil {
			t.Errorf("namespace %q was accepted; the set has to stay closed", ns)
		}
	}
}

// A bare id is a syntactically valid URL with a scheme, so it must never
// be used as a relative reference. This test exists to keep that fact in
// front of whoever next builds a link to one.
func TestIDIsNotAUsableRelativeReference(t *testing.T) {
	id := MustParse("builtin:gdrive")

	u, err := url.Parse(id.String())
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", id, err)
	}
	if u.Scheme != "builtin" || u.Opaque != "gdrive" || u.Path != "" {
		t.Fatalf("url.Parse(%q) = scheme %q opaque %q path %q; this test is "+
			"guarding the claim that a bare id parses as a SCHEME, and it no "+
			"longer does -- check whether the id format changed",
			id, u.Scheme, u.Opaque, u.Path)
	}

	// As a path segment, which is the only way it may be used, it is
	// the ordinary thing.
	u2, err := url.Parse("/api/v1/connect/" + id.String())
	if err != nil {
		t.Fatalf("url.Parse of the path form: %v", err)
	}
	if u2.Scheme != "" || u2.Path != "/api/v1/connect/builtin:gdrive" {
		t.Errorf("path form = scheme %q path %q, want no scheme and the full path",
			u2.Scheme, u2.Path)
	}
}

func TestConfigKey(t *testing.T) {
	tests := []struct {
		id      ID
		setting string
		want    string
	}{
		{ID{Builtin, "gdrive"}, "GROUPS", "HTTP_API_CONNECTOR_BUILTIN_GDRIVE_GROUPS"},
		{ID{Site, "cryoem"}, "KIND", "HTTP_API_CONNECTOR_SITE_CRYOEM_KIND"},
		// A hyphen is legal to set in a parameter name but reads as
		// subtraction wherever a name appears in an expression, so it
		// becomes an underscore.
		{ID{Site, "my-app"}, "GROUPS", "HTTP_API_CONNECTOR_SITE_MY_APP_GROUPS"},
	}
	for _, tc := range tests {
		if got := tc.id.ConfigKey(tc.setting); got != tc.want {
			t.Errorf("%v.ConfigKey(%q) = %q, want %q", tc.id, tc.setting, got, tc.want)
		}
	}
}

// Two names differing only by hyphen-versus-underscore are one
// parameter name and two connectors. Refusing both is the fail-closed
// answer: enabling either would be enabling it under a configuration
// that might have been written for the other, and these configurations
// carry client registrations.
func TestMacroCollision(t *testing.T) {
	ids := []ID{
		{Site, "my-app"},
		{Site, "my_app"},
		{Builtin, "gdrive"},
		{Site, "cryoem"},
	}
	got := MacroCollision(ids)

	if len(got) != 1 {
		t.Fatalf("MacroCollision found %d collisions, want 1: %v", len(got), got)
	}
	group, ok := got["SITE_MY_APP"]
	if !ok {
		t.Fatalf("no collision reported for SITE_MY_APP; got %v", got)
	}
	if len(group) != 2 || group[0].Name != "my-app" || group[1].Name != "my_app" {
		t.Errorf("collision group = %v, want both my-app and my_app, sorted", group)
	}
}

func TestMacroCollisionIsEmptyWhenNamesAreDistinct(t *testing.T) {
	ids := []ID{{Builtin, "gdrive"}, {Site, "cryoem"}, {Site, "other"}}
	if got := MacroCollision(ids); len(got) != 0 {
		t.Errorf("MacroCollision = %v, want none", got)
	}
}

// The namespace is part of the credd service name, so two connectors
// that differ only by namespace cannot land on one credential file.
//
// builtin:gdrive and site:gdrive are different client registrations --
// different applications. Sharing a file would mean one application's
// token answering for the other.
func TestServiceNameIsInjectiveAcrossNamespaces(t *testing.T) {
	a := ID{Builtin, "gdrive"}.Service("webapi")
	b := ID{Site, "gdrive"}.Service("webapi")

	if a == b {
		t.Fatalf("builtin:gdrive and site:gdrive both store as %q", a)
	}
	if a != "webapi_builtin_gdrive" {
		t.Errorf("builtin:gdrive stores as %q, want webapi_builtin_gdrive", a)
	}
}

// The prefix is what keeps this server's credentials out of the
// administrator's. A connector must never store as a bare provider
// name, because that is the administrator's file.
func TestServiceNameIsNeverTheBareProviderName(t *testing.T) {
	for _, prefix := range []string{"", "webapi", "api2"} {
		got := ID{Builtin, "gdrive"}.Service(prefix)
		if got == "gdrive" {
			t.Fatalf("prefix %q produced the bare provider name %q, which is "+
				"the administrator's credd file", prefix, got)
		}
		if !strings.HasSuffix(got, "_builtin_gdrive") {
			t.Errorf("Service(%q) = %q, want it to end in _builtin_gdrive", prefix, got)
		}
	}
}

func TestServiceNameDefaultsThePrefix(t *testing.T) {
	if got := (ID{Builtin, "gdrive"}).Service(""); got != DefaultServicePrefix+"_builtin_gdrive" {
		t.Errorf("Service(\"\") = %q, want the default prefix applied", got)
	}
}

// Whatever a name is allowed to contain, the resulting service name has
// to be storable by the credd: okay_for_oauth_filename (store_cred.cpp)
// permits letters, digits, - + = _ and dot, and nothing else.
func TestServiceNameIsStorableByTheCredd(t *testing.T) {
	ok := func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '+' || r == '=' || r == '_' || r == '.'
	}
	for _, name := range []string{"gdrive", "my-app", "my_app", "a1"} {
		id := ID{Site, name}
		for _, r := range id.Service("webapi") {
			if !ok(r) {
				t.Errorf("Service for %v contains %q, which the credd refuses", id, r)
			}
		}
	}
}
