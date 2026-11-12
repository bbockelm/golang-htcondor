package siteapps

import (
	"strings"
	"testing"
)

// The rule the whole package is shaped around: an app author cannot
// publish their own app to anybody. If this ever passes by accident,
// a lab that forgets its policy file ships its science to the pool.
func TestBundleManifestRefusesGroups(t *testing.T) {
	_, err := ParseBundleManifest([]byte("name: X\ngroups: [\"*\"]\n"))
	if err == nil {
		t.Fatal("a bundle manifest naming groups was accepted")
	}
	// The error has to explain where groups DO go, or the author just
	// deletes the key and still does not know how to scope their app.
	if !strings.Contains(err.Error(), "configuration") {
		t.Errorf("error does not say where groups belong: %v", err)
	}
}

func TestBundleManifestRequiresName(t *testing.T) {
	if _, err := ParseBundleManifest([]byte("description: no name here\n")); err == nil {
		t.Fatal("a manifest with no name was accepted")
	}
}

// An empty groups list is a mistake, not a request to publish to
// nobody, and has to be refused loudly at load.
func TestMergeRefusesEmptyGroups(t *testing.T) {
	// A policy naming no groups is a mistake far more often than it is
	// a deliberate request to publish an app to nobody, so it fails at
	// load rather than publishing something invisible.
	for _, groups := range [][]string{nil, {}, {"", "  "}} {
		if _, err := Merge("app", BundleManifest{Name: "X"}, Policy{Groups: groups}); err == nil {
			t.Errorf("groups %q published the app with no groups", groups)
		}
	}
}

func TestMergePolicyOverridesBundle(t *testing.T) {
	home := true
	policy := Policy{Groups: []string{"lab"}, Name: "Site Name", Home: &home, Origin: "HTTP_API_SITE_APP_CRYOEM_GROUPS"}
	bundle := BundleManifest{
		Name: "Bundle Name", Description: "from the bundle", Icon: "beaker",
		Version: "2.1.0", Revision: "abc1234",
	}

	app, err := Merge("cryoem", bundle, policy)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if app.Name != "Site Name" {
		t.Errorf("Name = %q, want the site's override", app.Name)
	}
	// Merging is key by key: an operator who set only the name must
	// still inherit the description rather than blanking it.
	if app.Description != "from the bundle" {
		t.Errorf("Description = %q, want the bundle's", app.Description)
	}
	if app.Icon != "beaker" {
		t.Errorf("Icon = %q, want the bundle's", app.Icon)
	}
	if !app.Home {
		t.Error("Home = false, want true")
	}
	if app.ID != "cryoem" {
		t.Errorf("ID = %q, want cryoem", app.ID)
	}
	// The build labels are the bundle's alone -- a site does not get to
	// restate which build it is running.
	if app.Version != "2.1.0" || app.Revision != "abc1234" {
		t.Errorf("Version/Revision = %q/%q, want the bundle's", app.Version, app.Revision)
	}
	if app.Origin != policy.Origin {
		t.Errorf("Origin = %q, want %q", app.Origin, policy.Origin)
	}
}

func TestIsEnabledDefaultsTrue(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		p    Policy
		want bool
	}{
		{"unset", Policy{}, true},
		{"true", Policy{Enabled: &yes}, true},
		{"false", Policy{Enabled: &no}, false},
	}
	for _, c := range cases {
		if got := c.p.IsEnabled(); got != c.want {
			t.Errorf("IsEnabled(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestVisibleTo(t *testing.T) {
	cases := []struct {
		name    string
		appGrps []string
		caller  []string
		want    bool
	}{
		{"member", []string{"smith_lab"}, []string{"smith_lab"}, true},
		{"non-member", []string{"smith_lab"}, []string{"jones_lab"}, false},
		{"no groups at all", []string{"smith_lab"}, nil, false},
		{"wildcard admits anyone authenticated", []string{"*"}, []string{"nobody"}, true},
		{"wildcard admits a caller with no groups", []string{"*"}, nil, true},
		{"one of several", []string{"a", "b"}, []string{"b"}, true},
		// The group sources disagree about case often enough that an
		// exact match would silently publish nothing.
		{"case-insensitive", []string{"Smith_Lab"}, []string{"smith_lab"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := App{Groups: tc.appGrps}
			if got := app.VisibleTo(tc.caller); got != tc.want {
				t.Errorf("VisibleTo(%v) with groups %v = %v, want %v",
					tc.caller, tc.appGrps, got, tc.want)
			}
		})
	}
}

func TestValidateID(t *testing.T) {
	for _, bad := range []string{
		"", "_shell", "_", "UPPER", "has space", "has/slash", "has.dot",
		"dot..dot", strings.Repeat("a", maxIDLen+1),
	} {
		if err := ValidateID(bad); err == nil {
			t.Errorf("ValidateID(%q) accepted an invalid id", bad)
		}
	}
	for _, ok := range []string{"cryoem", "cryo-em", "cryo_em", "app2", "a"} {
		if err := ValidateID(ok); err != nil {
			t.Errorf("ValidateID(%q) rejected a valid id: %v", ok, err)
		}
	}
}
