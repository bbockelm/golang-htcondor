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
	if !strings.Contains(err.Error(), "policy file") {
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
	for _, policy := range []string{"", "groups: []\n", "groups: [\"\", \"  \"]\n"} {
		site, err := ParseSiteManifest([]byte(policy))
		if err != nil {
			t.Fatalf("parse %q: %v", policy, err)
		}
		if _, err := Merge("app", BundleManifest{Name: "X"}, site); err == nil {
			t.Errorf("policy %q published the app with no groups", policy)
		}
	}
}

func TestMergeSiteOverridesBundle(t *testing.T) {
	site, err := ParseSiteManifest([]byte("groups: [lab]\nname: Site Name\nhome: true\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	bundle := BundleManifest{Name: "Bundle Name", Description: "from the bundle", Icon: "beaker"}

	app, err := Merge("cryoem", bundle, site)
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
}

func TestIsEnabledDefaultsTrue(t *testing.T) {
	cases := map[string]bool{
		"groups: [lab]\n":                 true,
		"groups: [lab]\nenabled: true\n":  true,
		"groups: [lab]\nenabled: false\n": false,
	}
	for policy, want := range cases {
		site, err := ParseSiteManifest([]byte(policy))
		if err != nil {
			t.Fatalf("parse %q: %v", policy, err)
		}
		if got := site.IsEnabled(); got != want {
			t.Errorf("IsEnabled(%q) = %v, want %v", policy, got, want)
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
