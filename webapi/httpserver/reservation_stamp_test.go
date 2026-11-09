package httpserver

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func identityAd(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(text)
	if err != nil {
		t.Fatalf("parsing %q: %v", text, err)
	}
	return ad
}

// A stamp is an edit to somebody's job, made as them, so the identity
// read off the ad is the whole basis for the write being allowed.
func TestJobIdentityNamesTheOwnerToActAs(t *testing.T) {
	cases := []struct {
		name      string
		uidDomain string
		ad        string
		want      string
	}{
		{
			name: "User is already qualified",
			ad:   `[ User = "alice@example.org"; Owner = "alice" ]`,
			want: "alice@example.org",
		},
		{
			name:      "User wins over Owner even on a different domain",
			uidDomain: "other.org",
			ad:        `[ User = "alice@example.org"; Owner = "alice" ]`,
			want:      "alice@example.org",
		},
		{
			name:      "a bare Owner is qualified with the UID domain",
			uidDomain: "example.org",
			ad:        `[ Owner = "bob" ]`,
			want:      "bob@example.org",
		},
		{
			name:      "an unqualified User falls back to Owner",
			uidDomain: "example.org",
			ad:        `[ User = "bob"; Owner = "bob" ]`,
			want:      "bob@example.org",
		},
		{
			name:      "no owner at all",
			uidDomain: "example.org",
			ad:        `[ ClusterId = 7 ]`,
			want:      "",
		},
		{
			name: "a bare Owner with no UID domain names nobody",
			ad:   `[ Owner = "bob" ]`,
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &Handler{uidDomain: c.uidDomain}
			if got := h.jobIdentity(identityAd(t, c.ad)); got != c.want {
				t.Fatalf("jobIdentity = %q, want %q", got, c.want)
			}
		})
	}
}

func TestMissingStampCredentialNamesWhatToSet(t *testing.T) {
	cases := []struct{ key, domain, want string }{
		{"", "", "token signing key and no TRUST_DOMAIN"},
		{"", "pool.example.org", "token signing key"},
		{"/etc/condor/passwords.d/POOL", "", "TRUST_DOMAIN"},
	}
	for _, c := range cases {
		if got := missingStampCredential(c.key, c.domain); got != c.want {
			t.Fatalf("missingStampCredential(%q, %q) = %q, want %q", c.key, c.domain, got, c.want)
		}
	}
}
