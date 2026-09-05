package htcondor

import (
	"context"
	"strings"
	"testing"
)

func TestConfigValRejectsBadNames(t *testing.T) {
	s := NewSchedd("test", "127.0.0.1:9618")
	ctx := context.Background()

	t.Run("empty name", func(t *testing.T) {
		if _, _, err := s.ConfigVal(ctx, "  "); err == nil {
			t.Errorf("expected an error for an empty parameter name")
		}
	})

	t.Run("meta-query is refused", func(t *testing.T) {
		// daemon core answers "?names" with a different reply shape than a
		// parameter lookup. Silently mis-parsing that would surface as a
		// nonsense config value rather than an error, so refuse up front.
		// The check must happen before any connection attempt.
		_, _, err := s.ConfigVal(ctx, "?names")
		if err == nil {
			t.Fatalf("expected an error for a meta-query")
		}
		if !strings.Contains(err.Error(), "meta-quer") {
			t.Errorf("error = %v, want it to name the meta-query problem", err)
		}
	})
}

// TestQueueSuperUserQualification pins the identity forms the schedd actually
// compares against.
//
// QUEUE_SUPER_USERS names OS users ("root, condor") while an authenticated
// identity is "user@domain", and the schedd bridges the two by also treating
// "<name>@$(UID_DOMAIN)" as a superuser. A caller that compared an
// authenticated identity against the raw config string would never match, and
// would silently conclude nobody is a superuser.
func TestQueueSuperUserQualification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       string
		uidDomain string
		want      []string
	}{
		{
			name:      "bare names gain a qualified form",
			raw:       "root, condor",
			uidDomain: "example.org",
			want:      []string{"root", "root@example.org", "condor", "condor@example.org"},
		},
		{
			name:      "already-qualified names are left alone",
			raw:       "condor@other.org",
			uidDomain: "example.org",
			want:      []string{"condor@other.org"},
		},
		{
			name:      "space separated",
			raw:       "root condor",
			uidDomain: "example.org",
			want:      []string{"root", "root@example.org", "condor", "condor@example.org"},
		},
		{
			name:      "no uid domain leaves names bare",
			raw:       "root, condor",
			uidDomain: "",
			want:      []string{"root", "condor"},
		},
		{
			name:      "duplicates collapse",
			raw:       "condor, condor, condor@example.org",
			uidDomain: "example.org",
			want:      []string{"condor", "condor@example.org"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := qualifySuperUsers(tc.raw, tc.uidDomain)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("qualifySuperUsers(%q, %q) = %v, want %v",
					tc.raw, tc.uidDomain, got, tc.want)
			}
		})
	}
}
