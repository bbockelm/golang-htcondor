package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestCreateUserRecordQueryAd(t *testing.T) {
	t.Run("defaults to Owner ads", func(t *testing.T) {
		ad := createUserRecordQueryAd(nil)
		if got, ok := ad.EvaluateAttrString("TargetType"); !ok || got != "Owner" {
			t.Errorf("TargetType = %q (ok=%v), want \"Owner\"", got, ok)
		}
	})

	t.Run("carries constraint, projection and limit", func(t *testing.T) {
		ad := createUserRecordQueryAd(&UserRecordQueryOptions{
			Constraint: `User == "alice@example.org"`,
			Projection: []string{"User", "Enabled"},
			Limit:      1,
		})
		if got, ok := ad.EvaluateAttrString("Projection"); !ok || got != "User,Enabled" {
			t.Errorf("Projection = %q (ok=%v), want \"User,Enabled\"", got, ok)
		}
		if got, ok := ad.EvaluateAttrInt("LimitResults"); !ok || got != 1 {
			t.Errorf("LimitResults = %d (ok=%v), want 1", got, ok)
		}
		if _, ok := ad.Lookup("Requirements"); !ok {
			t.Errorf("Requirements not set on the query ad")
		}
	})

	t.Run("an unparseable constraint fails closed", func(t *testing.T) {
		// A dropped constraint would widen a single-user lookup into
		// "every user on this schedd", and callers make access decisions
		// from the result — so a parse failure must match nothing rather
		// than everything.
		ad := createUserRecordQueryAd(&UserRecordQueryOptions{Constraint: `User == ((("`})
		expr, ok := ad.Lookup("Requirements")
		if !ok {
			t.Fatalf("Requirements missing entirely; the query would match every user")
		}
		if got := strings.ToLower(expr.String()); got != "false" {
			t.Errorf("Requirements = %q, want false", got)
		}
	})
}

func TestUserRecordFromAd(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	for _, tc := range []struct {
		name     string
		build    func(*classad.ClassAd)
		wantUser string
		wantEn   *bool
		wantDis  bool
		wantWhy  string
	}{
		{
			name: "enabled written as an int",
			build: func(a *classad.ClassAd) {
				_ = a.Set("User", "alice@example.org")
				_ = a.Set("Enabled", 1)
			},
			wantUser: "alice@example.org",
			wantEn:   boolPtr(true),
		},
		{
			name: "disabled with a reason",
			build: func(a *classad.ClassAd) {
				_ = a.Set("User", "bob@example.org")
				_ = a.Set("Enabled", 0)
				_ = a.Set("DisableReason", "left the lab")
			},
			wantUser: "bob@example.org",
			wantEn:   boolPtr(false),
			wantDis:  true,
			wantWhy:  "left the lab",
		},
		{
			name: "enabled written as a bool",
			build: func(a *classad.ClassAd) {
				_ = a.Set("User", "carol@example.org")
				_ = a.Set("Enabled", false)
			},
			wantUser: "carol@example.org",
			wantEn:   boolPtr(false),
			wantDis:  true,
		},
		{
			// An auto-created record that no admin has ever acted on may
			// not carry Enabled at all. That must read as "no statement",
			// not as a denial — the schedd's own default is enabled.
			name: "absent Enabled is not a denial",
			build: func(a *classad.ClassAd) {
				_ = a.Set("User", "dave@example.org")
			},
			wantUser: "dave@example.org",
			wantEn:   nil,
			wantDis:  false,
		},
		{
			name: "falls back to Name when User is absent",
			build: func(a *classad.ClassAd) {
				_ = a.Set("Name", "erin@example.org")
			},
			wantUser: "erin@example.org",
			wantEn:   nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := classad.New()
			tc.build(ad)
			rec := userRecordFromAd(ad)

			if rec.User != tc.wantUser {
				t.Errorf("User = %q, want %q", rec.User, tc.wantUser)
			}
			switch {
			case tc.wantEn == nil && rec.Enabled != nil:
				t.Errorf("Enabled = %v, want nil (no statement)", *rec.Enabled)
			case tc.wantEn != nil && rec.Enabled == nil:
				t.Errorf("Enabled = nil, want %v", *tc.wantEn)
			case tc.wantEn != nil && *rec.Enabled != *tc.wantEn:
				t.Errorf("Enabled = %v, want %v", *rec.Enabled, *tc.wantEn)
			}
			if got := rec.IsDisabled(); got != tc.wantDis {
				t.Errorf("IsDisabled() = %v, want %v", got, tc.wantDis)
			}
			if rec.DisableReason != tc.wantWhy {
				t.Errorf("DisableReason = %q, want %q", rec.DisableReason, tc.wantWhy)
			}
		})
	}

	t.Run("nil record is not disabled", func(t *testing.T) {
		var rec *UserRecord
		if rec.IsDisabled() {
			t.Errorf("a nil record must not read as disabled")
		}
	})
}

func TestClassadQuoteString(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`alice@example.org`, `"alice@example.org"`},
		{`say "hi"`, `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
	} {
		if got := classadQuoteString(tc.in); got != tc.want {
			t.Errorf("classadQuoteString(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
