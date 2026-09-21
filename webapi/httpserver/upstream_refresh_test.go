package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

func upstreamStore(t *testing.T, sealed bool) *upstreamRefreshStore {
	t.Helper()
	db := newTestDB(t, filepath.Join(t.TempDir(), "upstream.db"))
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	s := &upstreamRefreshStore{db: db, logger: logger}
	if sealed {
		kekPath := filepath.Join(t.TempDir(), "kek")
		if err := os.WriteFile(kekPath, mustRand32(t), 0o600); err != nil {
			t.Fatalf("write kek: %v", err)
		}
		sealer, _, err := setupSealer(context.Background(), db, kekPath, logger)
		if err != nil {
			t.Fatalf("setupSealer: %v", err)
		}
		s.sealer = sealer
	}
	return s
}

func sampleGrant() upstreamGrant {
	return upstreamGrant{
		Subject:       "http://cilogon.org/serverA/users/12345",
		Issuer:        "https://cilogon.org",
		RefreshToken:  "upstream-refresh-secret",
		GrantedScopes: []string{"openid", "profile", "offline_access"},
		ObtainedAt:    time.Now().UTC().Truncate(time.Second),
	}
}

// The credential round-trips, sealed and unsealed alike, because a
// deployment without a KEK still needs the feature to work.
func TestUpstreamRefreshRoundTrip(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		name := "plaintext"
		if sealed {
			name = "sealed"
		}
		t.Run(name, func(t *testing.T) {
			store := upstreamStore(t, sealed)
			want := sampleGrant()
			if err := store.Save(context.Background(), want); err != nil {
				t.Fatalf("Save: %v", err)
			}
			got, err := store.Load(context.Background(), want.Subject, want.Issuer)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got.RefreshToken != want.RefreshToken {
				t.Errorf("token = %q, want %q", got.RefreshToken, want.RefreshToken)
			}
			if !got.HasOfflineAccess() {
				t.Errorf("granted scopes did not survive: %v", got.GrantedScopes)
			}
		})
	}
}

// TestUpstreamRefreshIsSealedOnDisk: this is a long-lived key to somebody
// else's identity provider. A KEK that is configured and not applied to it
// is the failure worth naming, and it is invisible from the API -- Load
// returns the right string either way.
func TestUpstreamRefreshIsSealedOnDisk(t *testing.T) {
	store := upstreamStore(t, true)
	g := sampleGrant()
	if err := store.Save(context.Background(), g); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var stored []byte
	var dek []byte
	if err := store.db.QueryRowContext(context.Background(),
		`SELECT refresh_token, refresh_token_dek FROM upstream_refresh_tokens WHERE subject = ?`,
		g.Subject).Scan(&stored, &dek); err != nil {
		t.Fatalf("reading the row: %v", err)
	}
	if string(stored) == g.RefreshToken {
		t.Error("the refresh token is on disk in the clear despite a configured KEK")
	}
	if len(dek) == 0 {
		t.Error("no wrapped data key was stored, so the value cannot be unsealed later")
	}
}

// A sealed row read by a server with no KEK must refuse rather than hand
// back ciphertext, which would otherwise be sent to the provider as if it
// were a token.
func TestUpstreamRefreshRefusesSealedRowWithoutKEK(t *testing.T) {
	store := upstreamStore(t, true)
	g := sampleGrant()
	if err := store.Save(context.Background(), g); err != nil {
		t.Fatalf("Save: %v", err)
	}

	store.sealer = nil
	if _, err := store.Load(context.Background(), g.Subject, g.Issuer); err == nil {
		t.Fatal("a sealed row was read without a KEK")
	}
}

// A provider that stops returning a refresh token is saying this one is
// finished. Keeping the old one would go on asking about a user with a
// credential the provider has moved on from.
func TestUpstreamRefreshSaveWithoutTokenForgets(t *testing.T) {
	store := upstreamStore(t, false)
	g := sampleGrant()
	if err := store.Save(context.Background(), g); err != nil {
		t.Fatalf("Save: %v", err)
	}

	g.RefreshToken = ""
	if err := store.Save(context.Background(), g); err != nil {
		t.Fatalf("Save (empty): %v", err)
	}
	if _, err := store.Load(context.Background(), g.Subject, g.Issuer); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("the old credential survived a login that returned none: %v", err)
	}
}

// Two providers can use the same opaque subject string; answering one with
// the other's credential would ask the wrong provider about the wrong user.
func TestUpstreamRefreshIsKeyedByIssuerToo(t *testing.T) {
	store := upstreamStore(t, false)
	a := sampleGrant()
	b := a
	b.Issuer = "https://other.example.org"
	b.RefreshToken = "a-different-secret"

	for _, g := range []upstreamGrant{a, b} {
		if err := store.Save(context.Background(), g); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	// Both directions: a query that ignored the issuer would return
	// whichever row the database happened to pick, and asking only about
	// the first one passes on that luck.
	for _, want := range []upstreamGrant{a, b} {
		got, err := store.Load(context.Background(), want.Subject, want.Issuer)
		if err != nil {
			t.Fatalf("Load(%s): %v", want.Issuer, err)
		}
		if got.RefreshToken != want.RefreshToken {
			t.Errorf("issuer %q answered with %q, want %q",
				want.Issuer, got.RefreshToken, want.RefreshToken)
		}
	}
}

func TestParseUpstreamRefreshMode(t *testing.T) {
	for raw, want := range map[string]UpstreamRefreshMode{
		"":     UpstreamRefreshAuto,
		"auto": UpstreamRefreshAuto,
		"on":   UpstreamRefreshOn,
		"OFF":  UpstreamRefreshOff,
	} {
		got, err := ParseUpstreamRefreshMode(raw)
		if err != nil {
			t.Errorf("ParseUpstreamRefreshMode(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("ParseUpstreamRefreshMode(%q) = %q, want %q", raw, got, want)
		}
	}
	if _, err := ParseUpstreamRefreshMode("sometimes"); err == nil {
		t.Error("an unrecognised mode was accepted; which one is in force decides whether a " +
			"deployment checks its users at all")
	}
}
