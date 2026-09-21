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
	"golang.org/x/oauth2"
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

// handlerWithUpstream builds the smallest Handler that can file a
// credential: a store, a mode, and an upstream to attribute it to.
func handlerWithUpstream(t *testing.T, mode UpstreamRefreshMode) *Handler {
	t.Helper()
	store := upstreamStore(t, false)
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	return &Handler{
		logger:              logger,
		upstreamRefreshMode: mode,
		upstreamRefresh:     store,
		oauth2Config: &oauth2.Config{
			//nolint:gosec // G101: a provider's public token endpoint, not a credential
			Endpoint: oauth2.Endpoint{TokenURL: "https://cilogon.org/oauth2/token"},
		},
	}
}

// Auto keeps what the provider hands over. The mode is about what to do
// with the answer, not about asking a different question.
func TestUpstreamAutoKeepsWhatTheProviderGave(t *testing.T) {
	h := handlerWithUpstream(t, UpstreamRefreshAuto)
	h.rememberUpstreamRefresh(context.Background(), "alice", "sub-1", "rt-abc",
		[]string{"openid", "offline_access"})

	got, err := h.upstreamRefresh.Load(context.Background(), "alice", h.upstreamIssuer())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.RefreshToken != "rt-abc" {
		t.Errorf("stored %q, want rt-abc", got.RefreshToken)
	}
	if !got.HasOfflineAccess() {
		t.Error("the granted scopes were not recorded, so auto cannot tell a provider that " +
			"withheld offline_access from one that was never asked")
	}
}

// Off stores nothing. A deployment that would rather not hold a long-lived
// key to somebody else's provider gets to not hold one.
func TestUpstreamOffStoresNothing(t *testing.T) {
	h := handlerWithUpstream(t, UpstreamRefreshAuto)
	h.upstreamRefreshMode = UpstreamRefreshOff

	h.rememberUpstreamRefresh(context.Background(), "alice", "sub-1", "rt-abc", []string{"offline_access"})
	if _, err := h.upstreamRefresh.Load(context.Background(), "alice", h.upstreamIssuer()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("a credential was stored with the feature off: %v", err)
	}
}

// A later login that returns nothing retires the credential rather than
// leaving the old one to be used against a provider that has moved on.
func TestUpstreamLoginWithoutTokenRetiresTheOldOne(t *testing.T) {
	h := handlerWithUpstream(t, UpstreamRefreshAuto)
	ctx := context.Background()
	h.rememberUpstreamRefresh(ctx, "alice", "sub-1", "rt-abc", []string{"offline_access"})
	h.rememberUpstreamRefresh(ctx, "alice", "sub-1", "", []string{"openid"})

	if _, err := h.upstreamRefresh.Load(ctx, "alice", h.upstreamIssuer()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("the old credential survived a login that returned none: %v", err)
	}
}

// The scopes recorded are the ones the PROVIDER returned, not the ones
// asked for: a provider may quietly drop a scope it will not grant, and
// believing the request would have auto acting on a privilege it does not
// hold.
func TestScopesFromTokenPrefersWhatWasGranted(t *testing.T) {
	requested := []string{"openid", "offline_access"}

	granted := scopesFromToken(
		(&oauth2.Token{}).WithExtra(map[string]any{"scope": "openid profile"}), requested)
	for _, s := range granted {
		if s == "offline_access" {
			t.Errorf("reported offline_access as granted when the provider returned %v", granted)
		}
	}

	// A provider that says nothing has not refused: the request is then
	// the best answer available, and treating silence as refusal would
	// disable the feature against every such provider.
	silent := scopesFromToken(&oauth2.Token{}, requested)
	if len(silent) != len(requested) {
		t.Errorf("a silent provider yielded %v, want the requested %v", silent, requested)
	}
}
