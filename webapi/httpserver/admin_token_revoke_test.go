package httpserver

import (
	"context"
	"errors"
	"testing"
)

// signatureFor returns the stored signature of a subject's token, which is
// what the admin listing shows a prefix of.
func signatureFor(t *testing.T, f *reauthFixture, table, subject string) string {
	t.Helper()
	db := f.server.oauth2Provider.GetStorage().GetDB()
	var sig string
	err := db.QueryRowContext(context.Background(),
		"SELECT signature FROM "+table+" WHERE subject = ? AND active = 1 LIMIT 1", subject).Scan(&sig)
	if err != nil {
		t.Fatalf("reading a %s signature for %s: %v", table, subject, err)
	}
	return sig
}

// The point of per-token revocation. An operator looking at the token list
// picks one row and expects that client to stop working -- so revoking the
// ACCESS token has to take the refresh token with it. Otherwise the client
// mints a replacement within minutes and the button did nothing, which is
// exactly the case for a dynamically-registered client that cannot simply
// be disabled.
func TestRevokingOneTokenCutsOffTheRefresh(t *testing.T) {
	f := newReauthFixture(t, Config{})
	_, refreshToken, _ := f.grant(t, "alice", nil)

	// Sanity: the grant works first, or the test proves nothing.
	if status, body := f.refresh(t, refreshToken); status != 200 {
		t.Fatalf("refresh should work before revocation, got %d: %v", status, body)
	} else {
		refreshToken, _ = body["refresh_token"].(string)
	}

	sig := signatureFor(t, f, "oauth2_access_tokens", "alice")
	storage := f.server.oauth2Provider.GetStorage()

	grant, err := storage.FindGrantBySignaturePrefix(context.Background(), "access", sig[:8])
	if err != nil {
		t.Fatalf("FindGrantBySignaturePrefix: %v", err)
	}
	n, err := storage.RevokeGrant(context.Background(), grant.RequestID)
	if err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if n < 2 {
		t.Errorf("revoked %d rows; the access token's refresh token was left alive", n)
	}

	if status, body := f.refresh(t, refreshToken); status == 200 {
		t.Errorf("the client refreshed after its grant was revoked: %v", body)
	}
}

// The listing shows a truncated signature, so a fingerprint can in
// principle match more than one row. Guessing would revoke somebody
// else's access, so it refuses.
func TestAnAmbiguousFingerprintIsRefused(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.grant(t, "alice", nil)

	db := f.server.oauth2Provider.GetStorage().GetDB()
	sig := signatureFor(t, f, "oauth2_access_tokens", "alice")

	// A second row sharing the same 8-character prefix.
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO oauth2_access_tokens
		   (signature, request_id, requested_at, client_id, scopes, granted_scopes,
		    form_data, session_data, subject, active, expires_at)
		 VALUES (?, 'other-request', CURRENT_TIMESTAMP, 'c', '', '', '', '', 'bob', 1, CURRENT_TIMESTAMP)`,
		sig[:8]+"-collision")
	if err != nil {
		t.Fatalf("inserting a colliding row: %v", err)
	}

	storage := f.server.oauth2Provider.GetStorage()
	if _, err := storage.FindGrantBySignaturePrefix(context.Background(), "access", sig[:8]); !errors.Is(err, ErrTokenAmbiguous) {
		t.Errorf("err = %v, want ErrTokenAmbiguous", err)
	}
}

func TestAnUnknownFingerprintIsReported(t *testing.T) {
	f := newReauthFixture(t, Config{})
	storage := f.server.oauth2Provider.GetStorage()

	_, err := storage.FindGrantBySignaturePrefix(context.Background(), "access", "nosuchtoken")
	if !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("err = %v, want ErrTokenNotFound", err)
	}
}

// A fingerprint short enough to match anything is refused outright rather
// than resolved to whatever happens to sort first.
func TestAShortFingerprintIsRefused(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.grant(t, "alice", nil)
	storage := f.server.oauth2Provider.GetStorage()

	for _, prefix := range []string{"", "a", "abc"} {
		if _, err := storage.FindGrantBySignaturePrefix(context.Background(), "access", prefix); err == nil {
			t.Errorf("fingerprint %q was accepted", prefix)
		}
	}
}

// Revocation is scoped to one grant: another user's session is untouched.
func TestRevokingOneGrantLeavesOthersAlone(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.grant(t, "alice", nil)
	_, bobToken, _ := f.grant(t, "bob", nil)

	sig := signatureFor(t, f, "oauth2_access_tokens", "alice")
	storage := f.server.oauth2Provider.GetStorage()
	grant, err := storage.FindGrantBySignaturePrefix(context.Background(), "access", sig[:8])
	if err != nil {
		t.Fatalf("FindGrantBySignaturePrefix: %v", err)
	}
	if _, err := storage.RevokeGrant(context.Background(), grant.RequestID); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	if status, body := f.refresh(t, bobToken); status != 200 {
		t.Errorf("bob's grant was revoked too: %d %v", status, body)
	}
}

// The two token kinds live in different tables; asking for a nonsense kind
// must not be silently resolved to one of them.
func TestAnUnknownTokenKindIsRefused(t *testing.T) {
	f := newReauthFixture(t, Config{})
	storage := f.server.oauth2Provider.GetStorage()

	if _, err := storage.FindGrantBySignaturePrefix(context.Background(), "banana", "abcdefgh"); err == nil {
		t.Error("an unknown token kind was accepted")
	}
}
