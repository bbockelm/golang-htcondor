package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// apiKeySecurityContext gives an API key a schedd credential when, and
// only when, its scopes say it should have one.
//
// API keys started life deliberately unable to reach the schedd: they
// carried an identity and a scope set, but no SecurityConfig, so the
// blast radius of a leaked key was "scrape /metrics" rather than "drain
// the queue" (see the header comment in apikey_auth.go). Handing every
// key a full credential would throw that away.
//
// Instead the key's condor:/* scopes are carried into the IDTOKEN as
// authorization limits, so the restriction is enforced by HTCondor
// rather than by this process remembering to check. A key minted with
// only condor:/READ produces a token the schedd itself will refuse to
// let write, even on a codepath here that forgets to consult scopes.
//
// Returns (nil, nil) — leaving the request exactly as it was — for a
// key with no condor:/* scopes, which is every key that exists today.
func (s *Handler) apiKeySecurityContext(ctx context.Context, row *apiKeyRow) (context.Context, error) {
	if !hasCondorScopes(row.Scopes) {
		return nil, nil
	}
	authz := mapCondorScopesToAuthz(row.Scopes)
	if len(authz) == 0 {
		// hasCondorScopes matched but nothing mapped, i.e. every
		// condor:/* scope on the key is one this build doesn't know.
		// Minting an unrestricted token here would turn an unknown
		// scope into full access, which is the wrong direction to fail.
		return nil, fmt.Errorf("key %s has no recognized condor:/* authorization", row.KeyID)
	}
	if s.signingKeyPath == "" || s.trustDomain == "" {
		return nil, fmt.Errorf("SIGNING_KEY and TRUST_DOMAIN must both be configured to issue schedd credentials for API keys")
	}

	iat := time.Now().Unix()
	exp := time.Now().Add(condorIDTokenLifetime).Unix()
	token, err := generateMCPAccessJWT(
		filepath.Dir(s.signingKeyPath),
		filepath.Base(s.signingKeyPath),
		row.Creator,
		s.trustDomain,
		iat,
		exp,
		authz,
	)
	if err != nil {
		return nil, fmt.Errorf("mint IDTOKEN for %s: %w", row.Creator, err)
	}

	secConfig, err := htcondor.NewClientSecurityConfig(ctx, token, "", 0, "CLIENT", nil)
	if err != nil {
		return nil, fmt.Errorf("build security config: %w", err)
	}
	// cedar caches client sessions keyed {SecurityTag, address,
	// command}. With an empty tag every API-key caller shares one entry
	// for the same schedd and command, so one key's request could
	// resume a session another key authenticated -- and run with that
	// key's authorizations, defeating the per-key limits above. Key the
	// tag on the key id so each key gets its own session.
	secConfig.SecurityTag = apiKeySessionTag(row.KeyID)
	return htcondor.WithSecurityConfig(ctx, secConfig), nil
}

// apiKeySessionTag derives a cedar session-cache tag for an API key.
// The key id (not the secret) is enough: ids are unique per key and
// already appear in logs, so hashing avoids nothing, but a digest keeps
// the tag a fixed-width opaque string like the MCP path's.
func apiKeySessionTag(keyID string) string {
	sum := sha256.Sum256([]byte("apikey:" + keyID))
	return hex.EncodeToString(sum[:])
}
