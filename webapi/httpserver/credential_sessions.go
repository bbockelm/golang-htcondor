package httpserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Credential session caches.
//
// The paths that hand cedar a credential minted or forwarded for a caller
// (MCP, the SSH gateway, API keys, superuser mode, user-header mode, the
// schedd-ACL authz probe) used to pass a nil cache, which is cedar's
// process-global one. That cache also holds this daemon's own sessions
// under the untagged {address, command} slot, and cedar releases that
// predate storing client sessions by tag put every client session in that
// slot whatever the config's tag -- so a caller's session could be resumed
// by the daemon's untagged connections, and the reverse.
//
// Each of those paths now takes its session cache from
// Handler.credentialSessions, a TokenCache used only through
// sessionCacheFor and keyed by the session tag: bounded, one private cache
// per tag, never the global one. Whichever cedar is linked, nothing a
// caller negotiates lands in the global cache, and a cache is only ever
// shared by configs with the same tag. Session-cookie mode does the same
// keyed by user (cookieSessionCaches).

// mintedCredentialSessionTag derives the cedar session tag for a token this
// server minted, from what the schedd will authorize it for: its issuer,
// subject and authorization limits (the scope claim; absent means
// unlimited). kind separates paths whose sessions must not be resumed by
// each other even for the same grant.
//
// Tokens minted per request differ in jti and iat, so a digest of the whole
// token would never match twice. A bare username is not enough either: once
// cedar resumes sessions by tag, a READ-only grant would resume a session a
// READ+WRITE grant of the same user negotiated, and the schedd bounds a
// session's authority by the token that negotiated it, not the one that
// resumes it.
//
// The claims are read without verifying the signature, which is sound only
// because the caller minted the token itself. A token that cannot be read
// is tagged by its own digest, which shares nothing.
func mintedCredentialSessionTag(kind, token string) string {
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
		Scope   string `json:"scope"`
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return kind + ":" + mcpActorKey(token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.Subject == "" {
		return kind + ":" + mcpActorKey(token)
	}
	scopes := strings.Fields(claims.Scope)
	sort.Strings(scopes)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		kind, claims.Issuer, claims.Subject, strings.Join(scopes, " "),
	}, "\x00")))
	return kind + ":" + hex.EncodeToString(sum[:])
}
