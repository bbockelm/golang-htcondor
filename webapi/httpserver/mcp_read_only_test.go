package httpserver

import (
	"slices"
	"testing"
)

// An installation that will refuse every write must not hand out the
// authorization to attempt one. The token would work once, at the
// consent page, and never again -- and the user would have been told
// they were given something they were not.
func TestReadOnlyMCPDoesNotGrantWriteScope(t *testing.T) {
	h := &Handler{}
	h.mcpReadOnly.Store(true)

	granted := h.getScopesForGroups(nil, []string{"mcp:read", "mcp:write"})
	if slices.Contains(granted, "mcp:write") {
		t.Errorf("mcp:write was granted on a read-only server; granted = %v", granted)
	}
	// The read half still has to work, or the setting is just "MCP off"
	// under another name.
	if !slices.Contains(granted, "mcp:read") {
		t.Errorf("mcp:read was refused on a read-only server; granted = %v", granted)
	}
}

// No group policy is configured in the test above, which is the case
// that previously granted write to any authenticated caller. Check the
// other direction too: with MCP read-only off, the old behaviour is
// untouched.
func TestWriteScopeStillGrantedWhenNotReadOnly(t *testing.T) {
	h := &Handler{}
	granted := h.getScopesForGroups(nil, []string{"mcp:read", "mcp:write"})
	if !slices.Contains(granted, "mcp:write") {
		t.Errorf("mcp:write was refused on an ordinary server; granted = %v", granted)
	}
}

// A client asks for each scope the server advertises, so the
// advertisement is what stops a consent page offering a write
// authorization this server would refuse to use.
func TestReadOnlyMCPAdvertisementDropsWrite(t *testing.T) {
	h := &Handler{mcpEnabled: true}
	h.mcpReadOnly.Store(true)
	got := h.advertisedScopes()

	if slices.Contains(got, "mcp:write") {
		t.Errorf("mcp:write is advertised by a read-only server; advertised = %v", got)
	}
	if !slices.Contains(got, "mcp:read") {
		t.Errorf("mcp:read is not advertised by a read-only server; advertised = %v", got)
	}
	// Only mcp:write goes. Narrowing anything else here would stop a
	// CIMD client requesting it, which breaks every grant that carries
	// it -- the failure the advertisement/requestable split exists to
	// prevent.
	for _, s := range oauth2AdvertisedScopes {
		if s == "mcp:write" {
			continue
		}
		if !slices.Contains(got, s) {
			t.Errorf("%s stopped being advertised by a read-only server", s)
		}
	}

	// And what a client may REQUEST is unchanged, so a grant made
	// before the setting was turned on still refreshes.
	if !slices.Contains(cimdClientScopes("mcp:read mcp:write"), "mcp:write") {
		t.Error("read-only narrowed what a CIMD client may request, which strands existing grants")
	}
}

// With MCP on and not read-only, the advertisement is byte-for-byte what
// it was.
func TestOrdinaryMCPAdvertisementIsUnchanged(t *testing.T) {
	h := &Handler{mcpEnabled: true}
	if got := h.advertisedScopes(); !slices.Equal(got, oauth2AdvertisedScopes) {
		t.Errorf("advertised = %v, want %v", got, oauth2AdvertisedScopes)
	}
}
