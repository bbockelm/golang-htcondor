//go:build linux

package droppriv

import (
	"context"
	"testing"
)

func TestSSSDIfpLookup(t *testing.T) {
	// Try to create SSSD InfoPipe strategy
	strategy, err := NewSSSDIfpLookup(context.Background())
	if err != nil {
		t.Skipf("SSSD InfoPipe not available: %v", err)
	}
	defer func() {
		if err := strategy.Close(); err != nil {
			t.Logf("Failed to close strategy: %v", err)
		}
	}()

	t.Logf("SSSD InfoPipe strategy created successfully")
	t.Logf("Strategy name: %s", strategy.Name())

	// Try to look up root user
	info, err := strategy.LookupUser(context.Background(), "root")
	if err != nil {
		// It's okay if the lookup fails - SSSD might not have root in its database
		t.Logf("Root lookup via SSSD failed (expected if SSSD not configured): %v", err)
		return
	}

	if info.UID != 0 {
		t.Errorf("Expected UID 0 for root, got %d", info.UID)
	}

	t.Logf("Root lookup via SSSD: UID=%d GID=%d HomeDir=%s Shell=%s",
		info.UID, info.GID, info.HomeDir, info.Shell)
}
