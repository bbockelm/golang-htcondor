package httpserver

import (
	"context"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// versionHandler is a server using the placementd at address, discovered
// through coll.
func versionHandler(t *testing.T, coll *fakeCollector, address string) *Handler {
	t.Helper()
	cfg, _ := discoveryConfig(t, thisAPHost)
	h := &Handler{
		logger:            discoveryLogger(t),
		placementd:        htcondor.NewPlacementd(address),
		placementdLocator: newTestLocator(t, cfg, coll, thisAPHost),
	}
	h.placementdAvailable.Store(true)
	return h
}

func placementdAdWithVersion(name, machine, addr string, version int) map[string]any {
	ad := placementdAd(name, machine, addr)
	ad[htcondor.PlacementdAPIVersionAttr] = version
	return ad
}

// The version shown is this access point's placementd's, though another
// access point's newer one is listed first.
func TestPlacementAPIVersionIsThisAccessPoints(t *testing.T) {
	coll := sharedCollector(t,
		placementdAdWithVersion(otherAPHost, otherAPHost, otherPlacementd, 2),
		placementdAd(thisAPHost, thisAPHost, localPlacementd),
	)
	if got := versionHandler(t, coll, localPlacementd).placementAPIVersion(context.Background()); got != 1 {
		t.Errorf("version = %d, want this access point's 1, not the other's 2", got)
	}
}

// With only another access point's ad, the version is unknown: 1, which
// keeps the directory pages hidden.
func TestPlacementAPIVersionIgnoresAnotherAccessPoints(t *testing.T) {
	coll := sharedCollector(t, placementdAdWithVersion(otherAPHost, otherAPHost, otherPlacementd, 2))
	if got := versionHandler(t, coll, addressFileSinful).placementAPIVersion(context.Background()); got != 1 {
		t.Errorf("version = %d, want 1", got)
	}
}

// An address that has moved on from the ad's (a restart the collector has
// not caught up with) still finds this access point's ad by its host.
func TestPlacementAPIVersionMatchesByHostWhenAddressDiffers(t *testing.T) {
	coll := sharedCollector(t,
		placementdAd(otherAPHost, otherAPHost, otherPlacementd),
		placementdAdWithVersion(thisAPHost, thisAPHost, localPlacementd, 2),
	)
	if got := versionHandler(t, coll, addressFileSinful).placementAPIVersion(context.Background()); got != 2 {
		t.Errorf("version = %d, want this access point's 2", got)
	}
}
