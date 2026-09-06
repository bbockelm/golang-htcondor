// Package apiad builds the collector advertisement for the htcondor-api
// (HTTP_API) daemon. The generic daemon.Advertise loop owns the base ad
// (PublishAd: versions, uptime, memory, Name, MyAddress), MyType, the sequence
// number, DAEMON_SHUTDOWN, the collector list, and INVALIDATE-on-shutdown; apiad
// only supplies the HTTP-API-specific attributes -- exactly the split dbad uses
// for htcondordb.
//
// The ad makes a web-API instance discoverable in the pool (nothing could find
// the REST/MCP endpoint before) and gives condor_status / a collector scraper a
// fleet-wide view of each instance's health: the schedd it fronts, whether its
// htcondordb mirror is reachable and how far behind, and how many live watch
// streams it is carrying.
package apiad

import (
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// AdType is the advertised MyType. Non-standard (HTCondor has no such daemon),
// so daemon.Advertise routes it via UPDATE_AD_GENERIC. condor_status -any and a
// -constraint 'MyType=="HTCondorAPI"' query both surface it.
const AdType = "HTCondorAPI"

// MirrorStatus is the htcondordb-mirror half of the ad, mirroring what the /info
// admin panel shows so the same state is visible pool-wide.
type MirrorStatus struct {
	Enabled          bool
	Healthy          bool  // reachable AND (if a token is used) minted without error
	StalenessSeconds int64 // history-sync lag as of the mirror's last advertised ad
	Status           string
}

// Input is the HTTP-API state captured once per advertisement cycle, so a value
// that changes at runtime (mirror health, stream count, a rediscovered schedd)
// is always current.
type Input struct {
	// Endpoint is the externally reachable base URL (HTTP_API_BASE_URL / the
	// OAuth issuer) -- the user-facing address, not the bind address, which
	// behind a proxy or ingress is not reachable.
	Endpoint         string
	ScheddName       string
	ScheddAddress    string
	TrustDomain      string
	MCPEnabled       bool
	SuperuserEnabled bool
	ActiveStreams    int64
	Mirror           MirrorStatus
}

// AddAttrs writes the HTTP-API attributes onto the daemon-produced base ad.
func AddAttrs(ad *classad.ClassAd, in Input) {
	if in.Endpoint != "" {
		ad.InsertAttrString("HTTPEndpoint", in.Endpoint)
	}
	if in.ScheddName != "" {
		ad.InsertAttrString("ScheddName", in.ScheddName)
	}
	if in.ScheddAddress != "" {
		ad.InsertAttrString("ScheddAddress", ensureAngle(in.ScheddAddress))
	}
	if in.TrustDomain != "" {
		ad.InsertAttrString("TrustDomain", in.TrustDomain)
	}
	ad.InsertAttrBool("MCPEnabled", in.MCPEnabled)
	ad.InsertAttrBool("SuperuserModeEnabled", in.SuperuserEnabled)
	ad.InsertAttr("ActiveWatchStreams", in.ActiveStreams)

	ad.InsertAttrBool("HTCondorDBMirrorEnabled", in.Mirror.Enabled)
	if in.Mirror.Enabled {
		ad.InsertAttrBool("HTCondorDBMirrorHealthy", in.Mirror.Healthy)
		ad.InsertAttr("HTCondorDBMirrorStalenessSeconds", in.Mirror.StalenessSeconds)
		if in.Mirror.Status != "" {
			ad.InsertAttrString("HTCondorDBMirrorStatus", in.Mirror.Status)
		}
	}
}

// Augment returns the daemon.AdvertiseConfig.Augment callback. snapshot is
// called once per cycle to capture the current state.
func Augment(snapshot func() Input) func(*classad.ClassAd) {
	return func(ad *classad.ClassAd) {
		if snapshot == nil {
			return
		}
		AddAttrs(ad, snapshot())
	}
}

// ensureAngle wraps a sinful string in the angle brackets a collector expects,
// idempotently (matches dbad/daemon).
func ensureAngle(addr string) string {
	if addr == "" || strings.HasPrefix(addr, "<") {
		return addr
	}
	return "<" + addr + ">"
}
