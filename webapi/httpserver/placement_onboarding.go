package httpserver

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Placement onboarding is the user-facing half of condor_placementd, ported
// from CHTC's placement-webapp: a person signs in, picks a project and the
// authorizations they want, and receives an IDTOKEN for their AP account --
// in the browser, or through the RFC 8628 device flow placement-client uses.
//
// The security invariant, which nothing here may relax: the placementd is
// called with this server's daemon credential (it registers its commands at
// ADMINISTRATOR), so the identity sent is ALWAYS the session's
// PlacementIdentity, never anything from the request; Requester always
// equals UserName; and the INSTRUCTOR third-party flow stays off. That is
// what stops a signed-in user from minting a token for somebody else.

// placementOnboarding is the Handler's onboarding state.
type placementOnboarding struct {
	// identityClaims and displayNameClaims are the ordered userinfo
	// claims the identity and greeting come from
	// (HTTP_API_PLACEMENT_IDENTITY_CLAIMS, ..._DISPLAY_NAME_CLAIMS).
	identityClaims    []string
	displayNameClaims []string
	// deviceClients are the client_ids the device shim accepts
	// (HTTP_API_PLACEMENT_DEVICE_CLIENTS).
	deviceClients map[string]bool
	// scheddHost and collectorHost fill the ~/.condor/user_config snippet
	// shown with a token.
	scheddHost    string
	collectorHost string

	devices       *placementDeviceStore
	deviceLimiter *LoginRateLimiter

	// requests are the access requests of people the placementd does not
	// map, and the limits on filing them (placement_access_requests.go).
	requests               *placementAccessRequestStore
	requestIdentityLimiter *LoginRateLimiter
	requestAddressLimiter  *LoginRateLimiter

	// mapIdentity is set when HTTP_API_IDENTITY_MAP names placementd;
	// mapIdentityFirst when it is listed before every local strategy.
	mapIdentity      bool
	mapIdentityFirst bool

	// resolving is set while a background look for a placementd runs;
	// see placementdReady.
	resolving atomic.Bool

	// placementBearers caches which bearer tokens hold the placement scope.
	bearers placementBearerCache

	// records, when set, replaces the schedd for user and project record
	// calls. Tests set it.
	records placementRecordClient
}

// defaultPlacementDeviceClients is pdwebapp's DEVICE_CLIENTS default. The
// empty entry is kept for fidelity; a request with no client_id is refused
// before the list is consulted, exactly as there.
const defaultPlacementDeviceClients = "placement_client,curl,"

// placementDeviceClientNames are the names pdwebapp shows for its default
// clients. Any other client is shown by its id.
var placementDeviceClientNames = map[string]string{
	"":                 "Unregistered Client",
	"curl":             "cURL Client",
	"placement_client": "Placement Client",
}

// parsePlacementDeviceClients splits HTTP_API_PLACEMENT_DEVICE_CLIENTS on
// commas only, keeping an empty entry the way pdwebapp's default does.
func parsePlacementDeviceClients(v string) map[string]bool {
	out := make(map[string]bool)
	for _, f := range strings.Split(v, ",") {
		out[strings.TrimSpace(f)] = true
	}
	return out
}

// configurePlacementOnboarding fills the onboarding state from the handler
// configuration. Called from NewHandler once the database is open.
func (h *Handler) configurePlacementOnboarding(cfg HandlerConfig) {
	po := &h.placementOnboard
	po.identityClaims = cfg.PlacementIdentityClaims
	if len(po.identityClaims) == 0 {
		po.identityClaims = defaultPlacementIdentityClaims
	}
	po.displayNameClaims = cfg.PlacementDisplayNameClaims
	if len(po.displayNameClaims) == 0 {
		po.displayNameClaims = defaultPlacementDisplayNameClaims
	}
	clients := cfg.PlacementDeviceClients
	if clients == nil {
		def := defaultPlacementDeviceClients
		clients = &def
	}
	po.deviceClients = parsePlacementDeviceClients(*clients)

	po.scheddHost = cfg.PlacementScheddHost
	if po.scheddHost == "" {
		po.scheddHost = h.scheddName
	}
	if po.scheddHost == "" {
		po.scheddHost = h.scheddHost
	}
	po.collectorHost = cfg.PlacementCollectorHost
	if po.collectorHost == "" && cfg.HTCondorConfig != nil {
		if v, ok := cfg.HTCondorConfig.Get("COLLECTOR_HOST"); ok {
			po.collectorHost = strings.TrimSpace(v)
		}
	}

	if h.db != nil {
		po.devices = &placementDeviceStore{db: h.db, sealer: h.sealer, now: time.Now}
		po.requests = &placementAccessRequestStore{db: h.db, now: time.Now}
	}
	po.requestIdentityLimiter = NewLoginRateLimiter(accessRequestIdentityRate, accessRequestIdentityBurst)
	po.requestAddressLimiter = NewLoginRateLimiter(accessRequestAddressRate, accessRequestAddressBurst)
	// Polls arrive every five seconds per client; this allows a busy NAT
	// a good many clients while still bounding what one address can do.
	po.deviceLimiter = NewLoginRateLimiter(2, 60)
}

// placementOnboardingEnabled reports whether the user-facing placement
// features are served: a placementd is reachable and this is not a
// multi-AP server, which has no single placementd to front.
func (h *Handler) placementOnboardingEnabled(ctx context.Context) bool {
	return h.multi == nil && h.placementdReady(ctx)
}

// placementUserContext is the context user-facing placement calls run
// under: this server's credential, because the placementd authorizes the
// access point. The identity in every such call is the session's own.
func placementUserContext(r *http.Request) context.Context {
	return htcondor.WithDaemonCredential(r.Context(),
		"placementd: user onboarding, identity fixed to the session's")
}

// placementUserConfig is the ~/.condor/user_config snippet pdwebapp shows
// beside a token, so the token's holder reaches this schedd and pool.
func (h *Handler) placementUserConfig() string {
	po := &h.placementOnboard
	var lines []string
	if po.scheddHost != "" {
		lines = append(lines, "SCHEDD_HOST = "+po.scheddHost)
	}
	if po.collectorHost != "" {
		lines = append(lines, "COLLECTOR_HOST = "+po.collectorHost)
	}
	return strings.Join(lines, "\n")
}

// placementRecordClient is the slice of the schedd client the onboarding
// and admin record views use.
type placementRecordClient interface {
	QueryUserRecords(ctx context.Context, opts *htcondor.UserRecordQueryOptions) ([]htcondor.UserRecord, error)
	QueryProjectRecords(ctx context.Context, opts *htcondor.UserRecordQueryOptions) ([]htcondor.UserRecord, error)
	EnableUserRecord(ctx context.Context, kind htcondor.UserRecordKind, name string) (*htcondor.UserRecordActionResult, error)
	DisableUserRecord(ctx context.Context, kind htcondor.UserRecordKind, name, reason string) (*htcondor.UserRecordActionResult, error)
}

// placementRecords returns the client for schedd user and project records,
// or nil when there is no schedd.
func (h *Handler) placementRecords() placementRecordClient {
	if h.placementOnboard.records != nil {
		return h.placementOnboard.records
	}
	if h.multi != nil {
		return nil
	}
	if s := h.getSchedd(); s != nil {
		return s
	}
	return nil
}

// placementUserRecordLookup is the user-record lookup for placement
// accounts: the records override when a test set one, else the schedd.
func (h *Handler) placementUserRecordLookup() UserRecordLookup {
	if rc := h.placementOnboard.records; rc != nil {
		return recordClientLookup{rc}
	}
	return h.userRecordLookup()
}

// recordClientLookup adapts a placementRecordClient to UserRecordLookup.
type recordClientLookup struct{ rc placementRecordClient }

func (l recordClientLookup) GetUserRecord(ctx context.Context, user string) (*htcondor.UserRecord, error) {
	recs, err := l.rc.QueryUserRecords(ctx, &htcondor.UserRecordQueryOptions{
		Constraint: "User == " + classadString(user), Limit: 1,
	})
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	return &recs[0], nil
}
