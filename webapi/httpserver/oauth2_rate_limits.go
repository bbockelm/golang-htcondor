package httpserver

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

// Per-source limits on the OAuth2 endpoints that create state for a
// caller who has not authenticated: dynamic client registration writes
// a client row (and spends a bcrypt hash on its secret), and device
// authorization writes a device-code row. Both are keyed on the client
// address as actorResolveSource reports it.
//
// Registration is something an application does once per install, so
// its budget is small. Device authorization is looser because the SSH
// gateway starts a device flow for every login it handles and does so
// from this server's own address, so all of its users share one budget.
const (
	registrationsPerHour          = 30
	registrationBurst             = 30
	deviceAuthorizationsPerMinute = 30
	deviceAuthorizationBurst      = 60
)

// oauth2LimitState is embedded in Handler and built on first use, for
// the reasons given on sshConsentState.
type oauth2LimitState struct {
	oauth2LimitOnce        sync.Once
	registrationLimiter    *LoginRateLimiter
	deviceAuthorizeLimiter *LoginRateLimiter
}

func (h *Handler) oauth2Limiters() (register, deviceAuthorize *LoginRateLimiter) {
	h.oauth2LimitOnce.Do(func() {
		h.registrationLimiter = NewLoginRateLimiter(rate.Limit(registrationsPerHour/3600.0), registrationBurst)
		h.deviceAuthorizeLimiter = NewLoginRateLimiter(rate.Limit(deviceAuthorizationsPerMinute/60.0), deviceAuthorizationBurst)
	})
	return h.registrationLimiter, h.deviceAuthorizeLimiter
}

// allowRegistration spends one dynamic registration from the caller's
// budget.
func (h *Handler) allowRegistration(r *http.Request) bool {
	register, _ := h.oauth2Limiters()
	return register.Allow(actorResolveSource(r, h.trustedProxies))
}

// allowDeviceAuthorization spends one device authorization from the
// caller's budget.
func (h *Handler) allowDeviceAuthorization(r *http.Request) bool {
	_, deviceAuthorize := h.oauth2Limiters()
	return deviceAuthorize.Allow(actorResolveSource(r, h.trustedProxies))
}

// withCIMDSource notes on the request context who a client metadata
// fetch made while serving it should be charged to. See
// cimdResolver.resolve.
func (h *Handler) withCIMDSource(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r.WithContext(WithCIMDSource(r.Context(), actorResolveSource(r, h.trustedProxies))))
	}
}
