package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Each AP's own verdict on a caller, enforced when a request is routed
// to it.
//
// A grant is revoked only when every member agrees (multiAPOracle), so a
// user disabled on one AP keeps their token. Without this check they
// would also keep acting on that AP through the API -- hold, remove,
// ssh, sandbox reads -- which in single-AP mode the refresh-time
// revocation closed. So the user-record oracles are also asked per AP,
// at route time, and an AP whose records say the user is disabled
// refuses everything routed to it for them.

// apVerdictTTL bounds how long one AP's verdict on one user is reused.
// Disabling a user is an administrative act; a minute's delay before it
// takes effect here is the same order as the refresh-time oracles'.
const apVerdictTTL = time.Minute

type apVerdict struct {
	err     error
	expires time.Time
}

type apVerdicts struct {
	mu sync.Mutex
	m  map[string]apVerdict
}

func (v *apVerdicts) get(key string, now time.Time) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.m[key]
	if !ok || now.After(e.expires) {
		return false, nil
	}
	return true, e.err
}

func (v *apVerdicts) put(key string, err error, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.m == nil {
		v.m = map[string]apVerdict{}
	}
	for k, e := range v.m {
		if now.After(e.expires) {
			delete(v.m, k)
		}
	}
	v.m[key] = apVerdict{err: err, expires: now.Add(apVerdictTTL)}
}

// admitToAP is multiap.Service.Admit: refuse user on m when one of the
// configured user-record oracles, asked of m alone, says they are
// revoked. An oracle that cannot answer has no opinion, as at refresh.
func (h *Handler) admitToAP(ctx context.Context, m apregistry.Member, user string) error {
	var judges []*multiAPOracle
	for _, o := range h.revocationOracles {
		if mo, ok := o.(*multiAPOracle); ok && mo.judgesUser {
			judges = append(judges, mo)
		}
	}
	if len(judges) == 0 {
		return nil
	}
	key := strings.ToLower(m.Name) + "\x00" + user
	now := time.Now()
	if ok, err := h.apVerdicts.get(key, now); ok {
		return err
	}
	var refusal error
	for _, o := range judges {
		d, err := o.perMember(m).Check(ctx, user, nil)
		if err == nil && d.Status == UserStatusRevoked {
			reason := d.Reason
			if reason == "" {
				reason = "your account is disabled there"
			}
			refusal = &multiap.Error{Status: http.StatusForbidden, Reason: multiap.ReasonDenied,
				Msg: fmt.Sprintf("access point %s refuses you: %s", m.Name, reason)}
			h.logger.Info(logging.DestinationSecurity, "Refusing a request routed to an access point that disables its caller",
				"access_point", m.Name, "user", user, "oracle", o.Name(), "reason", d.Reason)
			break
		}
	}
	h.apVerdicts.put(key, refusal, now)
	return refusal
}

// verifyRoutedCaller is multiap.Service.VerifyCaller: ask m who ctx's
// credential is, and require user. Cached per credential and AP.
func (h *Handler) verifyRoutedCaller(ctx context.Context, m apregistry.Member, user string) error {
	sec, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok {
		return &multiap.Error{Status: http.StatusUnauthorized, Msg: "no credential to present to the access point"}
	}
	tag := sec.SecurityTag
	if tag == "" {
		tag = mcpActorKey(sec.Token)
	}
	key := tag + "\x00" + strings.ToLower(m.Name)
	actor, cached := h.routedCallers.get(key)
	if !cached {
		res, err := m.Schedd.PingWithOptions(ctx, &htcondor.PingOptions{Command: htcondor.DCNopRead})
		if err != nil {
			h.routedCallers.put(key, "", mcpActorFailTTL)
			return &multiap.Error{Status: http.StatusForbidden, Reason: multiap.ReasonDenied,
				Msg: fmt.Sprintf("access point %s did not accept your credential: %v", m.Name, err)}
		}
		actor = res.User
		h.routedCallers.put(key, actor, mcpActorTTL)
	}
	if actor == "" {
		return &multiap.Error{Status: http.StatusForbidden, Reason: multiap.ReasonDenied,
			Msg: fmt.Sprintf("access point %s did not accept your credential", m.Name)}
	}
	if !sameIdentity(qualifyUser(actor, h.uidDomain), user) {
		return &multiap.Error{Status: http.StatusForbidden, Reason: multiap.ReasonDenied,
			Msg: fmt.Sprintf("access point %s identifies your credential as %q, not %q", m.Name, actor, user)}
	}
	return nil
}
