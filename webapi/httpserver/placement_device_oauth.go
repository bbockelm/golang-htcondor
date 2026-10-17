package httpserver

import (
	"fmt"
	"html"
	"net/http"
	"slices"

	"github.com/ory/fosite"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Approval of a placement device request in this server's own RFC 8628 flow
// for placement-client. It differs from other device approvals in two ways:
//
//   - a placement-only session may approve it, and only it;
//   - the grant records the approving identity, which is what the placement
//     endpoints act for. Its subject is the account the session signed in as,
//     or the local username, or empty for a placement-only session.

// placementApproverBinding is the CSRF binding name for an approver known
// only by identity.
func placementApproverBinding(identity string) string {
	return "placement:" + identity
}

// placementDeviceApprover is the session that may approve a placement
// request: any session, placement-only included, that carries an identity.
func (h *Handler) placementDeviceApprover(r *http.Request) (*SessionData, bool) {
	sd, ok := h.getAnySessionFromRequest(r)
	if !ok || sd.PlacementIdentity == "" {
		return nil, false
	}
	return sd, true
}

// placementGrantSubject is the subject a placement grant gets.
func placementGrantSubject(sd *SessionData) string {
	switch {
	case sd.IsPlacementd():
		return sd.Placement.Account
	case sd.IsPlacementOnly():
		return ""
	default:
		return sd.Username
	}
}

// renderPlacementDeviceConsent shows the approve/deny form for a placement
// request. The grant is fixed (a placement token for this identity), so
// there are no scope checkboxes.
func (h *Handler) renderPlacementDeviceConsent(w http.ResponseWriter, approver *SessionData, userCode string, request fosite.Requester) {
	clientName := placementDeviceClientName(request.GetClient().GetID())
	token := h.consentCSRFToken(placementApproverBinding(approver.PlacementIdentity), userCode)
	page := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Placement token request</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
               background: #f3f4f6; display: flex; align-items: center; justify-content: center;
               min-height: 100vh; margin: 0; padding: 20px; }
        .box { background: white; border-radius: 12px; max-width: 480px; width: 100%%; padding: 32px;
               box-shadow: 0 4px 20px rgba(0,0,0,.08); }
        h1 { font-size: 22px; margin: 0 0 12px; }
        p { color: #444; line-height: 1.5; }
        code { background: #f3f4f6
; padding: 2px 6px; border-radius: 4px; }
        button { padding: 10px 18px; border-radius: 6px; border: 0; font-size: 15px; cursor: pointer; margin-right: 8px; }
        .approve { background: #2563eb; color: white; }
        .deny { background: #e5e7eb; color: #111; }
    </style>
</head>
<body>
    <div class="box">
        <h1>Placement token request</h1>
        <p><strong>%s</strong> is asking for a placement token for <code>%s</code>.</p>
        <p>Check that the code <code>%s</code> matches the one it shows.</p>
        <form method="POST" action="%s">
            <input type="hidden" name="user_code" value="%s">
            <input type="hidden" name="%s" value="%s">
            <button class="approve" type="submit" name="action" value="approve">Approve</button>
            <button class="deny" type="submit" name="action" value="deny">Deny</button>
        </form>
    </div>
</body>
</html>`,
		html.EscapeString(clientName),
		html.EscapeString(approver.PlacementIdentity),
		html.EscapeString(userCode),
		html.EscapeString(h.deviceVerifyPath()),
		html.EscapeString(userCode),
		consentCSRFField, html.EscapeString(token))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

// decidePlacementDevice applies an approve or deny to a placement request.
// The caller has checked the CSRF token against the approver's identity.
func (h *Handler) decidePlacementDevice(w http.ResponseWriter, r *http.Request, approver *SessionData,
	userCode string, request fosite.Requester) {
	ctx := r.Context()
	storage := h.oauth2Provider.GetStorage()
	switch r.FormValue("action") {
	case "approve":
		accepted := make([]string, 0, 2)
		for _, s := range request.GetRequestedScopes() {
			if slices.Contains(placementClientScopes, s) && !slices.Contains(accepted, s) {
				accepted = append(accepted, s)
			}
		}
		if !isPlacementGrant(accepted) {
			h.writeHTMLError(w, "This request does not ask for a placement token")
			return
		}
		subject := placementGrantSubject(approver)
		session := DefaultOpenIDConnectSession(subject).WithAuthorizedScopes(accepted)
		session.PlacementIdentity = approver.PlacementIdentity
		if err := storage.ApproveDeviceCodeSessionWithScopes(ctx, userCode, subject, session, accepted); err != nil {
			h.logger.Error(logging.DestinationHTTP, "Failed to approve a placement device request", "error", err)
			h.writeHTMLError(w, "Failed to approve the request")
			return
		}
		h.logger.Info(logging.DestinationSecurity, "Placement device request approved",
			"user_code", userCode, "identity", approver.PlacementIdentity, "subject", subject,
			"client_id", request.GetClient().GetID(), "scopes", accepted)
		h.renderResultPage(w, http.StatusOK, "Request approved", "#4CAF50", "&#10003; Request approved",
			"The program that asked will receive its token.", "You can close this window now.")
	case "deny":
		if err := storage.DenyDeviceCodeSession(ctx, userCode); err != nil {
			h.writeHTMLError(w, "Failed to deny the request")
			return
		}
		h.logger.Info(logging.DestinationHTTP, "Placement device request denied",
			"user_code", userCode, "identity", approver.PlacementIdentity)
		h.renderResultPage(w, http.StatusOK, "Request denied", "#f44336", "&#10007; Request denied",
			"You have denied the request.", "You can close this window now.")
	default:
		h.writeHTMLError(w, "Invalid action")
	}
}

// refusePlacementdDeviceClient refuses a placementd-assigned account's
// approval of the SSH gateway's device request: the gateway logs in as a
// local account, which such an account need not be.
func (h *Handler) refusePlacementdDeviceClient(w http.ResponseWriter, r *http.Request, request fosite.Requester) bool {
	if request.GetClient().GetID() != sshGatewayClientID {
		return false
	}
	if _, ok := h.placementdSession(r); !ok {
		return false
	}
	h.writeHTMLError(w, "The SSH gateway is not available to accounts assigned by the placement service")
	return true
}
