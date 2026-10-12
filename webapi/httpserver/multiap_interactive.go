package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// Interactive work in multi-AP mode: browser terminals, named sessions
// (MCP and the SSH gateway), JupyterLab and apps.
//
// Each is placed like a submission: the AP the caller's assignment
// names, for the kind of work it is ("interactive" for terminals,
// sessions and apps, "jupyter" for JupyterLab), or an alternate the
// caller names with ?schedd=. That AP is then part of the thing's
// record -- the terminal's complete job id, the session's record in the
// manager, the JupyterLab row's schedd column, the app's id -- and every
// later step goes there by that record. Nothing is assigned twice: a
// user whose assignment moves keeps what they have where it is.
//
// Lists are reads, and come from the hub like every other multi-AP read;
// an action on one thing asks its own AP.

// multiAPInteractivePath reports whether multi-AP mode serves method on
// one of the interactive surfaces' paths.
func multiAPInteractivePath(method, path string) bool {
	read := method == http.MethodGet || method == http.MethodHead
	switch {
	case path == "/api/v1/interactive/terminal":
		return read || method == http.MethodPost
	case path == "/api/v1/apps" || path == "/api/v1/apps/":
		return read || method == http.MethodPost
	case strings.HasPrefix(path, "/api/v1/apps/"):
		rest := strings.TrimPrefix(path, "/api/v1/apps/")
		return rest != "" && !strings.Contains(rest, "/") && (read || method == http.MethodDelete)
	case path == "/api/v1/jupyter/instances" || path == "/api/v1/jupyter/instances/":
		return read || method == http.MethodPost
	case strings.HasPrefix(path, "/api/v1/jupyter/instances/"):
		// One instance, its events, its helper's tunnel, and the proxy
		// into it, which carries whatever JupyterLab speaks. The
		// handler refuses what it does not serve.
		return true
	}
	return false
}

// interactiveAssignRequest is the assignment question for a new piece
// of interactive work of kind.
func (h *Handler) interactiveAssignRequest(ctx context.Context, r *http.Request, user, kind string) apassign.Request {
	c := h.callerClaims(ctx, r)
	return apassign.Request{User: user, Subject: c.Subject, Groups: c.Groups, Kind: kind}
}

// multiAssign places a new terminal, JupyterLab or app: the AP the
// caller's assignment names for kind, or the alternate ?schedd= names,
// admitting the caller and identifying them as themselves there. It
// returns ctx routed to that AP, or writes the error. The caller notes
// the write again when it is done.
func (h *Handler) multiAssign(ctx context.Context, w http.ResponseWriter, r *http.Request, actor, kind string) (context.Context, apregistry.Member, bool) {
	user, err := h.multi.svc.UserFor(actor)
	if err != nil {
		h.multiAPError(w, err)
		return nil, apregistry.Member{}, false
	}
	m, _, err := h.multi.svc.SubmitTarget(ctx, h.interactiveAssignRequest(ctx, r, user, kind), r.URL.Query().Get("schedd"))
	if err != nil {
		h.multiAPError(w, err)
		return nil, apregistry.Member{}, false
	}
	ctx = multiap.WithTarget(ctx, multiap.Target{Member: m})
	if v := h.multi.svc.VerifyCaller; v != nil {
		if err := v(ctx, m, user); err != nil {
			h.multiAPError(w, err)
			return nil, apregistry.Member{}, false
		}
	}
	h.multi.svc.NoteWrite(m.Name)
	return ctx, m, true
}

// multiRoute routes ctx to ap, the AP an existing terminal, JupyterLab
// or app is recorded on: the member as the registry knows it now, and
// the AP's own verdict on the caller. Never another AP.
func (h *Handler) multiRoute(ctx context.Context, actor, ap string) (context.Context, error) {
	user, err := h.multi.svc.UserFor(actor)
	if err != nil {
		return nil, err
	}
	m, err := h.multi.svc.Member(ap)
	if err != nil {
		return nil, err
	}
	if err := h.multi.svc.AdmitTo(ctx, m, user); err != nil {
		return nil, err
	}
	return multiap.WithTarget(ctx, multiap.Target{Member: m}), nil
}

// --- browser terminals --------------------------------------------------------

// interactiveTerminalAttrs is what a terminal listing reads off a job.
var interactiveTerminalAttrs = []string{
	"ClusterId", "ProcId", "JobStatus", "JobBatchName",
	"HoldReason", "HoldReasonCode", "QDate",
	"JobCurrentStartExecutingDate",
}

// interactiveTerminalSummary reads one terminal or session job's ad, or
// reports false for a job that is neither.
func (h *Handler) interactiveTerminalSummary(ad *classad.ClassAd, schedd string) (InteractiveTerminalSummary, bool) {
	batchName, ok := ad.EvaluateAttrString("JobBatchName")
	if !ok {
		return InteractiveTerminalSummary{}, false
	}
	kind, sessionName, ok := classifyInteractiveBatchName(batchName)
	if !ok {
		return InteractiveTerminalSummary{}, false
	}
	clusterID, _ := ad.EvaluateAttrInt("ClusterId")
	procID, _ := ad.EvaluateAttrInt("ProcId")
	jobStatus, _ := ad.EvaluateAttrInt("JobStatus")
	holdCode, _ := ad.EvaluateAttrInt("HoldReasonCode")
	holdReason, _ := ad.EvaluateAttrString("HoldReason")
	qdate, _ := ad.EvaluateAttrInt("QDate")
	startExec, _ := ad.EvaluateAttrInt("JobCurrentStartExecutingDate")

	summary := InteractiveTerminalSummary{
		Kind:                         kind,
		Name:                         sessionName,
		SSHCommand:                   h.sshCommandForSession(kind, sessionName),
		InstanceID:                   strings.TrimPrefix(batchName, interactiveTerminalBatchPrefix),
		JobID:                        fmt.Sprintf("%d.%d", clusterID, procID),
		Schedd:                       schedd,
		ClusterID:                    int(clusterID),
		ProcID:                       int(procID),
		BatchName:                    batchName,
		JobStatus:                    int(jobStatus),
		JobCurrentStartExecutingDate: startExec,
		HoldReasonCode:               int(holdCode),
		HoldReason:                   holdReason,
	}
	if h.multi != nil && schedd != "" {
		summary.JobID = h.multi.codec.Format(jobid.ID{Schedd: schedd, Cluster: clusterID, Proc: procID})
	}
	if qdate > 0 {
		summary.SubmittedAt = time.Unix(qdate, 0).UTC().Format(time.RFC3339)
	}
	return summary, true
}

// multiListInteractiveTerminals serves GET /api/v1/interactive/terminal
// in multi-AP mode: the caller's terminals and sessions on every AP,
// from the hub, each naming its AP and carrying its complete job id.
func (h *Handler) multiListInteractiveTerminals(ctx context.Context, w http.ResponseWriter, actor string) {
	user, err := h.multi.svc.UserFor(actor)
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	constraint := fmt.Sprintf("regexp(%s, JobBatchName) || regexp(%s, JobBatchName)",
		classadStringLit("^"+interactiveTerminalBatchPrefix), classadStringLit("^"+interactive.SessionBatchPrefix))
	rows, sources, err := h.multi.svc.FindOwn(ctx, user, constraint, interactiveTerminalAttrs, 500)
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	out := make([]InteractiveTerminalSummary, 0, len(rows))
	for _, row := range rows {
		if summary, ok := h.interactiveTerminalSummary(row.Ad, row.ID.Schedd); ok {
			out = append(out, summary)
		}
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"terminals": out, "source": "hub", "sources": sources})
}

// --- apps -------------------------------------------------------------------

// appIDText is how an app is named to callers: its id, and in multi-AP
// mode the id with the AP it is on ("<id>@<schedd>"), so a later GET or
// DELETE goes straight there -- the app's own record, as a complete job
// id is a job's.
func (h *Handler) appIDText(id, schedd string) string {
	if h.multi == nil || schedd == "" {
		return id
	}
	return id + "@" + schedd
}

// splitAppID reads an app id: the id, and the AP when the text names
// one. An app's own id never contains "@"; an AP name may.
func splitAppID(text string) (id, schedd string) {
	id, schedd, _ = strings.Cut(text, "@")
	return id, schedd
}

// multiListApps serves GET /api/v1/apps in multi-AP mode: the caller's
// apps on every AP, from the hub.
func (h *Handler) multiListApps(ctx context.Context, w http.ResponseWriter, owner string) {
	user, err := h.multi.svc.UserFor(owner)
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	rows, sources, err := h.multi.svc.FindOwn(ctx, user, appConstraint, appAdAttrs, 200)
	if err != nil {
		h.multiAPError(w, err)
		return
	}
	out := make([]AppSummary, 0, len(rows))
	for _, row := range rows {
		if sum, ok := h.appSummary(row.Ad, owner, row.ID.Schedd); ok {
			out = append(out, sum)
		}
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"apps": out, "source": "hub", "sources": sources})
}

// multiFindApp finds one of the caller's apps by id in multi-AP mode.
// An id naming its AP ("<id>@<schedd>") is looked up on that AP only;
// a bare id is placed by the hub, and one the hub finds on two APs is
// refused rather than guessed. It returns the context routed to the
// app's AP, for whatever is done to it next.
func (h *Handler) multiFindApp(ctx context.Context, owner, text string) (AppSummary, context.Context, error) {
	id, schedd := splitAppID(text)
	want := appBatchConstraint(id)
	if schedd == "" {
		user, err := h.multi.svc.UserFor(owner)
		if err != nil {
			return AppSummary{}, nil, err
		}
		rows, _, err := h.multi.svc.FindOwn(ctx, user, want, appAdAttrs, 10)
		if err != nil {
			return AppSummary{}, nil, err
		}
		var aps []string
		for _, row := range rows {
			if !containsFold(aps, row.ID.Schedd) {
				aps = append(aps, row.ID.Schedd)
			}
		}
		switch len(aps) {
		case 0:
			return AppSummary{}, nil, errNoSuchApp
		case 1:
			schedd = aps[0]
		default:
			return AppSummary{}, nil, &multiap.Error{Status: http.StatusConflict,
				Msg: fmt.Sprintf("app %s is on more than one access point (%s); name it as <id>@<access point>",
					id, strings.Join(aps, ", "))}
		}
	}
	routed, err := h.multiRoute(ctx, owner, schedd)
	if err != nil {
		return AppSummary{}, nil, err
	}
	schedd = routedSchedd(routed) // the AP set's spelling
	ads, err := h.queryAppAdsWithConstraint(routed, owner, want)
	if err != nil {
		return AppSummary{}, nil, err
	}
	for _, ad := range ads {
		if sum, ok := h.appSummary(ad, owner, schedd); ok && sum.ID == h.appIDText(id, schedd) {
			return sum, routed, nil
		}
	}
	return AppSummary{}, nil, errNoSuchApp
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// --- JupyterLab ---------------------------------------------------------------

// jupyterScheddMeta is the instance metadata key recording the AP a
// JupyterLab session's job is on, in multi-AP mode.
const jupyterScheddMeta = "schedd"

// jupyterQueryContext is the context a JupyterLab instance's job is read
// with: ctx in single-AP mode; in multi-AP mode, ctx routed to the AP the
// instance's record names. ok is false for an instance with no AP on
// record (a row from before this server fronted several APs) or whose
// AP cannot be asked now: its job is not looked for anywhere else, and
// the instance is neither enriched nor reaped.
func (h *Handler) jupyterQueryContext(ctx context.Context, actor, schedd string) (context.Context, bool) {
	if h.multi == nil {
		return ctx, true
	}
	if schedd == "" {
		return nil, false
	}
	routed, err := h.multiRoute(ctx, actor, schedd)
	if err != nil {
		return nil, false
	}
	return routed, true
}

// jupyterScheddFor is the schedd a JupyterLab call on ctx uses: the
// stand-in a unit test installed, else scheddFor's answer.
func (h *Handler) jupyterScheddFor(ctx context.Context) jupyterScheddOps {
	if h.jupyterScheddOverride != nil {
		return h.jupyterScheddOverride
	}
	return h.scheddFor(ctx)
}
