package httpserver

import (
	"github.com/PelicanPlatform/classad/classad"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bbockelm/golang-htcondor/webapi/apiad"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// AdvertiseAugment returns the daemon.AdvertiseConfig.Augment callback that adds
// this API server's attributes to its collector ad. Exported so the daemon
// bootstrap in package main can wire it without reaching into unexported state.
func (h *Handler) AdvertiseAugment() func(*classad.ClassAd) {
	return apiad.Augment(h.advertiseInput)
}

// registerStreamGauge exports the live open-stream count to Prometheus, backed
// by the same atomic the collector ad reads.
func (h *Handler) registerStreamGauge() {
	h.httpMetricsState.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "htcondor_api",
		Subsystem: "http",
		Name:      "active_watch_streams",
		Help:      "Long-lived SSE streams (job/collector watch, Jupyter events) currently open.",
	}, func() float64 { return float64(h.activeStreams.Load()) }))
}

// streamOpened records that a long-lived SSE stream has started and returns the
// matching close func; call as `defer h.streamOpened()()` right after the SSE
// headers are written. This is the single inc/dec choke point for the
// active-stream gauge and the ad's ActiveWatchStreams.
func (h *Handler) streamOpened() func() {
	h.activeStreams.Add(1)
	return func() { h.activeStreams.Add(-1) }
}

// advertiseInput snapshots the HTTP-API state for one collector advertisement.
// Called once per cycle by apiad.Augment, so runtime changes (mirror health, a
// rediscovered schedd, the current stream count) are always current.
func (h *Handler) advertiseInput() apiad.Input {
	in := apiad.Input{
		Endpoint:         h.httpBaseURL,
		ScheddName:       h.scheddName,
		TrustDomain:      h.trustDomain,
		MCPEnabled:       h.mcpServer != nil,
		SuperuserEnabled: h.superuserGroup != "",
		ActiveStreams:    h.activeStreams.Load(),
	}
	if sch := h.getSchedd(); sch != nil {
		in.ScheddAddress = sch.Address()
	}
	if h.dbMirror != nil {
		in.Mirror = mirrorStatusForAd(h.dbMirror.Health())
	}
	return in
}

// mirrorStatusForAd distills a dbmirror.Health into the ad's compact mirror
// summary: healthy means enabled, dialable, and (if a token is used) minted
// without error; Status carries the first failing reason otherwise.
func mirrorStatusForAd(hl dbmirror.Health) apiad.MirrorStatus {
	m := apiad.MirrorStatus{Enabled: hl.Enabled}
	if !hl.Enabled {
		return m
	}
	switch {
	case hl.LastDialError != "":
		m.Status = "connection error: " + hl.LastDialError
	case hl.TokenError != "":
		m.Status = "token error: " + hl.TokenError
	case hl.LastError != "":
		m.Status = hl.LastError
	default:
		m.Healthy = true
		m.Status = "ok"
	}
	if hl.Info != nil {
		m.StalenessSeconds = dbmirror.HistoryStaleness(hl.Info)
	}
	return m
}
