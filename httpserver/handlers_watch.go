package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
	"github.com/PelicanPlatform/classad/collections/vm"
)

// handleCollectorWatch streams collector ad changes to the client as Server-Sent
// Events. Query parameters:
//
//	type       - the ad type to watch (default "StartdAd")
//	constraint - an optional ClassAd match expression (e.g. State == "Claimed")
//
// Resumption uses the standard SSE Last-Event-ID header, which carries the last
// cursor the client received. Each event is emitted as:
//
//	event: reset|upsert|delete|synced|resync|goingaway
//	id:    <base64 cursor>              (on synced and live events)
//	data:  {"key":"<base64>","ad":{...}} (ad present only on upsert)
func (h *Handler) handleCollectorWatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, needsRedirect, err := h.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			h.redirectToLogin(w, r)
			return
		}
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("authentication failed: %v", err))
		return
	}
	col := h.getCollector()
	if col == nil {
		h.writeError(w, http.StatusServiceUnavailable, "no collector configured")
		return
	}

	adType := r.URL.Query().Get("type")
	if adType == "" {
		adType = "StartdAd"
	}
	constraint := r.URL.Query().Get("constraint")
	cursor := cursorFromRequest(r)

	flusher, ok := sseSetup(w)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, "server does not support streaming")
		return
	}

	events, err := col.WatchAds(ctx, adType, constraint, cursor)
	if err != nil {
		// Headers are already sent; report the failure as an SSE error event.
		_ = writeWatchSSE(w, flusher, "error", "", nil, nil, err.Error())
		return
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := writeWatchSSE(w, flusher, sseKind(ev.Kind.String()), watchKeyString(ev.Key), ev.Ad, ev.Cursor, ""); err != nil {
				return
			}
		}
	}
}

// sseSetup writes the SSE response headers and returns the flusher. It reports
// false if the writer cannot stream.
func sseSetup(w http.ResponseWriter) (http.Flusher, bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(": connected\n\n")) // flush headers; EventSource goes "open"
	flusher.Flush()
	return flusher, true
}

// writeWatchSSE writes one watch event as an SSE frame. A non-empty cursor is
// emitted as the id: (the resume token); errMsg, if set, is included in data.
func writeWatchSSE(w http.ResponseWriter, flusher http.Flusher, event, key string, ad *classad.ClassAd, cursor []byte, errMsg string) error {
	var b strings.Builder
	if len(cursor) > 0 {
		fmt.Fprintf(&b, "id: %s\n", base64.StdEncoding.EncodeToString(cursor))
	}
	payload := map[string]any{}
	if key != "" {
		payload["key"] = key
	}
	if ad != nil {
		payload["ad"] = ad // ClassAd.MarshalJSON
	}
	if errMsg != "" {
		payload["error"] = errMsg
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil // skip an unencodable event rather than tear down the stream
	}
	fmt.Fprintf(&b, "event: %s\ndata: %s\n\n", event, data)
	if _, err := w.Write([]byte(b.String())); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

// sseKind maps a watch Kind name ("Upsert", ...) to its lower-case SSE event name.
func sseKind(kindName string) string { return strings.ToLower(kindName) }

// watchKeyString renders a watch key as a stable, JSON-safe identifier the
// client uses to correlate upserts and deletes. A clean printable-ASCII key
// (e.g. a job's "cluster.proc") passes through as-is; a key with a NUL or other
// non-printable byte (e.g. the collector's composite Name\0Address) is base64ed.
func watchKeyString(key string) string {
	if key == "" {
		return ""
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x20 || key[i] > 0x7e {
			return base64.StdEncoding.EncodeToString([]byte(key))
		}
	}
	return key
}

// collectionsKind maps a collections.WatchKind to its SSE event name.
func collectionsKind(k collections.WatchKind) string {
	switch k {
	case collections.WatchUpsert:
		return "upsert"
	case collections.WatchDelete:
		return "delete"
	case collections.WatchReset:
		return "reset"
	case collections.WatchSynced:
		return "synced"
	case collections.WatchResync:
		return "resync"
	default:
		return "unknown"
	}
}

// handleJobsWatch streams job-ad changes -- from the schedd's job_queue.log
// mirror -- to the client as Server-Sent Events, using the same framing and
// resume semantics as handleCollectorWatch. Query parameter constraint (a ClassAd
// match expression, e.g. DAGManJobId == 42) delivers only matching jobs; a job
// that stops matching arrives as a delete.
func (h *Handler) handleJobsWatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, needsRedirect, err := h.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			h.redirectToLogin(w, r)
			return
		}
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("authentication failed: %v", err))
		return
	}
	if h.jobMirror == nil {
		h.writeError(w, http.StatusServiceUnavailable, "job queue mirror not configured")
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stop the watch iterator when the handler returns

	constraint := r.URL.Query().Get("constraint")
	cursor := cursorFromRequest(r)

	flusher, ok := sseSetup(w)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, "server does not support streaming")
		return
	}

	seq, err := h.jobMirror.Collection().Watch(ctx, cursor)
	if err != nil {
		_ = writeWatchSSE(w, flusher, "error", "", nil, nil, err.Error())
		return
	}
	if strings.TrimSpace(constraint) != "" {
		q, err := vm.Parse(constraint)
		if err != nil {
			_ = writeWatchSSE(w, flusher, "error", "", nil, nil, fmt.Sprintf("bad constraint: %v", err))
			return
		}
		seq = collections.WatchFilter(seq, q.Matches)
	}

	streamCollectionEvents(ctx, w, r, flusher, seq)
}

// streamCollectionEvents pumps a collections watch sequence to the client as SSE
// frames until ctx or the request ends, servicing a heartbeat so idle proxies
// keep the connection. The pull iterator is fed through a channel so the loop can
// also select on the ticker and disconnect.
func streamCollectionEvents(ctx context.Context, w http.ResponseWriter, r *http.Request, flusher http.Flusher, seq iter.Seq[collections.WatchEvent]) {
	events := make(chan collections.WatchEvent, 64)
	go func() {
		defer close(events)
		for ev := range seq {
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := writeWatchSSE(w, flusher, collectionsKind(ev.Kind), watchKeyString(string(ev.Key)), ev.Ad, ev.Cursor, ""); err != nil {
				return
			}
		}
	}
}

// cursorFromRequest recovers a resume cursor from the SSE Last-Event-ID header
// (or a ?cursor= query param), which carries the base64 cursor of the last event
// the client saw. Returns nil (full replay) if absent or malformed.
func cursorFromRequest(r *http.Request) []byte {
	id := r.Header.Get("Last-Event-ID")
	if id == "" {
		id = r.URL.Query().Get("cursor")
	}
	if id == "" {
		return nil
	}
	c, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		return nil
	}
	return c
}
