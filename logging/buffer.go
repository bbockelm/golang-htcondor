package logging

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// BufferEntry is a single in-memory log line, kept lightweight so we can
// hold thousands of them without significant memory pressure.
type BufferEntry struct {
	Time        time.Time         `json:"time"`
	Level       string            `json:"level"`       // ERROR/WARN/INFO/DEBUG
	Destination string            `json:"destination"` // http/schedd/cedar/...
	Message     string            `json:"message"`
	Fields      map[string]string `json:"fields,omitempty"`
}

// Buffer is a thread-safe ring buffer of recent log entries. Used by the
// admin Web UI to show recent activity without giving the SPA a path to
// the on-disk log files.
type Buffer struct {
	mu      sync.RWMutex
	entries []BufferEntry
	size    int
	pos     int  // next write position
	full    bool // wrapped at least once
	// minLevel filters entries before they enter the buffer. Records below
	// this threshold are dropped on Add — there's no point storing them.
	minLevel slog.Level
}

// NewBuffer returns a ring buffer holding the most-recent `size` entries
// at or above `minLevel`. Pass slog.LevelInfo for "operationally
// interesting" only; slog.LevelDebug to keep everything.
func NewBuffer(size int, minLevel slog.Level) *Buffer {
	if size <= 0 {
		size = 1000
	}
	return &Buffer{
		entries:  make([]BufferEntry, size),
		size:     size,
		minLevel: minLevel,
	}
}

// Add appends an entry, overwriting the oldest if full. Entries below
// minLevel are silently dropped.
func (b *Buffer) Add(e BufferEntry) {
	if levelFromString(e.Level) < b.minLevel {
		return
	}
	b.mu.Lock()
	b.entries[b.pos] = e
	b.pos++
	if b.pos == b.size {
		b.pos = 0
		b.full = true
	}
	b.mu.Unlock()
}

// Entries returns all stored entries in chronological order (oldest first).
// Returns at most `limit` entries; pass 0 for "all".
func (b *Buffer) Entries(limit int) []BufferEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	n := b.pos
	if b.full {
		n = b.size
	}
	out := make([]BufferEntry, 0, n)
	if b.full {
		// Oldest entries start at b.pos and wrap around.
		out = append(out, b.entries[b.pos:b.size]...)
		out = append(out, b.entries[:b.pos]...)
	} else {
		out = append(out, b.entries[:b.pos]...)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// teeHandler is a slog.Handler that copies records to a Buffer in
// addition to delegating to its inner handler. We don't try to be
// perfectly lossless: we copy a small fixed number of structured fields
// and drop the rest. The on-disk log remains the source of truth.
type teeHandler struct {
	inner slog.Handler
	buf   *Buffer
	// maxFields caps how many attribute key/values we serialize into
	// each BufferEntry. The Web UI shows a few fields per row, not the
	// full structured payload.
	maxFields int
}

func (h *teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	// Always forward to the inner handler first.
	innerErr := h.inner.Handle(ctx, r)

	// Skip buffer capture if the record is below threshold — saves the
	// allocations below. teeHandler is constructed with the buffer's
	// minLevel so this short-circuit catches the common case cheaply.
	if r.Level < h.buf.minLevel {
		return innerErr
	}

	entry := BufferEntry{
		Time:    r.Time,
		Level:   r.Level.String(),
		Message: r.Message,
	}
	fields := map[string]string{}
	count := 0
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "destination" {
			entry.Destination = a.Value.String()
			return true
		}
		if count >= h.maxFields {
			return true
		}
		fields[a.Key] = a.Value.String()
		count++
		return true
	})
	if len(fields) > 0 {
		entry.Fields = fields
	}
	h.buf.Add(entry)
	return innerErr
}

func (h *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &teeHandler{
		inner:     h.inner.WithAttrs(attrs),
		buf:       h.buf,
		maxFields: h.maxFields,
	}
}

func (h *teeHandler) WithGroup(name string) slog.Handler {
	return &teeHandler{
		inner:     h.inner.WithGroup(name),
		buf:       h.buf,
		maxFields: h.maxFields,
	}
}

// AttachBuffer wraps the logger's existing slog handler with one that
// also writes to the supplied buffer. Subsequent log calls (and any
// already-active descendants made via the slog API) will fan out to
// both the original destination and the buffer.
//
// Returns immediately if l or buf is nil. Idempotent in the sense that
// re-attaching is safe — but it stacks; pass a freshly-built logger
// once at startup.
func AttachBuffer(l *Logger, buf *Buffer) {
	if l == nil || buf == nil {
		return
	}
	cur := l.logger.Load()
	if cur == nil {
		return
	}
	tee := &teeHandler{
		inner:     cur.Handler(),
		buf:       buf,
		maxFields: 8,
	}
	l.logger.Store(slog.New(tee))
}

// levelFromString converts the strings emitted by slog.Level.String()
// (and by our writeLog wrappers) back into a slog.Level for comparison.
// Anything unrecognized maps to LevelInfo so unknown rows aren't
// silently dropped by the threshold check.
func levelFromString(s string) slog.Level {
	switch s {
	case "DEBUG", "Debug", "debug":
		return slog.LevelDebug
	case "INFO", "Info", "info":
		return slog.LevelInfo
	case "WARN", "Warning", "warn", "WARNING":
		return slog.LevelWarn
	case "ERROR", "Error", "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
