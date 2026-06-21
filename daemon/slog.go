package daemon

import (
	"context"
	"log/slog"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Slog returns a *slog.Logger that forwards into the daemon's HTCondor logger
// (at DestinationGeneral). This lets components written against the standard
// library's slog (a common case) log through the daemon's configured log file,
// levels, and rotation without depending on the htcondor logging API directly.
func (d *Daemon) Slog() *slog.Logger {
	return slog.New(&slogBridge{log: d.log})
}

// slogBridge is an slog.Handler that maps slog records onto a logging.Logger.
type slogBridge struct {
	log    *logging.Logger
	attrs  []any
	groups []string
}

func (h *slogBridge) Enabled(_ context.Context, _ slog.Level) bool {
	// Let the underlying logging.Logger do level/destination filtering.
	return true
}

func (h *slogBridge) Handle(_ context.Context, r slog.Record) error {
	args := make([]any, 0, len(h.attrs)+r.NumAttrs()*2)
	args = append(args, h.attrs...)
	prefix := ""
	for _, g := range h.groups {
		prefix += g + "."
	}
	r.Attrs(func(a slog.Attr) bool {
		args = append(args, prefix+a.Key, a.Value.Any())
		return true
	})

	switch {
	case r.Level >= slog.LevelError:
		h.log.Error(logging.DestinationGeneral, r.Message, args...)
	case r.Level >= slog.LevelWarn:
		h.log.Warn(logging.DestinationGeneral, r.Message, args...)
	case r.Level >= slog.LevelInfo:
		h.log.Info(logging.DestinationGeneral, r.Message, args...)
	default:
		h.log.Debug(logging.DestinationGeneral, r.Message, args...)
	}
	return nil
}

func (h *slogBridge) WithAttrs(attrs []slog.Attr) slog.Handler {
	prefix := ""
	for _, g := range h.groups {
		prefix += g + "."
	}
	extra := make([]any, 0, len(attrs)*2)
	for _, a := range attrs {
		extra = append(extra, prefix+a.Key, a.Value.Any())
	}
	return &slogBridge{
		log:    h.log,
		attrs:  append(append([]any{}, h.attrs...), extra...),
		groups: h.groups,
	}
}

func (h *slogBridge) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &slogBridge{
		log:    h.log,
		attrs:  h.attrs,
		groups: append(append([]string{}, h.groups...), name),
	}
}
