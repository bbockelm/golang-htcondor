package logging

import (
	"context"
	"log/slog"
)

// Slog returns a *slog.Logger that forwards into this logger, defaulting to
// dest for records that do not name a destination themselves. It lets
// components written against the standard library's slog (a common case) log
// through the configured log file, levels, and rotation without depending on
// the htcondor logging API directly.
func (l *Logger) Slog(dest Destination) *slog.Logger {
	return slog.New(&slogBridge{log: l, dest: dest})
}

// slogBridge is an slog.Handler that maps slog records onto a logging.Logger.
type slogBridge struct {
	log    *Logger
	dest   Destination
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

	// Honor the destination the record names (e.g. cedar tags its records
	// destination=cedar) instead of forcing General, and drop that attribute so
	// logging.Logger re-adds exactly one canonical destination rather than leaving the
	// record with two (the bug that produced "destination=general destination=cedar" and
	// bypassed the cedar destination's Warn-level suppression). Absent/unknown -> General.
	dest, args := extractDestination(args, h.dest)

	switch {
	case r.Level >= slog.LevelError:
		h.log.Error(dest, r.Message, args...)
	case r.Level >= slog.LevelWarn:
		h.log.Warn(dest, r.Message, args...)
	case r.Level >= slog.LevelInfo:
		h.log.Info(dest, r.Message, args...)
	default:
		h.log.Debug(dest, r.Message, args...)
	}
	return nil
}

// extractDestination pulls a "destination" key/value pair out of a flat key,value arg
// slice and maps it to a logging.Destination, returning the remaining args with that pair
// removed. slog callers such as cedar tag records with destination="cedar"; the bridge
// routes on that and removes it so logging.Logger stamps exactly one canonical destination.
// Defaults to the bridge's configured destination when the attribute is absent
// or unrecognized.
func extractDestination(args []any, fallback Destination) (Destination, []any) {
	dest := fallback
	filtered := args[:0]
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			filtered = append(filtered, args[i]) // dangling key; preserve
			break
		}
		if k, ok := args[i].(string); ok && k == "destination" {
			if s, ok := args[i+1].(string); ok {
				if d, ok := ParseDestination(s); ok {
					dest = d
				}
			}
			continue // drop the destination pair
		}
		filtered = append(filtered, args[i], args[i+1])
	}
	return dest, filtered
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
		dest:   h.dest,
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
		dest:   h.dest,
		attrs:  h.attrs,
		groups: append(append([]string{}, h.groups...), name),
	}
}
