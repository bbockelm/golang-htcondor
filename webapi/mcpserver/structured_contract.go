package mcpserver

import (
	"reflect"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Making a published outputSchema true of what a tool actually returns.
//
// A tool that publishes an outputSchema has promised two things a client
// enforces: every successful result carries structuredContent, and that
// content validates. Break either and the client turns a result this server
// considers a success into a failure the caller sees instead -- for a
// mutating tool, a failure for work that already happened, which invites a
// retry that does it twice.
//
// Nothing here fails on this side, which is why all three instances were
// found on a live access point rather than in a test:
//
//   - A Go nil slice or nil map marshals to JSON `null`, not `[]` or `{}`.
//     A handler that accumulates with append into a `var xs []T` emits a
//     correct array for every result with something in it and `null` for
//     the empty one. query_jobs did exactly this: it worked until a
//     constraint matched no jobs.
//
//   - A handler that files its payload under this codebase's `metadata` key
//     and never mirrors it into structuredContent looks complete -- the text
//     block and the metadata are both right -- and is rejected wholesale at
//     the client. build_container did this: it submitted the build job,
//     spooled its inputs, and then reported a failure.
//
//   - A handler that returns the content envelope alone, with the payload
//     rendered into the text, has the same effect. whoami did this.
//
// finalizeToolResult is the one place both are corrected, applied by
// handleCallTool to every successful tool result from either transport.
// Handlers are still expected to get this right themselves; this is the net
// under them, and the promotion half of it logs, because a handler that
// needed it has a bug that will otherwise stay invisible.

// finalizeToolResult brings one successful tool result up to the contract
// its published outputSchema states. A tool with no schema is returned
// untouched: nothing is promised about its result, so nothing is repaired.
func (s *Server) finalizeToolResult(name string, result interface{}) interface{} {
	if outputSchemaFor(name) == nil {
		return result
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		return result
	}

	// A handler that put the payload only under "metadata" has published
	// no structuredContent at all. Throughout this server the two carry
	// the same map -- every withStructured call site passes one value to
	// both -- so the metadata is the payload, filed under the older name.
	if _, has := m["structuredContent"]; !has {
		if meta, ok := m["metadata"].(map[string]interface{}); ok && len(meta) > 0 {
			m["structuredContent"] = meta
			if s != nil && s.logger != nil {
				s.logger.Warn(logging.DestinationMCP,
					"tool result carried no structuredContent; promoted its metadata",
					"tool", name)
			}
		}
	}

	if sc, has := m["structuredContent"]; has {
		if fixed, changed := emptyNotNull(sc); changed {
			m["structuredContent"] = fixed
		}
	}
	return m
}

// emptyNotNull replaces nil slices and nil maps with empty ones, so that a
// result with nothing in it marshals as `[]` / `{}` rather than `null` and
// satisfies a schema that declares an array or an object there.
//
// It reports whether anything changed, and writes only when something did:
// a payload can share a map with state the server keeps (the match
// analyzer's slot-cache status, say), and an unconditional write-back would
// be a write to shared state on every call.
//
// Recursion stops at the first element of a slice whose element kind cannot
// itself hold a nil slice or map, which makes the common cases -- []byte,
// []*classad.ClassAd, []string -- one type check rather than a walk.
func emptyNotNull(v interface{}) (interface{}, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() {
			return reflect.MakeMap(rv.Type()).Interface(), true
		}
		m, ok := v.(map[string]interface{})
		if !ok {
			// A concretely-typed map (map[string]string) has no
			// interface-valued members to descend into.
			return v, false
		}
		changed := false
		for k, e := range m {
			if fixed, c := emptyNotNull(e); c {
				m[k] = fixed
				changed = true
			}
		}
		return v, changed
	case reflect.Slice:
		if rv.IsNil() {
			return reflect.MakeSlice(rv.Type(), 0, 0).Interface(), true
		}
		changed := false
		for i := 0; i < rv.Len(); i++ {
			el := rv.Index(i)
			switch el.Kind() {
			case reflect.Interface, reflect.Map, reflect.Slice:
			default:
				// Homogeneous element kind, and not one that can hold
				// a nil collection: nothing below this is reachable.
				return v, false
			}
			fixed, c := emptyNotNull(el.Interface())
			if !c || !el.CanSet() {
				continue
			}
			fv := reflect.ValueOf(fixed)
			if fv.IsValid() && fv.Type().AssignableTo(el.Type()) {
				el.Set(fv)
				changed = true
			}
		}
		return v, changed
	default:
		return v, false
	}
}
