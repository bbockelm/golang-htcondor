package httpserver

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The handler replaces h.schedd when the collector reports a new schedd
// address, under scheddMu. Reading the field directly is therefore two
// bugs at once: a data race with that write, and a captured pointer that
// keeps dialling a socket which no longer exists. getSchedd() takes the
// read lock and returns the current one.
//
// Nothing in the type system enforces that, and the failure is silent --
// the handler keeps answering, against the wrong address -- so this
// guards the invariant by reading the package's own source.
//
// scheddFieldAllowed lists the only places allowed to touch the field
// directly, each because it already holds scheddMu. Adding to this list
// means arguing that the caller holds the lock.
var scheddFieldAllowed = map[string][]string{
	// The getters themselves, under RLock.
	"handler.go": {
		"return h.schedd",
		// applyScheddConfirmationLocked: the caller holds the write
		// lock, so getSchedd() here would deadlock.
		"old := h.schedd.Address()",
	},
}

var scheddFieldUse = regexp.MustCompile(`\b[a-z]\w*(?:\.[a-z]\w*)*\.schedd\b`)

// readsScheddField reports whether a line reads the schedd FIELD. It
// rejects two lookalikes: a comment, and a method named schedd (the
// OAuth2 oracles carry an o.schedd() accessor, which is not this field
// and needs no lock).
func readsScheddField(line string) bool {
	if strings.HasPrefix(line, "//") {
		return false
	}
	for _, loc := range scheddFieldUse.FindAllStringIndex(line, -1) {
		if loc[1] < len(line) && line[loc[1]] == '(' {
			continue // a call, not a field
		}
		return true
	}
	return false
}

func TestScheddIsReadThroughTheGetter(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if !readsScheddField(trimmed) {
				continue
			}
			// Assignments set the field; they are not reads through a
			// stale pointer, and the writers hold the lock.
			if strings.Contains(trimmed, ".schedd =") || strings.Contains(trimmed, "schedd:") {
				continue
			}
			if allowedIn(scheddFieldAllowed[name], trimmed) {
				continue
			}
			offenders = append(offenders, fmt.Sprintf("%s:%d: %s", name, i+1, trimmed))
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("these read the schedd field directly instead of through getSchedd(); "+
			"the field is swapped under scheddMu when the collector reports a new address:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// The guard is only worth having if it would fire, so prove the matcher
// recognises the shape it is looking for.
func TestScheddGetterGuardMatchesTheShapeItGuards(t *testing.T) {
	for _, bad := range []string{
		"result, err := s.schedd.Ping(ctx)",
		"ads, _, err := h.schedd.QueryWithOptions(ctx, c, nil)",
		"errs := s.h.schedd.ReceiveJobSandbox(ctx, c, w)",
	} {
		if !readsScheddField(bad) {
			t.Fatalf("the guard would not catch %q", bad)
		}
	}
	for _, ok := range []string{
		"result, err := s.getSchedd().Ping(ctx)",
		"ads, _, err := h.getSchedd().QueryWithOptions(ctx, c, nil)",
		"scheddName := h.scheddName",
		"schedd := o.schedd()", // an accessor method, not this field
		"// scheddAddrSetAt is the timestamp at which h.schedd was last replaced",
	} {
		if readsScheddField(ok) {
			t.Fatalf("the guard falsely flags %q", ok)
		}
	}
}

func allowedIn(allowed []string, line string) bool {
	for _, a := range allowed {
		if strings.Contains(line, a) {
			return true
		}
	}
	return false
}
