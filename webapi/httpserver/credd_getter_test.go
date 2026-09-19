package httpserver

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// The credd address updater replaces h.credd in the background when a
// credd appears or moves. creddAvailable is atomic, which covered the
// flag but never the handle beside it: an interface value is two words,
// so a reader racing the write can observe a type and a data pointer
// that never went together. getCredd() takes the read lock.
//
// Run with -race, this fails on a direct field read in the request path.
func TestCreddIsSafeUnderConcurrentReplacement(t *testing.T) {
	h := &Handler{}
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h.setCredd(htcondor.NewInMemoryCredd())
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if c := h.getCredd(); c == nil {
					continue
				}
			}
		}()
	}
	wg.Wait()

	if h.getCredd() == nil {
		t.Fatal("no credd survived the replacements")
	}
}

// creddFieldAllowed lists the only places allowed to touch the field
// directly, each because it is the accessor itself. Adding to this list
// means arguing that the caller holds creddMu.
var creddFieldAllowed = map[string][]string{
	"handler.go": {
		"return h.credd", // getCredd, under RLock
		"h.credd = c",    // setCredd, under Lock
	},
}

var creddFieldUse = regexp.MustCompile(`\b[a-z]\w*(?:\.[a-z]\w*)*\.credd\b`)

// readsCreddField reports whether a line reads the credd FIELD, ignoring
// comments and same-named method calls.
func readsCreddField(line string) bool {
	if strings.HasPrefix(line, "//") {
		return false
	}
	for _, loc := range creddFieldUse.FindAllStringIndex(line, -1) {
		if loc[1] < len(line) && line[loc[1]] == '(' {
			continue // a call, not a field
		}
		return true
	}
	return false
}

func TestCreddIsReadThroughTheGetter(t *testing.T) {
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
		//nolint:gosec // G304: name comes from ReadDir of this package's
		// own directory, in a test.
		src, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if !readsCreddField(trimmed) {
				continue
			}
			if allowedCredd(creddFieldAllowed[name], trimmed) {
				continue
			}
			offenders = append(offenders, fmt.Sprintf("%s:%d: %s", name, i+1, trimmed))
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("these read the credd field directly instead of through getCredd(); "+
			"the address updater replaces it in the background:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// The guard is only worth having if it would fire.
func TestCreddGetterGuardMatchesTheShapeItGuards(t *testing.T) {
	for _, bad := range []string{
		"creds, err := s.credd.ListServiceCreds(ctx, htcondor.CredTypeOAuth, user)",
		"if h.credd == nil {",
		"Credd: h.credd,",
	} {
		if !readsCreddField(bad) {
			t.Fatalf("the guard would not catch %q", bad)
		}
	}
	for _, ok := range []string{
		"creds, err := s.getCredd().ListServiceCreds(ctx, htcondor.CredTypeOAuth, user)",
		"if !s.creddAvailable.Load() {",
		"// h.credd is replaced by the address updater",
		"h.creddDiscovered = true",
	} {
		if readsCreddField(ok) {
			t.Fatalf("the guard falsely flags %q", ok)
		}
	}
}

func allowedCredd(allowed []string, line string) bool {
	for _, a := range allowed {
		if strings.Contains(line, a) {
			return true
		}
	}
	return false
}
