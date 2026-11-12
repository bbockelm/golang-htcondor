package siteapps

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A bundle with no policy file beside it must not be served, and the
// operator must be told. Failing silently here is how a lab's app ends
// up either invisible with no explanation or, worse, published by a
// future default.
func TestUnconfiguredBundleIsNotPublished(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	// deliberately not named by any configuration

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 0 {
		t.Fatalf("published %d apps that no configuration names", published)
	}
	if len(problems) != 1 {
		t.Fatalf("problems = %d, want exactly one explaining the missing policy", len(problems))
	}
	// The message has to carry the parameter to set. An operator who
	// is told only that something is missing has to go and find out
	// what to write.
	if msg := problems[0].Error(); !strings.Contains(msg, "HTTP_API_SITE_APP_CRYOEM_GROUPS") {
		t.Errorf("problem does not name the parameter to set: %v", msg)
	}
	if _, ok := lib.Get("cryoem"); ok {
		t.Error("the app is reachable despite not being published")
	}
}

// enabled: false is a deliberate choice, so it is silent -- unlike a
// missing policy file, which is a mistake.
func TestDisabledIsSilent(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	setPolicy(cfg, "cryoem", "lab", "ENABLED", "false")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 0 {
		t.Fatalf("published %d apps, want 0", published)
	}
	if len(problems) != 0 {
		t.Errorf("a deliberate disable reported problems: %v", problems)
	}
}

func TestLoadAndServe(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	setPolicy(cfg, "cryoem", "smith_lab", "HOME", "true")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if published != 1 {
		t.Fatalf("published %d, want 1", published)
	}

	entry, ok := lib.Get("cryoem")
	if !ok {
		t.Fatal("app not found after a successful load")
	}
	if entry.App.Name != "Example Pipeline" {
		t.Errorf("Name = %q", entry.App.Name)
	}
	if !entry.App.Home {
		t.Error("Home = false, want true")
	}
	if got := readFS(t, entry.FS(), "index.html"); !strings.Contains(got, "hi") {
		t.Errorf("index.html = %q", got)
	}
	if got := readFS(t, entry.FS(), "assets/app.js"); got == "" {
		t.Error("nested asset is unreadable")
	}
}

// The served filesystem is rooted at web/, so the manifest is not
// merely unlisted -- it is structurally unreachable. A bundle's
// policy-adjacent metadata must never be fetchable over HTTP.
func TestManifestIsNotServable(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	setPolicy(cfg, "cryoem", "*")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	entry, _ := lib.Get("cryoem")

	for _, escape := range []string{"app.yaml", "../app.yaml", "/app.yaml"} {
		if _, err := fs.ReadFile(entry.FS(), escape); err == nil {
			t.Errorf("%q is readable through the served filesystem", escape)
		}
	}
}

func TestBundleWithoutIndexIsRefused(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", defaultManifest, map[string]string{"web/other.html": "x"})
	setPolicy(cfg, "cryoem", "*")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 0 || len(problems) == 0 {
		t.Fatalf("a bundle with no entry point was published (%d, %v)", published, problems)
	}
}

// A truncated scp produces a zip that opens cleanly and serves a
// subset of the app. Per-entry CRC32 does not catch it. The digest is
// the only thing that does.
func TestDigestMismatchRefuses(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	path := writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	setPolicy(cfg, "cryoem", "*")
	writeDigest(t, path)

	// Rewrite the bundle so the recorded digest no longer matches.
	writeBundle(t, dir, "cryoem", "name: Tampered\n", defaultFiles())

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 0 {
		t.Fatal("a bundle that did not match its digest was published")
	}
	if len(problems) == 0 || !strings.Contains(problems[0].Error(), "digest") {
		t.Fatalf("problems do not explain the digest mismatch: %v", problems)
	}
}

func TestDigestMatchPublishes(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	path := writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	setPolicy(cfg, "cryoem", "*")
	writeDigest(t, path)

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 1 || len(problems) != 0 {
		t.Fatalf("published=%d problems=%v", published, problems)
	}
	entry, _ := lib.Get("cryoem")
	if entry.App.Digest == "" {
		t.Error("a verified bundle reports no digest")
	}
}

// Dropping a new zip in place must take effect without a restart, and
// the OLD bundle's file handle must be released.
func TestReloadPicksUpAReplacedBundle(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", "name: First\n", defaultFiles())
	setPolicy(cfg, "cryoem", "*")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	first, _ := lib.Get("cryoem")

	// Make the mtime unambiguously different; a same-second rewrite on
	// a coarse filesystem would otherwise look unchanged.
	time.Sleep(10 * time.Millisecond)
	path := writeBundle(t, dir, "cryoem", "name: Second\n", defaultFiles())
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems after replace: %v", problems)
	}
	second, _ := lib.Get("cryoem")
	if second.App.Name != "Second" {
		t.Errorf("Name = %q, want Second: the replacement was not picked up", second.App.Name)
	}
	// The retired bundle stays OPEN for its grace period: a request
	// already reading from it must be allowed to finish. Closing it
	// here is what used to give a visitor "file already closed" on an
	// asset when somebody redeployed mid-page-load.
	if _, err := fs.ReadFile(first.FS(), "index.html"); err != nil {
		t.Errorf("the retired bundle was closed out from under a live reader: %v", err)
	}
}

// A reader that was already going when a redeploy landed must finish
// intact, not get a truncated body or "file already closed".
func TestInFlightReadSurvivesARedeploy(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	body := strings.Repeat("x", 200_000)
	writeBundle(t, dir, "cryoem", defaultManifest, map[string]string{
		"web/index.html":    "<html></html>",
		"web/assets/big.js": body,
	})
	setPolicy(cfg, "cryoem", "*")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	entry, _ := lib.Get("cryoem")

	f, err := entry.FS().Open("assets/big.js")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	one := make([]byte, 1)
	if _, err := f.Read(one); err != nil {
		t.Fatalf("first read: %v", err)
	}

	// Redeploy underneath it.
	time.Sleep(10 * time.Millisecond)
	path := writeBundle(t, dir, "cryoem", "name: Second\n", map[string]string{
		"web/index.html": "<html>2</html>",
	})
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("reload problems: %v", problems)
	}

	rest, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("the in-flight read failed after a redeploy: %v", err)
	}
	if len(rest) != len(body)-1 {
		t.Fatalf("the in-flight read was truncated: %d bytes, want %d", len(rest), len(body)-1)
	}
}

// The grace period must actually end, or a server that redeploys often
// accumulates descriptors on unlinked files until it runs out.
func TestRetiredBundlesAreClosedAfterTheGracePeriod(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	setPolicy(cfg, "cryoem", "*")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })
	lib.retireGrace = time.Nanosecond // expire immediately
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	first, _ := lib.Get("cryoem")

	// Redeploy twice: the first retires `first`, the second sweeps it.
	for i, name := range []string{"Second", "Third"} {
		time.Sleep(10 * time.Millisecond)
		path := writeBundle(t, dir, "cryoem", "name: "+name+"\n", defaultFiles())
		future := time.Now().Add(time.Duration(i+1) * time.Second)
		if err := os.Chtimes(path, future, future); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
		if _, problems := lib.Reload(); len(problems) != 0 {
			t.Fatalf("reload problems: %v", problems)
		}
	}

	if _, err := fs.ReadFile(first.FS(), "index.html"); err == nil {
		t.Error("a bundle past its grace period is still open; descriptors would accumulate")
	}
	if len(lib.retired) != 1 {
		t.Errorf("retired list holds %d bundles, want just the most recent", len(lib.retired))
	}
}

// An unchanged bundle must keep the SAME open handle across rescans.
// Reopening every bundle every interval would re-hash and re-parse all
// of them for nothing.
func TestReloadReusesUnchangedBundles(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	setPolicy(cfg, "cryoem", "*")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	before, _ := lib.Get("cryoem")

	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems on rescan: %v", problems)
	}
	after, _ := lib.Get("cryoem")

	if before.bundle != after.bundle {
		t.Error("an unchanged bundle was reopened")
	}
	// And it must still work, i.e. the reuse did not close it.
	if got := readFS(t, after.FS(), "index.html"); got == "" {
		t.Error("the reused bundle serves nothing")
	}
}

// A policy change alone must take effect, even though the bundle's
// bytes have not moved.
func TestReloadPicksUpAPolicyChange(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	setPolicy(cfg, "cryoem", "smith_lab")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if got := lib.VisibleTo([]string{"jones_lab"}); len(got) != 0 {
		t.Fatal("jones_lab can already see an app scoped to smith_lab")
	}

	setPolicy(cfg, "cryoem", "smith_lab, jones_lab")
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if got := lib.VisibleTo([]string{"jones_lab"}); len(got) != 1 {
		t.Errorf("the policy change did not take effect: %d apps visible", len(got))
	}
}

func TestVisibleToAndHomes(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "cryoem", "name: CryoEM\n", defaultFiles())
	setPolicy(cfg, "cryoem", "smith_lab", "HOME", "true")
	writeBundle(t, dir, "seqqc", "name: SeqQC\n", defaultFiles())
	setPolicy(cfg, "seqqc", "jones_lab", "HOME", "true")
	writeBundle(t, dir, "shared", "name: Shared\n", defaultFiles())
	setPolicy(cfg, "shared", "*")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })
	published, problems := lib.Reload()
	if published != 3 || len(problems) != 0 {
		t.Fatalf("published=%d problems=%v", published, problems)
	}

	// A member of one lab sees their app and the shared one, never the
	// other lab's.
	got := lib.VisibleTo([]string{"smith_lab"})
	if len(got) != 2 {
		t.Fatalf("smith_lab sees %d apps, want 2", len(got))
	}
	for _, e := range got {
		if e.App.ID == "seqqc" {
			t.Error("smith_lab can see jones_lab's app")
		}
	}
	// Listing order is stable so a switcher does not reshuffle itself.
	if got[0].App.ID != "cryoem" || got[1].App.ID != "shared" {
		t.Errorf("order = %s,%s; want cryoem,shared", got[0].App.ID, got[1].App.ID)
	}

	if homes := lib.Homes([]string{"smith_lab"}); len(homes) != 1 || homes[0].App.ID != "cryoem" {
		t.Errorf("Homes(smith_lab) = %v, want just cryoem", homes)
	}
	// Somebody in both labs has two homes. That is a supported state,
	// and the switcher is what resolves it.
	if homes := lib.Homes([]string{"smith_lab", "jones_lab"}); len(homes) != 2 {
		t.Errorf("a member of both labs has %d homes, want 2", len(homes))
	}
	if homes := lib.Homes([]string{"nobody"}); len(homes) != 0 {
		t.Errorf("a member of neither lab has %d homes, want 0", len(homes))
	}
}

// One broken bundle must not stop the others loading: an operator
// deploying app B should not take app A down with a typo.
func TestOneBadBundleDoesNotStopTheRest(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "good", defaultManifest, defaultFiles())
	setPolicy(cfg, "good", "*")
	writeBundle(t, dir, "bad", "this: is not a manifest\n", defaultFiles())
	setPolicy(cfg, "bad", "*")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 1 {
		t.Errorf("published %d, want just the good one", published)
	}
	if len(problems) != 1 {
		t.Errorf("problems = %v, want one naming the bad bundle", problems)
	}
	if _, ok := lib.Get("good"); !ok {
		t.Error("the good app was not published")
	}
}

// Reserved ids must not be loadable, or a bundle could shadow the
// shell script every app depends on.
func TestReservedIDRefused(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestParams()
	writeBundle(t, dir, "_shell", defaultManifest, defaultFiles())
	setPolicy(cfg, "_shell", "*")

	lib := NewLibrary(dir, NewConfigPolicy(cfg))
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 0 || len(problems) == 0 {
		t.Fatalf("a reserved id was published (%d, %v)", published, problems)
	}
}

// A missing directory is an operator misconfiguration, reported once,
// not a crash.
func TestMissingDirectoryReportsAProblem(t *testing.T) {
	lib := NewLibrary(filepath.Join(t.TempDir(), "nope"), NewConfigPolicy(newTestParams()))
	t.Cleanup(func() { _ = lib.Close() })
	published, problems := lib.Reload()
	if published != 0 || len(problems) != 1 {
		t.Fatalf("published=%d problems=%v", published, problems)
	}
}

// An unset directory disables the feature; it is not an error.
func TestEmptyDirectoryConfigIsNotAnError(t *testing.T) {
	lib := NewLibrary("", NewConfigPolicy(newTestParams()))
	t.Cleanup(func() { _ = lib.Close() })
	if published, problems := lib.Reload(); published != 0 || len(problems) != 0 {
		t.Fatalf("published=%d problems=%v", published, problems)
	}
}
