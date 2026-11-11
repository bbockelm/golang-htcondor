package siteapps

import (
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
func TestNoPolicyFileIsNotPublished(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	// deliberately no policy file

	lib := NewLibrary(dir)
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 0 {
		t.Fatalf("published %d apps without a policy file", published)
	}
	if len(problems) != 1 {
		t.Fatalf("problems = %d, want exactly one explaining the missing policy file", len(problems))
	}
	if msg := problems[0].Error(); !strings.Contains(msg, "cryoem.yaml") {
		t.Errorf("problem does not name the file to write: %v", msg)
	}
	if _, ok := lib.Get("cryoem"); ok {
		t.Error("the app is reachable despite not being published")
	}
}

// enabled: false is a deliberate choice, so it is silent -- unlike a
// missing policy file, which is a mistake.
func TestDisabledIsSilent(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [lab]\nenabled: false\n")

	lib := NewLibrary(dir)
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
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [smith_lab]\nhome: true\n")

	lib := NewLibrary(dir)
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
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	lib := NewLibrary(dir)
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
	writeBundle(t, dir, "cryoem", defaultManifest, map[string]string{"web/other.html": "x"})
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	lib := NewLibrary(dir)
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
	path := writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")
	writeDigest(t, path)

	// Rewrite the bundle so the recorded digest no longer matches.
	writeBundle(t, dir, "cryoem", "name: Tampered\n", defaultFiles())

	lib := NewLibrary(dir)
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
	path := writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")
	writeDigest(t, path)

	lib := NewLibrary(dir)
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
	writeBundle(t, dir, "cryoem", "name: First\n", defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	lib := NewLibrary(dir)
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
	// The retired bundle must be closed, or every redeploy leaks a file
	// descriptor until the daemon runs out.
	if err := first.bundle.Close(); err == nil {
		t.Error("the retired bundle was still open; Reload leaked its handle")
	}
}

// An unchanged bundle must keep the SAME open handle across rescans.
// Reopening every bundle every interval would re-hash and re-parse all
// of them for nothing.
func TestReloadReusesUnchangedBundles(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	lib := NewLibrary(dir)
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
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [smith_lab]\n")

	lib := NewLibrary(dir)
	t.Cleanup(func() { _ = lib.Close() })
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if got := lib.VisibleTo([]string{"jones_lab"}); len(got) != 0 {
		t.Fatal("jones_lab can already see an app scoped to smith_lab")
	}

	writePolicy(t, dir, "cryoem", "groups: [smith_lab, jones_lab]\n")
	if _, problems := lib.Reload(); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if got := lib.VisibleTo([]string{"jones_lab"}); len(got) != 1 {
		t.Errorf("the policy change did not take effect: %d apps visible", len(got))
	}
}

func TestVisibleToAndHomes(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "cryoem", "name: CryoEM\n", defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [smith_lab]\nhome: true\n")
	writeBundle(t, dir, "seqqc", "name: SeqQC\n", defaultFiles())
	writePolicy(t, dir, "seqqc", "groups: [jones_lab]\nhome: true\n")
	writeBundle(t, dir, "shared", "name: Shared\n", defaultFiles())
	writePolicy(t, dir, "shared", "groups: [\"*\"]\n")

	lib := NewLibrary(dir)
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
	writeBundle(t, dir, "good", defaultManifest, defaultFiles())
	writePolicy(t, dir, "good", "groups: [\"*\"]\n")
	writeBundle(t, dir, "bad", "this: is not a manifest\n", defaultFiles())
	writePolicy(t, dir, "bad", "groups: [\"*\"]\n")

	lib := NewLibrary(dir)
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
	writeBundle(t, dir, "_shell", defaultManifest, defaultFiles())
	writePolicy(t, dir, "_shell", "groups: [\"*\"]\n")

	lib := NewLibrary(dir)
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 0 || len(problems) == 0 {
		t.Fatalf("a reserved id was published (%d, %v)", published, problems)
	}
}

// A missing directory is an operator misconfiguration, reported once,
// not a crash.
func TestMissingDirectoryReportsAProblem(t *testing.T) {
	lib := NewLibrary(filepath.Join(t.TempDir(), "nope"))
	t.Cleanup(func() { _ = lib.Close() })
	published, problems := lib.Reload()
	if published != 0 || len(problems) != 1 {
		t.Fatalf("published=%d problems=%v", published, problems)
	}
}

// An unset directory disables the feature; it is not an error.
func TestEmptyDirectoryConfigIsNotAnError(t *testing.T) {
	lib := NewLibrary("")
	t.Cleanup(func() { _ = lib.Close() })
	if published, problems := lib.Reload(); published != 0 || len(problems) != 0 {
		t.Fatalf("published=%d problems=%v", published, problems)
	}
}
