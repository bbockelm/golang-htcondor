package siteapps

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countOpenDirEntries reports what is actually sitting in the bundle
// directory, so a test can assert that nothing was left behind.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// loadOneApp publishes the single bundle in dir and returns it.
func loadOneApp(t *testing.T, dir string) *Entry {
	t.Helper()
	const id = "cryoem"
	lib := NewLibrary(dir)
	t.Cleanup(func() { _ = lib.Close() })
	published, problems := lib.Reload()
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if published != 1 {
		t.Fatalf("published %d, want 1", published)
	}
	entry, ok := lib.Get(id)
	if !ok {
		t.Fatalf("app %q not found", id)
	}
	return entry
}

// Every served file must be seekable, because net/http refuses a Range
// request on a file that is not -- and a deflated zip entry is not.
// This is the property the whole normalization step exists for.
func TestServedFilesAreSeekable(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat("abcdefghij", 500) // compressible, so it WILL be deflated
	writeBundle(t, dir, "cryoem", defaultManifest, map[string]string{
		"web/index.html":    "<html></html>",
		"web/assets/big.js": body,
	})
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	entry := loadOneApp(t, dir)

	f, err := entry.FS().Open("assets/big.js")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	seeker, ok := f.(io.Seeker)
	if !ok {
		t.Fatal("the opened file is not an io.Seeker; Range requests will be refused")
	}

	// Seek into the middle and read: this is exactly what serving a
	// Range header does.
	const offset = 2500
	if _, err := seeker.Seek(offset, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	got := make([]byte, 10)
	if _, err := io.ReadFull(f, got); err != nil {
		t.Fatalf("read after seek: %v", err)
	}
	if want := body[offset : offset+10]; string(got) != want {
		t.Errorf("read %q at offset %d, want %q", got, offset, want)
	}

	// And a full read still returns the whole, correct content.
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind: %v", err)
	}
	all, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if string(all) != body {
		t.Errorf("full read returned %d bytes, want %d", len(all), len(body))
	}
}

// The scratch copy must never appear in the bundle directory once
// loading is done: it is unlinked at creation, so there is nothing to
// clean up and nothing for a rescan to trip over.
func TestScratchFileIsNotLeftBehind(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "cryoem", defaultManifest, map[string]string{
		"web/index.html": strings.Repeat("compress me ", 1000),
	})
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	entry := loadOneApp(t, dir)

	for _, name := range dirNames(t, dir) {
		if strings.HasPrefix(name, tempPrefix) || strings.HasSuffix(name, tempSuffix) {
			t.Errorf("a scratch file was left in the bundle directory: %s", name)
		}
	}

	// And the content is still served, which is the point of holding
	// the descriptor open across the unlink.
	if got := readFS(t, entry.FS(), "index.html"); !strings.Contains(got, "compress me") {
		t.Errorf("the unlinked scratch file is not serving: %q", truncate(got, 40))
	}
}

// A bundle that is already stored must be served straight from the
// original file, with no copy written at all.
func TestStoredBundleIsNotRewritten(t *testing.T) {
	dir := t.TempDir()

	// Build a bundle with every entry STORED, the way `zip -0` does.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"app.yaml":       defaultManifest,
		"web/index.html": "<html>stored</html>",
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cryoem.zip"), buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	entry := loadOneApp(t, dir)
	if got := readFS(t, entry.FS(), "index.html"); !strings.Contains(got, "stored") {
		t.Errorf("index.html = %q", got)
	}
}

// Directory entries have to exist for the SPA handler's dynamic-route
// resolution, which walks them to tell a literal segment from a
// [param] placeholder. A zip need not carry them, so they are
// synthesized.
func TestParentDirectoriesAreSynthesized(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "cryoem", defaultManifest, map[string]string{
		"web/index.html":         "<html></html>",
		"web/jobs/_/detail.html": "<html>detail</html>",
	})
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	entry := loadOneApp(t, dir)
	for _, d := range []string{".", "jobs", "jobs/_"} {
		f, err := entry.FS().Open(d)
		if err != nil {
			t.Fatalf("open directory %q: %v", d, err)
		}
		info, err := f.Stat()
		_ = f.Close()
		if err != nil {
			t.Fatalf("stat %q: %v", d, err)
		}
		if !info.IsDir() {
			t.Errorf("%q is not reported as a directory", d)
		}
	}
}

// Path escapes must be refused by the filesystem itself, not only by
// the handler above it.
func TestStoredFSRejectsInvalidPaths(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "cryoem", defaultManifest, defaultFiles())
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	entry := loadOneApp(t, dir)
	for _, bad := range []string{"../app.yaml", "/index.html", "./index.html", ""} {
		if _, err := entry.FS().Open(bad); err == nil {
			t.Errorf("Open(%q) succeeded", bad)
		}
	}
	// app.yaml is outside web/, so it is absent from the map entirely
	// rather than merely filtered.
	if _, err := fs.ReadFile(entry.FS(), "app.yaml"); err == nil {
		t.Error("app.yaml is readable through the served filesystem")
	}
}

// A hidden or scratch-looking file in the bundle directory must never
// be loaded as a bundle.
func TestHiddenAndScratchNamesAreNotLoaded(t *testing.T) {
	dir := t.TempDir()
	// A real app, so the library has something to publish.
	writeBundle(t, dir, "good", defaultManifest, defaultFiles())
	writePolicy(t, dir, "good", "groups: [\"*\"]\n")

	// Things that must be ignored outright, with policy files that
	// would publish them if they ever were loaded.
	writeBundle(t, dir, ".hidden", defaultManifest, defaultFiles())
	writePolicy(t, dir, ".hidden", "groups: [\"*\"]\n")
	writeBundle(t, dir, tempPrefix+"deadbeef"+tempSuffix, defaultManifest, defaultFiles())

	lib := NewLibrary(dir)
	t.Cleanup(func() { _ = lib.Close() })

	published, problems := lib.Reload()
	if published != 1 {
		t.Errorf("published %d, want only the good bundle", published)
	}
	// Ignored means ignored: a skipped name must not even generate a
	// problem, or the log fills with complaints about editor backups.
	if len(problems) != 0 {
		t.Errorf("hidden/scratch names produced problems: %v", problems)
	}
	if _, ok := lib.Get(".hidden"); ok {
		t.Error("a dotfile bundle was published")
	}
}

func TestValidateIDBoundaryCharacters(t *testing.T) {
	for _, bad := range []string{"-lead", "trail-", "_lead", "trail_", ".hidden", "-"} {
		if err := ValidateID(bad); err == nil {
			t.Errorf("ValidateID(%q) accepted it", bad)
		}
	}
	for _, ok := range []string{"a", "a-b", "a_b", "a1", "1a", "cryo-em-2"} {
		if err := ValidateID(ok); err != nil {
			t.Errorf("ValidateID(%q) rejected it: %v", ok, err)
		}
	}
}

// writeDirBundle builds an UNPACKED bundle and returns its path.
func writeDirBundle(t *testing.T, dir, id string, files map[string]string) string {
	t.Helper()
	root := filepath.Join(dir, id)
	for name, body := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

// A directory bundle must not follow a symlink out of itself.
//
// os.DirFS, which this used at first, rejects a lexically escaping path
// but happily follows a symlink that points outside the tree -- so a
// bundle containing web/escape.txt -> /etc/shadow served it to everyone
// in the app's groups. A bundle directory is site content, and site
// content includes whatever was lying in the directory an operator
// pointed at.
func TestDirBundleDoesNotFollowSymlinksOut(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	root := writeDirBundle(t, dir, "cryoem", map[string]string{
		"app.yaml":       defaultManifest,
		"web/index.html": "<html></html>",
	})
	if err := os.Symlink(secret, filepath.Join(root, "web", "escape.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	entry := loadOneApp(t, dir)

	data, err := fs.ReadFile(entry.FS(), "escape.txt")
	if err == nil {
		t.Fatalf("a symlink out of the bundle was followed; read %q", data)
	}
	// The app itself must still work: this refuses an escape, not
	// directory bundles.
	if got := readFS(t, entry.FS(), "index.html"); got == "" {
		t.Error("the bundle serves nothing after the fix")
	}
}

// A symlink that stays inside the bundle is ordinary content and must
// keep working, or unpacking a build output with internal links breaks.
func TestDirBundleAllowsInternalSymlinks(t *testing.T) {
	dir := t.TempDir()
	root := writeDirBundle(t, dir, "cryoem", map[string]string{
		"app.yaml":           defaultManifest,
		"web/index.html":     "<html></html>",
		"web/assets/real.js": "console.log(1)",
	})
	if err := os.Symlink("real.js", filepath.Join(root, "web", "assets", "link.js")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	writePolicy(t, dir, "cryoem", "groups: [\"*\"]\n")

	entry := loadOneApp(t, dir)
	if got, err := fs.ReadFile(entry.FS(), "assets/link.js"); err != nil {
		t.Errorf("an internal symlink was refused: %v", err)
	} else if string(got) != "console.log(1)" {
		t.Errorf("link.js = %q", got)
	}
}

// truncate shortens a string for an error message.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
