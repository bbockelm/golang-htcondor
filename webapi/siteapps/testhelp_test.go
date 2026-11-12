package siteapps

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeBundle builds a zip bundle in dir and returns its path.
//
// files are published paths inside the bundle, so a caller writes
// "web/index.html" to place the entry point. The manifest goes in as
// app.yaml at the root.
func writeBundle(t *testing.T, dir, id, manifest string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	write := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if manifest != "" {
		write("app.yaml", manifest)
	}
	for name, body := range files {
		write(name, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	// G703: dir is t.TempDir() and id is a literal from the test.
	path := filepath.Join(dir, id+".zip") //nolint:gosec
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

// defaultManifest is a valid bundle manifest.
const defaultManifest = "name: Example Pipeline\ndescription: An example\nicon: beaker\n"

// defaultFiles is a minimal valid app.
func defaultFiles() map[string]string {
	return map[string]string{
		"web/index.html":    "<!doctype html><html><head></head><body>hi</body></html>",
		"web/assets/app.js": "console.log('hi')",
	}
}

// writePolicy writes the operator's <id>.yaml beside the bundle.
// writeDigest writes the .sha256 sidecar for a bundle, in shasum's
// output format.
func writeDigest(t *testing.T, bundlePath string) {
	t.Helper()
	data, err := os.ReadFile(bundlePath) //nolint:gosec // test-controlled
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	sum := sha256.Sum256(data)
	line := hex.EncodeToString(sum[:]) + "  " + filepath.Base(bundlePath) + "\n"
	// G703: bundlePath came from writeBundle, which built it under
	// t.TempDir() from a literal id.
	if err := os.WriteFile(bundlePath+".sha256", []byte(line), 0o600); err != nil { //nolint:gosec
		t.Fatalf("write digest: %v", err)
	}
}

// readFS reads a file out of a bundle's served filesystem.
func readFS(t *testing.T, fsys fs.FS, name string) string {
	t.Helper()
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// testParams is a configuration stated as a map, standing in for the
// HTCondor configuration a real deployment reads policy from.
type testParams struct{ m map[string]string }

func newTestParams() *testParams { return &testParams{m: map[string]string{}} }

func (p *testParams) Get(key string) (string, bool) {
	v, ok := p.m[strings.ToUpper(key)]
	return v, ok
}

func (p *testParams) GetBool(key string, def bool) bool {
	v, ok := p.Get(key)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "t", "1", "yes":
		return true
	case "false", "f", "0", "no":
		return false
	}
	return def
}

func (p *testParams) Keys() []string {
	out := make([]string, 0, len(p.m))
	for k := range p.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// setPolicy publishes an app to groups, the way an operator's
// configuration does. Extra settings are given as NAME, value pairs:
//
//	setPolicy(cfg, "cryoem", "smith_lab", "HOME", "true")
func setPolicy(p *testParams, id, groups string, kv ...string) {
	p.m[strings.ToUpper(ConfigKey(id, "GROUPS"))] = groups
	for i := 0; i+1 < len(kv); i += 2 {
		p.m[strings.ToUpper(ConfigKey(id, kv[i]))] = kv[i+1]
	}
}
