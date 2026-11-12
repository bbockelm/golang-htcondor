package siteapps

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Safety bounds on a bundle. A bundle is site-supplied data opened by a
// privileged daemon, so these are refused at load time rather than
// discovered while serving a request.
const (
	// maxBundleEntries bounds the file count. A static site export with
	// more than this has a build problem, not a content problem.
	maxBundleEntries = 20000
	// maxBundleBytes bounds the TOTAL uncompressed size, which is what
	// makes a zip bomb a bomb: the compressed file can be trivial.
	maxBundleBytes = 512 << 20 // 512 MiB
	// maxEntryBytes bounds one file. Large enough for a video a site
	// chose to ship, small enough that one entry cannot be the whole
	// budget by accident.
	maxEntryBytes = 128 << 20 // 128 MiB
	// maxManifestBytes bounds app.yaml. It is a
	// handful of keys.
	maxManifestBytes = 64 << 10
)

// webRoot is the directory inside a bundle that holds the app.
//
// The nesting is load-bearing rather than tidy: the handler serves
// fs.Sub(bundle, webRoot), so app.yaml is structurally unreachable
// over HTTP. The alternative -- app at the root, app.yaml excluded by
// a rule -- is a rule somebody has to remember to apply to the next
// root-level file we add.
const webRoot = "web"

// manifestName is the bundle's own manifest, at the bundle root.
const manifestName = "app.yaml"

// Bundle is an opened site app: its filesystem and the metadata
// needed to notice when it changes.
type Bundle struct {
	// FS serves the app's content, already rooted at webRoot.
	FS fs.FS
	// Manifest is app.yaml from inside the bundle.
	Manifest BundleManifest
	// Digest is the verified SHA-256 of the zip, or "" for a directory
	// bundle or an unverified zip. Non-empty means a .sha256 sidecar
	// was present and matched, which is a stronger statement than
	// ContentDigest makes and is why the two are separate.
	Digest string
	// ContentDigest is the SHA-256 of the zip as found, attested or
	// not. Empty for a directory bundle, which is a tree rather than a
	// set of bytes.
	ContentDigest string
	// SizeBytes is the bundle file's size; 0 for a directory bundle.
	SizeBytes int64

	// closer releases the underlying zip file. nil for a directory.
	closer io.Closer
	// stamp is what a rescan compares to decide whether to reload.
	stamp fileStamp
}

// Close releases the bundle's file handle.
func (b *Bundle) Close() error {
	if b == nil || b.closer == nil {
		return nil
	}
	return b.closer.Close()
}

// fileStamp is the cheap change check: size plus modification time.
//
// Not the digest, which would mean hashing every bundle on every
// rescan. A bundle whose stamp is unchanged is assumed unchanged; one
// whose stamp moved is re-verified in full.
//
// A replaced bundle is not closed at once -- see Library.retire. A
// request already reading it has to be allowed to finish, and the
// cost of waiting is one descriptor on a file that is already
// unlinked.
type fileStamp struct {
	size    int64
	modTime int64
}

func stampOf(info os.FileInfo) fileStamp {
	return fileStamp{size: info.Size(), modTime: info.ModTime().UnixNano()}
}

// OpenBundle opens a bundle at path, which may be a .zip or a
// directory.
//
// expectedDigest, when non-empty, is the contents of the .sha256
// sidecar: the bundle is refused if it does not match. An interrupted
// scp produces a zip truncated at a valid entry boundary, which opens
// cleanly and serves a subset of the app; per-entry CRC32 does not
// catch that because the entries that survived are intact.
func OpenBundle(path string, expectedDigest string) (*Bundle, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat bundle: %w", err)
	}
	if info.IsDir() {
		return openDirBundle(path, info)
	}
	return openZipBundle(path, info, expectedDigest)
}

// openDirBundle opens an unpacked bundle.
//
// os.OpenRoot, not os.DirFS. os.DirFS rejects a path that escapes
// lexically but still follows a symlink that points out of the tree, so
// a bundle containing web/data/ref.fa -> /etc/shadow would serve it to
// anyone in the app's groups. os.Root refuses to traverse out of the
// root at all, which is the property this needs: a bundle is site
// content, and "site content" includes whatever was in the directory
// an operator pointed at.
//
// Zip bundles have never had this problem and cannot acquire it: they
// are served from a name-to-offset map over one unlinked descriptor,
// with no filesystem underneath to traverse.
func openDirBundle(path string, info os.FileInfo) (*Bundle, error) {
	rootDir, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open bundle directory: %w", err)
	}
	root := rootDir.FS()

	manifest, err := readManifestFS(root)
	if err != nil {
		_ = rootDir.Close()
		return nil, err
	}
	web, err := fs.Sub(root, webRoot)
	if err != nil {
		_ = rootDir.Close()
		return nil, fmt.Errorf("bundle has no %s/ directory: %w", webRoot, err)
	}
	if _, err := fs.Stat(web, "index.html"); err != nil {
		_ = rootDir.Close()
		return nil, fmt.Errorf("bundle has no %s/index.html", webRoot)
	}
	return &Bundle{FS: web, Manifest: manifest, closer: rootDir, stamp: stampOf(info)}, nil
}

func openZipBundle(path string, info os.FileInfo, expectedDigest string) (*Bundle, error) {
	// Hashed whether or not there is a .sha256 to check it against:
	// the digest is the artifact's identity, and the audit trail needs
	// one for every bundle, not only for the attested ones. This runs
	// when a bundle is opened, which a rescan skips for a file that
	// has not moved, so it is not an every-interval cost.
	actual, err := digestFile(path)
	if err != nil {
		return nil, err
	}
	if expectedDigest != "" {
		if !strings.EqualFold(actual, expectedDigest) {
			return nil, fmt.Errorf("bundle digest mismatch: the file on disk hashes to %s "+
				"but its .sha256 says %s; it is not the bundle that was built", actual, expectedDigest)
		}
		expectedDigest = actual
	}

	f, err := os.Open(path) //nolint:gosec // operator-configured bundle directory
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("read bundle as zip: %w", err)
	}
	if err := checkZipBounds(zr); err != nil {
		_ = f.Close()
		return nil, err
	}

	// Read the manifest off the original archive, before normalization:
	// it lives outside web/ and so is not carried into the served
	// filesystem at all.
	manifest, err := readManifestFS(zr)
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	// Decompress into an unlinked scratch file, unless the bundle is
	// already stored. After this, backing is the file every entry is a
	// seekable section of -- which may still be f, or may be the
	// scratch copy, in which case f has been closed.
	backing, storedReader, err := normalizeToStored(f, zr, path)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	entries, err := collectEntries(storedReader)
	if err != nil {
		_ = backing.Close()
		return nil, err
	}

	web := newStoredFS(backing, entries, webRoot)
	// Fail here rather than on the first request: a bundle with no
	// entry point is broken, and the operator who just deployed it is
	// the person who can fix it.
	if _, err := fs.Stat(web, "index.html"); err != nil {
		_ = backing.Close()
		return nil, fmt.Errorf("bundle has no %s/index.html", webRoot)
	}

	return &Bundle{
		FS:            web,
		Manifest:      manifest,
		Digest:        expectedDigest,
		ContentDigest: actual,
		SizeBytes:     info.Size(),
		closer:        backing,
		stamp:         stampOf(info),
	}, nil
}

// checkZipBounds refuses a bundle that is too large or too strange
// before anything reads from it.
func checkZipBounds(zr *zip.Reader) error {
	if len(zr.File) > maxBundleEntries {
		return fmt.Errorf("bundle holds %d entries, more than the %d allowed",
			len(zr.File), maxBundleEntries)
	}
	var total uint64
	for _, entry := range zr.File {
		// zip.Reader.Open enforces fs.ValidPath, but only when something
		// opens that entry. Rejecting the whole bundle here means a
		// bundle with an unreachable entry never gets published at all,
		// rather than publishing and failing strangely on one path.
		if !fs.ValidPath(strings.TrimSuffix(entry.Name, "/")) {
			return fmt.Errorf("bundle holds an entry named %q, which is not a valid path", entry.Name)
		}
		if entry.UncompressedSize64 > maxEntryBytes {
			return fmt.Errorf("bundle entry %q is %d bytes, larger than the %d allowed",
				entry.Name, entry.UncompressedSize64, maxEntryBytes)
		}
		total += entry.UncompressedSize64
		if total > maxBundleBytes {
			return fmt.Errorf("bundle uncompresses to more than the %d bytes allowed", maxBundleBytes)
		}
	}
	return nil
}

func readManifestFS(fsys fs.FS) (BundleManifest, error) {
	f, err := fsys.Open(manifestName)
	if err != nil {
		return BundleManifest{}, fmt.Errorf("bundle has no %s: %w", manifestName, err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return BundleManifest{}, fmt.Errorf("read %s: %w", manifestName, err)
	}
	if len(data) > maxManifestBytes {
		return BundleManifest{}, fmt.Errorf("%s is larger than %d bytes", manifestName, maxManifestBytes)
	}
	return ParseBundleManifest(data)
}

// digestFile hashes a file with SHA-256.
func digestFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // operator-configured bundle directory
	if err != nil {
		return "", fmt.Errorf("open bundle for hashing: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash bundle: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// parseDigestSidecar extracts the hash from a .sha256 file.
//
// Accepts both the bare hash and the `shasum`/`sha256sum` output
// format ("<hash>  <name>"), because the sidecar is produced by
// whichever of those the app's build host had.
func parseDigestSidecar(data []byte) (string, error) {
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", fmt.Errorf("digest file is empty")
	}
	digest := strings.ToLower(fields[0])
	if len(digest) != sha256.Size*2 {
		return "", fmt.Errorf("digest %q is not a SHA-256 hash", fields[0])
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", fmt.Errorf("digest %q is not hexadecimal", fields[0])
	}
	return digest, nil
}

// bundleID derives an app id from a bundle's file name.
func bundleID(name string) string {
	return strings.TrimSuffix(name, filepath.Ext(name))
}
