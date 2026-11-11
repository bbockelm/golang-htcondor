package siteapps

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry is one published app: its metadata and its opened content.
type Entry struct {
	App    App
	bundle *Bundle
}

// FS is the app's content, rooted so that index.html is at the top.
// app.yaml is not reachable through it.
func (e *Entry) FS() fs.FS { return e.bundle.FS }

// Library is the set of apps loaded from a directory.
//
// Reads are lock-free against a snapshot pointer, the way groupSet in
// the httpserver package handles its lists: every request consults
// this, and a rescan replaces it from another goroutine. A reader sees
// either the old set or the new one, never a half-built one.
type Library struct {
	dir string

	mu   sync.Mutex // serializes rescans, not reads
	snap atomicSnapshot

	// retired holds bundles a reload replaced, kept open for a grace
	// period before their descriptors are closed.
	//
	// Closing one the moment it leaves the published set breaks any
	// request already reading from it: a redeploy mid-page-load gives
	// that visitor "file already closed" on an asset. The requests in
	// question last milliseconds and the cost of waiting is one file
	// descriptor on a file that is already unlinked, so the grace
	// period is the cheap side of that trade.
	//
	// Swept on the next reload rather than by a timer per bundle: a
	// reload is already happening on an interval, and a goroutine per
	// retired bundle would be a lot of machinery for a deadline nobody
	// needs to hit precisely.
	retired []retiredBundle
	// retireGrace is how long a replaced bundle stays open. Settable
	// for tests; see defaultRetireGrace.
	retireGrace time.Duration
}

// retiredBundle is a bundle waiting to be closed.
type retiredBundle struct {
	bundle *Bundle
	at     time.Time
}

// defaultRetireGrace is how long a replaced bundle keeps serving the
// requests that were already reading it.
//
// Two minutes rather than seconds because the thing being waited on is
// a browser finishing a page load over whatever network it has, and the
// cost of being generous is one descriptor on an unlinked file.
const defaultRetireGrace = 2 * time.Minute

// snapshot is an immutable published set.
type snapshot struct {
	byID  map[string]*Entry
	order []string // ids, sorted, for stable listing
}

// NewLibrary creates a library over dir. It does not scan; call
// Reload.
func NewLibrary(dir string) *Library {
	l := &Library{dir: dir, retireGrace: defaultRetireGrace}
	l.snap.store(&snapshot{byID: map[string]*Entry{}})
	return l
}

// Dir is the directory this library scans.
func (l *Library) Dir() string { return l.dir }

// Get returns the app with this id, if it is published.
func (l *Library) Get(id string) (*Entry, bool) {
	e, ok := l.snap.load().byID[id]
	return e, ok
}

// VisibleTo returns the apps these groups may see, in a stable order.
//
// The returned slice is freshly built, so a caller may sort or filter
// it; the Entries it holds are shared and must not be mutated.
func (l *Library) VisibleTo(groups []string) []*Entry {
	snap := l.snap.load()
	out := make([]*Entry, 0, len(snap.order))
	for _, id := range snap.order {
		if e := snap.byID[id]; e.App.VisibleTo(groups) {
			out = append(out, e)
		}
	}
	return out
}

// Homes returns the visible apps marked as a home, in the same order.
func (l *Library) Homes(groups []string) []*Entry {
	var out []*Entry
	for _, e := range l.VisibleTo(groups) {
		if e.App.Home {
			out = append(out, e)
		}
	}
	return out
}

// Reload rescans the directory and republishes.
//
// It returns the problems it found alongside the count it published:
// one malformed bundle must not stop the others from loading, but it
// must not be silent either, because the operator who just deployed it
// has no other way to learn that it did not take.
func (l *Library) Reload() (published int, problems []error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if strings.TrimSpace(l.dir) == "" {
		return 0, nil
	}
	dirEntries, err := os.ReadDir(l.dir)
	if err != nil {
		return 0, []error{fmt.Errorf("read site apps directory %s: %w", l.dir, err)}
	}

	old := l.snap.load()
	next := &snapshot{byID: make(map[string]*Entry)}

	for _, de := range dirEntries {
		name := de.Name()
		// Skip anything hidden or scratch outright, before the id is
		// even derived. normalizeToStored writes a decompressed copy
		// into this very directory and unlinks it immediately; this
		// closes the window where a rescan could catch it, and it also
		// keeps editor backups and partial uploads from being offered
		// to the loader at all.
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, tempSuffix) {
			continue
		}
		// Only .zip files and directories are bundles. The policy and
		// digest files sit beside them and are read through their
		// bundle, not scanned as one.
		isZip := strings.EqualFold(filepath.Ext(name), ".zip")
		if !isZip && !de.IsDir() {
			continue
		}

		id := bundleID(name)
		if err := ValidateID(id); err != nil {
			problems = append(problems, err)
			continue
		}
		if _, dup := next.byID[id]; dup {
			// A directory and a zip with the same stem. Refuse both
			// rather than letting file-system order decide.
			problems = append(problems, fmt.Errorf(
				"site app %q is both a directory and a zip; remove one", id))
			delete(next.byID, id)
			continue
		}

		entry, err := l.loadOne(filepath.Join(l.dir, name), id, old)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		if entry == nil {
			continue // not published; loadOne explained why if it mattered
		}
		next.byID[id] = entry
	}

	next.order = make([]string, 0, len(next.byID))
	for id := range next.byID {
		next.order = append(next.order, id)
	}
	sort.Strings(next.order)

	l.snap.store(next)
	l.retire(old, next, time.Now())
	return len(next.byID), problems
}

// loadOne loads a single bundle, reusing the already-open one when
// nothing has changed.
//
// Returns (nil, nil) when the bundle exists but is deliberately not
// published: no policy file, or enabled: false.
func (l *Library) loadOne(path, id string, old *snapshot) (*Entry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("site app %q: %w", id, err)
	}

	sitePath := filepath.Join(l.dir, id+".yaml")
	siteData, err := os.ReadFile(sitePath) //nolint:gosec // operator-configured directory
	if err != nil {
		if os.IsNotExist(err) {
			// Fail closed, and say so. Who may see an app is the site's
			// decision; a bundle that arrived without one is not a
			// bundle anybody has decided to publish yet.
			return nil, fmt.Errorf("site app %q: %s is present but %s is missing; not published. "+
				"Write %s naming the groups that may see it", id, filepath.Base(path),
				filepath.Base(sitePath), filepath.Base(sitePath))
		}
		return nil, fmt.Errorf("site app %q: read %s: %w", id, filepath.Base(sitePath), err)
	}
	if len(siteData) > maxManifestBytes {
		return nil, fmt.Errorf("site app %q: %s is larger than %d bytes", id, filepath.Base(sitePath), maxManifestBytes)
	}
	site, err := ParseSiteManifest(siteData)
	if err != nil {
		return nil, fmt.Errorf("site app %q: %w", id, err)
	}
	if !site.IsEnabled() {
		return nil, nil
	}

	expected, err := l.expectedDigest(id)
	if err != nil {
		return nil, fmt.Errorf("site app %q: %w", id, err)
	}

	// Reuse the open bundle when the file has not moved. Reopening a
	// zip on every rescan would re-hash and re-parse every app every
	// interval, for nothing.
	stamp := stampOf(info)
	if prev, ok := old.byID[id]; ok && prev.bundle.stamp == stamp && prev.App.Digest == expected {
		app, err := Merge(id, prev.bundle.Manifest, site)
		if err != nil {
			return nil, err
		}
		app.Digest = prev.bundle.Digest
		return &Entry{App: app, bundle: prev.bundle}, nil
	}

	bundle, err := OpenBundle(path, expected)
	if err != nil {
		return nil, fmt.Errorf("site app %q: %w", id, err)
	}
	app, err := Merge(id, bundle.Manifest, site)
	if err != nil {
		_ = bundle.Close()
		return nil, err
	}
	app.Digest = bundle.Digest
	return &Entry{App: app, bundle: bundle}, nil
}

// expectedDigest reads <id>.zip.sha256, if present.
func (l *Library) expectedDigest(id string) (string, error) {
	data, err := os.ReadFile(filepath.Join(l.dir, id+".zip.sha256")) //nolint:gosec // operator-configured directory
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read digest file: %w", err)
	}
	return parseDigestSidecar(data)
}

// retire moves bundles the new snapshot no longer holds onto the
// retirement list, and closes anything whose grace period has expired.
//
// A bundle still referenced by the new snapshot is the SAME *Bundle
// (loadOne reuses it), so identity comparison is what decides, not the
// id: an app that was reloaded has a new bundle and its old one must
// be retired even though the id survives.
//
// Called with l.mu held.
func (l *Library) retire(old, next *snapshot, now time.Time) {
	live := make(map[*Bundle]struct{}, len(next.byID))
	for _, e := range next.byID {
		live[e.bundle] = struct{}{}
	}
	for _, e := range old.byID {
		if _, stillUsed := live[e.bundle]; !stillUsed {
			l.retired = append(l.retired, retiredBundle{bundle: e.bundle, at: now})
		}
	}

	grace := l.retireGrace
	if grace <= 0 {
		grace = defaultRetireGrace
	}
	kept := l.retired[:0]
	for _, r := range l.retired {
		if now.Sub(r.at) >= grace {
			_ = r.bundle.Close()
			continue
		}
		kept = append(kept, r)
	}
	l.retired = kept
}

// Close releases every open bundle.
func (l *Library) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var firstErr error
	for _, e := range l.snap.load().byID {
		if err := e.bundle.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Retired bundles too: shutdown is the one time there is nothing
	// left to be in flight.
	for _, r := range l.retired {
		if err := r.bundle.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	l.retired = nil
	l.snap.store(&snapshot{byID: map[string]*Entry{}})
	return firstErr
}

var _ io.Closer = (*Library)(nil)
