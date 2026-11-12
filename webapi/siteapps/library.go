package siteapps

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// recordTimeout bounds one audit write. Generous: the write is a
// handful of small statements, and the only reason to give up is a
// database that is not answering at all.
const recordTimeout = 10 * time.Second

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

	// policySrc is the operator's decisions, replaced wholesale on a
	// reconfigure. See SetPolicySource.
	policySrc atomic.Pointer[PolicySource]

	// rec records what was served, for the audit trail. Optional.
	rec atomic.Pointer[Recorder]

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
func NewLibrary(dir string, policy PolicySource) *Library {
	l := &Library{dir: dir, retireGrace: defaultRetireGrace}
	l.snap.store(&snapshot{byID: map[string]*Entry{}})
	l.SetPolicySource(policy)
	return l
}

// SetPolicySource installs the policy a rescan will read.
//
// A reconfigure hands the daemon a freshly-read configuration rather
// than mutating the one it was started with, so the source has to be
// replaced rather than re-read. Stored through an atomic pointer
// because a rescan may be running on the reload goroutine while the
// signal goroutine calls this.
//
// A nil source declares nothing, which publishes nothing. That is the
// same answer as a configuration naming no apps, and it is the right
// one: a server that has lost track of who may see what must not keep
// serving on the strength of the last policy it remembers.
func (l *Library) SetPolicySource(policy PolicySource) {
	if policy == nil {
		policy = emptyPolicy{}
	}
	l.policySrc.Store(&policy)
}

// policy is the installed source.
func (l *Library) policy() PolicySource {
	if p := l.policySrc.Load(); p != nil {
		return *p
	}
	return emptyPolicy{}
}

// emptyPolicy declares no apps.
type emptyPolicy struct{}

func (emptyPolicy) Policy(string) (Policy, bool) { return Policy{}, false }
func (emptyPolicy) DeclaredIDs() []string        { return nil }

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
	var found []string

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
		// Recorded before the load is attempted, so a bundle that
		// fails to open still counts as present: its policy is not an
		// orphan, it is a policy for something broken, and saying
		// otherwise would send the operator after the wrong fault.
		found = append(found, id)
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

	// Two bundles whose ids differ only by hyphen-versus-underscore
	// share one set of configuration parameters, so neither can be
	// given a policy of its own. Refuse both: publishing either would
	// publish it under a policy that may have been written for the
	// other, and which one wins would come down to directory order.
	for macro, ids := range MacroCollision(found) {
		problems = append(problems, fmt.Errorf(
			"site apps %s share the configuration name %s, so neither can be given its own "+
				"policy; rename one of the bundles. Neither is published",
			strings.Join(quoteAll(ids), " and "), configPrefix+macro+"_GROUPS"))
		for _, id := range ids {
			delete(next.byID, id)
		}
	}

	// A policy naming an app with no bundle is usually a typo in the
	// parameter name or a bundle that was never copied across. Neither
	// is visible any other way: nothing is served, and nothing in the
	// directory is wrong.
	seen := make(map[string]bool, len(found))
	for _, id := range found {
		seen[MacroID(id)] = true
	}
	for _, macro := range l.policy().DeclaredIDs() {
		if !seen[macro] {
			problems = append(problems, fmt.Errorf(
				"%s names groups, but no bundle in %s has that id; nothing is served for it",
				configPrefix+macro+"_GROUPS", l.dir))
		}
	}

	next.order = make([]string, 0, len(next.byID))
	for id := range next.byID {
		next.order = append(next.order, id)
	}
	sort.Strings(next.order)

	l.snap.store(next)
	now := time.Now()
	l.retire(old, next, now)
	if err := l.record(next, now); err != nil {
		// Recording is an account of what was served, not a condition
		// of serving it. A database that is unwritable must not take
		// the apps down with it, so this is reported and the scan
		// stands.
		problems = append(problems, err)
	}
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

	// Fail closed. Who may see an app is the site's decision, and a
	// bundle nobody has made that decision about is not published --
	// however long it has been sitting in the directory.
	policy, ok := l.policy().Policy(id)
	if !ok {
		return nil, UnconfiguredMessage(id, filepath.Base(path))
	}
	if !policy.IsEnabled() {
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
		app, err := Merge(id, prev.bundle.Manifest, policy)
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
	app, err := Merge(id, bundle.Manifest, policy)
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

// quoteAll renders ids for a message listing more than one.
func quoteAll(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strconv.Quote(id)
	}
	return out
}

// record notes the published set in the audit trail.
func (l *Library) record(next *snapshot, now time.Time) error {
	rec := l.recorder()
	if rec == nil {
		return nil
	}
	apps := make([]Incarnation, 0, len(next.byID))
	for _, id := range next.order {
		e := next.byID[id]
		kind := "zip"
		if e.bundle.ContentDigest == "" {
			kind = "directory"
		}
		apps = append(apps, Incarnation{
			AppID:       e.App.ID,
			Digest:      e.bundle.ContentDigest,
			BundleKind:  kind,
			SizeBytes:   e.bundle.SizeBytes,
			DigestKnown: e.App.Digest != "",
			Version:     e.App.Version,
			Revision:    e.App.Revision,
			Name:        e.App.Name,
			Description: e.App.Description,
			Icon:        e.App.Icon,
			Groups:      e.App.Groups,
			Home:        e.App.Home,
			Origin:      e.App.Origin,
		})
	}
	// Bounded so a wedged database cannot hold the reload goroutine,
	// which is also the one that would otherwise pick up the next
	// bundle an operator drops.
	ctx, cancel := context.WithTimeout(context.Background(), recordTimeout)
	defer cancel()
	return rec.Observe(ctx, now, apps)
}

// SetRecorder installs the audit recorder. nil records nothing.
func (l *Library) SetRecorder(r Recorder) {
	if r == nil {
		l.rec.Store(nil)
		return
	}
	l.rec.Store(&r)
}

func (l *Library) recorder() Recorder {
	if r := l.rec.Load(); r != nil {
		return *r
	}
	return nil
}
