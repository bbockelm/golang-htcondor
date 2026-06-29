// Package sessioncache persists a daemon's CEDAR security session cache so that
// clients can resume sessions across a restart instead of all re-authenticating
// at once. It is storage-agnostic: the SessionStore interface defines the
// persistence contract, the sqlite subpackage provides an encrypted-at-rest
// implementation, and the daemon framework drives the restore/snapshot
// lifecycle.
//
// This is an opt-in deviation from C++ HTCondor, which does not persist the
// session cache. The persisted artifact contains live symmetric session keys;
// implementations are responsible for protecting them at rest.
package sessioncache

import (
	"context"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
)

// SessionRecord is the persistable form of a CEDAR session: everything needed to
// restore a resumable server-side session after a restart. KeyData is the
// symmetric session key; stores must protect it at rest.
type SessionRecord struct {
	ID          string
	Addr        string
	KeyData     []byte
	KeyProtocol string
	PolicyText  string // serialized ClassAd
	Expiration  time.Time
	LeaseSecs   int64
	Tag         string
	PeerVersion string
}

// SessionStore persists session records.
//
// Save replaces the persisted set with the supplied records; implementations
// may write incrementally but the observable result is the given set. Load
// returns the persisted records (implementations should drop expired ones).
type SessionStore interface {
	Load(ctx context.Context) ([]SessionRecord, error)
	Save(ctx context.Context, recs []SessionRecord) error
	Close() error
}

// EntryToRecord converts a cache entry into its persistable form.
func EntryToRecord(e *security.SessionEntry) SessionRecord {
	rec := SessionRecord{
		ID:          e.ID(),
		Addr:        e.Addr(),
		Expiration:  e.Expiration(),
		LeaseSecs:   int64(e.Lease().Seconds()),
		Tag:         e.Tag(),
		PeerVersion: e.LastPeerVersion(),
	}
	if ki := e.KeyInfo(); ki != nil {
		rec.KeyData = ki.Data
		rec.KeyProtocol = ki.Protocol
	}
	if pol := e.Policy(); pol != nil {
		rec.PolicyText = pol.String()
	}
	return rec
}

// RecordToEntry reconstructs a cache entry from a persisted record.
func RecordToEntry(r SessionRecord) (*security.SessionEntry, error) {
	var keyInfo *security.KeyInfo
	if len(r.KeyData) > 0 {
		keyInfo = &security.KeyInfo{Data: r.KeyData, Protocol: r.KeyProtocol}
	}
	var policy *classad.ClassAd
	if r.PolicyText != "" {
		pol, err := classad.Parse(r.PolicyText)
		if err != nil {
			return nil, err
		}
		policy = pol
	}
	entry := security.NewSessionEntry(
		r.ID, r.Addr, keyInfo, policy, r.Expiration,
		time.Duration(r.LeaseSecs)*time.Second, r.Tag,
	)
	if r.PeerVersion != "" {
		entry.SetLastPeerVersion(r.PeerVersion)
	}
	return entry, nil
}

// Snapshot returns the persistable records for the live cache, skipping
// inherited (re-imported from the environment each start) and expired sessions.
func Snapshot(cache *security.SessionCache) []SessionRecord {
	var recs []SessionRecord
	for _, e := range cache.Snapshot() {
		if e.IsInherited() || e.IsExpired() {
			continue
		}
		recs = append(recs, EntryToRecord(e))
	}
	return recs
}

// Restore loads persisted sessions into the cache. It returns the number
// restored. Records that fail to convert are skipped via onErr (if non-nil) so
// one bad record cannot block startup.
func Restore(ctx context.Context, store SessionStore, cache *security.SessionCache, onErr func(rec SessionRecord, err error)) (int, error) {
	recs, err := store.Load(ctx)
	if err != nil {
		return 0, err
	}
	restored := 0
	for _, r := range recs {
		entry, err := RecordToEntry(r)
		if err != nil {
			if onErr != nil {
				onErr(r, err)
			}
			continue
		}
		cache.Store(entry)
		restored++
	}
	return restored, nil
}
