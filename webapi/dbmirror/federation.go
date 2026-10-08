package dbmirror

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// HubConstraint selects a federation hub's collector ad: only a hub
// advertises FederationConstraint.
const HubConstraint = "FederationConstraint isnt undefined"

// SpokeConstraint selects the ads of databases that say which schedd
// they mirror.
const SpokeConstraint = "MirroredScheddName isnt undefined"

// SpokeSet is every per-AP mirror the collector advertises, keyed by the
// schedd each one mirrors.
type SpokeSet struct {
	// bySchedd is keyed by the lower-cased schedd name: schedd names are
	// host names, which compare without regard to case.
	bySchedd map[string]*Info
	// Declined names the schedds two or more databases claimed with no
	// way to tell which is current, and why.
	Declined map[string]string
	// At is when the set was discovered.
	At time.Time
}

// For returns the mirror of schedd, or nil.
func (s *SpokeSet) For(schedd string) *Info {
	if s == nil {
		return nil
	}
	return s.bySchedd[strings.ToLower(schedd)]
}

// Names lists the schedds that have a mirror, sorted.
func (s *SpokeSet) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.bySchedd))
	for _, info := range s.bySchedd {
		out = append(out, info.MirroredScheddName)
	}
	sort.Strings(out)
	return out
}

// PickSpokes pairs mirror ads with the schedds they name.
//
// The pairing is by MirroredScheddName, which the database fills from
// the schedd whose files it reads -- not by host, which is the heuristic
// pickMirror falls back on for a single access point. A database that
// names no schedd, or has no address, is not a spoke.
//
// Two databases claiming one schedd (an HA pair, or a leftover) are
// resolved the way pickMirror resolves them: the one that is syncing
// with its job queue caught up wins, and when that does not single one
// out the schedd is declined rather than guessed at. A wrong pick serves
// a stale or foreign queue.
func PickSpokes(ads []*classad.ClassAd) (map[string]*Info, map[string]string) {
	claims := map[string][]*Info{}
	for _, ad := range ads {
		info := ParseAd(ad)
		if info.Address == "" || info.MirroredScheddName == "" || info.FederationConstraint != "" {
			continue
		}
		key := strings.ToLower(info.MirroredScheddName)
		claims[key] = append(claims[key], info)
	}
	out := make(map[string]*Info, len(claims))
	declined := map[string]string{}
	for key, infos := range claims {
		if len(infos) == 1 {
			out[key] = infos[0]
			continue
		}
		var current []*Info
		for _, info := range infos {
			if info.Syncing && info.JobQueueCaughtUp {
				current = append(current, info)
			}
		}
		if len(current) == 1 {
			out[key] = current[0]
			continue
		}
		declined[infos[0].MirroredScheddName] = fmt.Sprintf(
			"%d htcondordb databases claim to mirror this schedd and %d of them are caught up; not guessing which is current",
			len(infos), len(current))
	}
	return out, declined
}

func spokeQueryOptions() *htcondor.QueryOptions {
	// Limit -1: a zero limit is quietly capped at 50 by the collector
	// client, and a pool can have more access points than that.
	return &htcondor.QueryOptions{Limit: -1, Projection: mirrorAdAttrs()}
}

// Spokes discovers every per-AP mirror with one collector query, reusing
// the answer for InfoTTL. A failed query is an error, never an empty set:
// "the collector did not answer" is not "no AP has a mirror".
func (l *Locator) Spokes(ctx context.Context) (*SpokeSet, error) {
	if l == nil || l.collector == nil {
		return nil, fmt.Errorf("no collector configured for htcondordb discovery")
	}
	l.mu.Lock()
	if l.spokes != nil && time.Since(l.spokesAt) < InfoTTL {
		set := l.spokes
		l.mu.Unlock()
		return set, nil
	}
	l.mu.Unlock()

	ads, _, err := l.collector.QueryAdsWithOptions(ctx, AdType, SpokeConstraint, spokeQueryOptions())
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.spokesErr = err.Error()
		return nil, fmt.Errorf("querying collector for htcondordb spokes: %w", err)
	}
	by, declined := PickSpokes(ads)
	set := &SpokeSet{bySchedd: by, Declined: declined, At: time.Now()}
	l.spokes, l.spokesAt, l.spokesErr = set, set.At, ""
	return set, nil
}

// NewSpokeSetForTest builds a SpokeSet from infos keyed by their
// MirroredScheddName. Not for production use.
func NewSpokeSetForTest(infos ...*Info) *SpokeSet {
	set := &SpokeSet{bySchedd: map[string]*Info{}, Declined: map[string]string{}, At: time.Now()}
	for _, info := range infos {
		set.bySchedd[strings.ToLower(info.MirroredScheddName)] = info
	}
	return set
}

// ClientFor dials the database info describes, authenticating the way
// Client does. The caller must invoke the returned closer.
func (l *Locator) ClientFor(ctx context.Context, info *Info) (*dbrpc.Client, func(), error) {
	if info == nil || info.Address == "" {
		return nil, nil, fmt.Errorf("no htcondordb address to dial")
	}
	if l == nil || l.cfg == nil {
		return nil, nil, fmt.Errorf("no HTCondor config for htcondordb authentication")
	}
	sec, err := l.securityConfig(ctx, info.Address)
	if err != nil {
		return nil, nil, err
	}
	cl, err := htcondor.DialSinful(ctx, info.Address, sec, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to htcondordb at %s: %w", info.Address, err)
	}
	return dbrpc.NewClient(dbrpc.NewCedarConn(ctx, cl.GetStream())), func() { _ = cl.Close() }, nil
}
