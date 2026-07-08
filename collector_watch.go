package htcondor

import (
	"context"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/watch"
)

// WatchEvent is one item in a collector watch stream (see Collector.WatchAds).
// Its Kind mirrors the collections engine's event kinds, plus GoingAway:
//
//	Upsert  - Ad is the added/updated ad for Key
//	Delete  - Key was removed (Ad is nil)
//	Reset   - discard local state; an authoritative snapshot of Upserts follows
//	Synced  - end of the initial snapshot/catch-up; now live. Cursor is durable
//	Resync  - the live stream fell behind; reconnect with the last cursor
//	GoingAway - the server is shutting down; reconnect (with the last cursor),
//	          possibly to another collector
//
// Cursor, when non-nil (Synced and live events), is an opaque token to persist
// and pass back to WatchAds to resume without a full replay.
type WatchEvent struct {
	Kind   watch.Kind
	Key    string
	Ad     *classad.ClassAd
	Cursor []byte
}

// WatchAds subscribes to changes for adType (e.g. "StartdAd", "Machine",
// "ScheddAd") at the collector and returns a channel of events. constraint, if
// non-empty, is a ClassAd match expression (e.g. `DAGManJobId == 42`) so only
// events for matching ads are delivered -- an ad that stops matching arrives as
// a Delete. Pass a nil cursor for a full replay, or a cursor from a prior
// Synced/live event to resume incrementally.
//
// The channel is closed when ctx is cancelled or the stream ends (the server
// went away or the connection dropped); a GoingAway event, if delivered, arrives
// just before the close. The caller should range over the channel and, on
// GoingAway/Resync or an unexpected close, reconnect with its last cursor. The
// underlying connection is closed automatically when the stream ends.
func (c *Collector) WatchAds(ctx context.Context, adType, constraint string, cursor []byte) (<-chan WatchEvent, error) {
	hc, err := c.dialAndAuthenticate(ctx, commands.CommandType(watch.WatchAds))
	if err != nil {
		return nil, fmt.Errorf("watch: connect/authenticate: %w", err)
	}
	stream := hc.GetStream()

	req := message.NewMessageForStream(stream)
	if err := req.PutClassAd(ctx, watch.EncodeRequest(adType, constraint, cursor)); err != nil {
		_ = hc.Close()
		return nil, fmt.Errorf("watch: send request: %w", err)
	}
	if err := req.FinishMessage(ctx); err != nil {
		_ = hc.Close()
		return nil, fmt.Errorf("watch: finish request: %w", err)
	}

	events := make(chan WatchEvent)
	go func() {
		defer close(events)
		defer func() { _ = hc.Close() }()
		resp := message.NewMessageFromStream(stream)
		for {
			header, err := resp.GetClassAd(ctx)
			if err != nil {
				return // stream ended / disconnected
			}
			kind, key, cur, err := watch.DecodeHeader(header)
			if err != nil {
				return
			}
			ev := WatchEvent{Kind: kind, Key: string(key), Cursor: cur}
			if kind.HasAd() {
				ad, err := resp.GetClassAd(ctx)
				if err != nil {
					return
				}
				ev.Ad = ad
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return events, nil
}
