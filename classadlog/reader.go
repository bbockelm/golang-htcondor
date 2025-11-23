package classadlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Reader provides access to the job queue state by tailing the log file
type Reader struct {
	filename   string
	parser     *Parser
	prober     *Prober
	collection *Collection
	mu         sync.RWMutex // Protects collection during updates

	// Watch support
	watchCtx    context.Context
	watchCancel context.CancelFunc
	watchCh     chan struct{}
	watchMu     sync.Mutex // Protects watch state
}

// NewReader creates a new ClassAd log reader
func NewReader(filename string) (*Reader, error) {
	return &Reader{
		filename:   filename,
		parser:     NewParser(filename),
		prober:     NewProber(),
		collection: NewCollection(),
	}, nil
}

// Poll checks for changes and updates the in-memory state
// Returns error if unable to read or parse the log
func (r *Reader) Poll(ctx context.Context) error {
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Probe for changes
	result, err := r.prober.Probe(r.filename, r.parser.GetNextOffset())
	if err != nil {
		return fmt.Errorf("probe failed: %w", err)
	}

	switch result {
	case ProbeNoChange:
		// No changes, nothing to do
		return nil

	case ProbeCompressed:
		// File was compressed/rotated - do full reload
		return r.fullReload(ctx)

	case ProbeAddition:
		// New entries added - do incremental update
		return r.incrementalUpdate(ctx)

	case ProbeError:
		return fmt.Errorf("probe error: %w", err)

	case ProbeFatalError:
		return fmt.Errorf("probe fatal error: %w", err)

	default:
		return fmt.Errorf("unknown probe result: %v", result)
	}
}

// fullReload performs a complete reload of the log file
func (r *Reader) fullReload(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset everything
	r.collection.Reset()
	r.parser.SetNextOffset(0)
	r.prober.Reset()

	// Read all entries
	if err := r.parser.Open(); err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = r.parser.Close() }()

	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entry, err := r.parser.ReadEntry()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read entry: %w", err)
		}

		if err := r.applyEntry(entry); err != nil {
			// Log error but continue processing
			// In production, might want to use a logger here
			_ = err
		}
	}

	// Update prober state
	if err := r.prober.Update(r.filename); err != nil {
		return fmt.Errorf("failed to update prober: %w", err)
	}

	return nil
}

// incrementalUpdate reads new entries from the log
func (r *Reader) incrementalUpdate(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.parser.Open(); err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = r.parser.Close() }()

	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entry, err := r.parser.ReadEntry()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read entry: %w", err)
		}

		if err := r.applyEntry(entry); err != nil {
			// Log error but continue processing
			_ = err
		}
	}

	// Update prober state
	if err := r.prober.Update(r.filename); err != nil {
		return fmt.Errorf("failed to update prober: %w", err)
	}

	return nil
}

// applyEntry applies a log entry to the collection
func (r *Reader) applyEntry(entry *LogEntry) error {
	switch entry.OpType {
	case OpNewClassAd:
		return r.collection.NewClassAd(entry.Key, entry.MyType, entry.TargetType)

	case OpDestroyClassAd:
		return r.collection.DestroyClassAd(entry.Key)

	case OpSetAttribute:
		return r.collection.SetAttribute(entry.Key, entry.Name, entry.Value)

	case OpDeleteAttribute:
		return r.collection.DeleteAttribute(entry.Key, entry.Name)

	case OpBeginTransaction, OpEndTransaction, OpLogHistoricalSequenceNumber:
		// These operations can be ignored for read-only access
		return nil

	default:
		return fmt.Errorf("unknown operation type: %v", entry.OpType)
	}
}

// Query returns ClassAds matching the constraint
// projection specifies which attributes to include (nil = all)
func (r *Reader) Query(constraint string, projection []string) ([]*classad.ClassAd, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.collection.Query(constraint, projection)
}

// GetClassAd returns a single ClassAd by key
func (r *Reader) GetClassAd(key string) *classad.ClassAd {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.collection.Get(key)
}

// GetAllKeys returns all ClassAd keys in the collection
func (r *Reader) GetAllKeys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.collection.GetAllKeys()
}

// Len returns the number of ClassAds in the collection
func (r *Reader) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.collection.Len()
}

// Close closes the reader and releases resources
func (r *Reader) Close() error {
	// Stop watching if active
	r.watchMu.Lock()
	if r.watchCancel != nil {
		r.watchCancel()
		r.watchCancel = nil
	}
	r.watchMu.Unlock()

	return r.parser.Close()
}

// Watch starts monitoring the log file for changes and returns a channel
// that will receive notifications when the file is updated.
// The channel is closed when the context is cancelled or Close() is called.
// Only one watcher can be active at a time; calling Watch multiple times
// will cancel the previous watcher.
//
// Example usage:
//
//	ctx := context.Background()
//	updates := reader.Watch(ctx, 1*time.Second)
//	for {
//	    select {
//	    case <-updates:
//	        // File was updated, call Poll() to read changes
//	        if err := reader.Poll(ctx); err != nil {
//	            log.Printf("Poll error: %v", err)
//	        }
//	    case <-ctx.Done():
//	        return
//	    }
//	}
func (r *Reader) Watch(ctx context.Context, pollInterval time.Duration) <-chan struct{} {
	r.watchMu.Lock()
	defer r.watchMu.Unlock()

	// Cancel previous watcher if any
	if r.watchCancel != nil {
		r.watchCancel()
	}

	// Create new context and channel
	r.watchCtx, r.watchCancel = context.WithCancel(ctx)
	r.watchCh = make(chan struct{}, 1) // Buffered to avoid blocking

	// Start background goroutine to monitor file
	go r.watchLoop(r.watchCtx, pollInterval)

	return r.watchCh
}

// watchLoop monitors the file for changes and sends notifications
func (r *Reader) watchLoop(ctx context.Context, pollInterval time.Duration) {
	defer close(r.watchCh)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check if file has changed
			result, err := r.prober.Probe(r.filename, r.parser.GetNextOffset())
			if err != nil {
				// Ignore probe errors in watch loop
				continue
			}

			// Notify if there are changes
			if result != ProbeNoChange {
				select {
				case r.watchCh <- struct{}{}:
					// Notification sent
				default:
					// Channel already has pending notification, skip
				}
			}
		}
	}
}
