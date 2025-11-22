package classadlog

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/PelicanPlatform/classad/classad"
)

// Reader provides access to the job queue state by tailing the log file
type Reader struct {
	filename   string
	parser     *Parser
	prober     *Prober
	collection *Collection
	mu         sync.RWMutex // Protects collection during updates
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
	defer r.parser.Close()

	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entry, err := r.parser.ReadEntry()
		if err == io.EOF {
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
	defer r.parser.Close()

	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entry, err := r.parser.ReadEntry()
		if err == io.EOF {
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
	return r.parser.Close()
}
