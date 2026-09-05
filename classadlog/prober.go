package classadlog

import (
	"fmt"
	"os"
	"time"
)

// ProbeResult indicates what changed in the log file
type ProbeResult int

const (
	// ProbeNoChange indicates no changes to the log file
	ProbeNoChange ProbeResult = iota

	// ProbeAddition indicates new entries were added
	ProbeAddition

	// ProbeCompressed indicates the log was compressed/rotated - need full reload
	ProbeCompressed

	// ProbeError indicates a recoverable error
	ProbeError

	// ProbeFatalError indicates an unrecoverable error
	ProbeFatalError
)

// String returns the string representation of a ProbeResult
func (pr ProbeResult) String() string {
	switch pr {
	case ProbeNoChange:
		return "NoChange"
	case ProbeAddition:
		return "Addition"
	case ProbeCompressed:
		return "Compressed"
	case ProbeError:
		return "Error"
	case ProbeFatalError:
		return "FatalError"
	default:
		return "Unknown"
	}
}

// Prober monitors the log file for changes
type Prober struct {
	lastSize    int64
	lastModTime time.Time
}

// NewProber creates a new log file prober
func NewProber() *Prober {
	return &Prober{}
}

// Probe checks if the log file has changed
// Returns the type of change detected
func (p *Prober) Probe(filename string, currentOffset int64) (ProbeResult, error) {
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return ProbeFatalError, fmt.Errorf("log file does not exist: %w", err)
		}
		return ProbeError, fmt.Errorf("failed to stat file: %w", err)
	}

	size := info.Size()
	modTime := info.ModTime()

	// First probe - initialize state
	if p.lastSize == 0 && p.lastModTime.IsZero() {
		p.lastSize = size
		p.lastModTime = modTime
		// Unread data exists when the file extends past what the reader has consumed.
		if size > currentOffset {
			return ProbeAddition, nil
		}
		return ProbeNoChange, nil
	}

	// Check if file was truncated/compressed (size decreased)
	if size < p.lastSize || size < currentOffset {
		// File was compressed or rotated - need full reload
		return ProbeCompressed, nil
	}

	// Check for unread data: the file has bytes beyond what the reader has CONSUMED.
	// Compared against currentOffset, NOT p.lastSize (the file size at the last Update). Update
	// stats the path AFTER a read, so if the writer appended during the read, lastSize gets
	// AHEAD of currentOffset; keying the append check on lastSize then reports NoChange for the
	// un-consumed tail and wedges the reader until the file next shrinks (a compaction forcing a
	// reload). Keying on currentOffset cannot wedge -- it keeps reading until offset == size.
	if size > currentOffset {
		return ProbeAddition, nil
	}

	// Check if modification time changed but size didn't
	// This could indicate the file was rewritten
	if !modTime.Equal(p.lastModTime) && size == p.lastSize {
		// Be conservative and trigger reload
		return ProbeCompressed, nil
	}

	// No changes detected
	return ProbeNoChange, nil
}

// Update updates the prober's state after successful read
// Should be called after processing new entries
func (p *Prober) Update(filename string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	p.lastSize = info.Size()
	p.lastModTime = info.ModTime()
	return nil
}

// Reset resets the prober state (e.g., after full reload)
func (p *Prober) Reset() {
	p.lastSize = 0
	p.lastModTime = time.Time{}
}
