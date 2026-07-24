package classadlog

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Parser reads and parses the job queue log file
type Parser struct {
	filename   string
	file       *os.File
	reader     *bufio.Reader
	nextOffset int64 // byte offset where the next unread line begins
	consumed   int64 // bytes of complete (newline-terminated) lines read since Open
	lastEntry  *LogEntry
}

// NewParser creates a new log parser
func NewParser(filename string) *Parser {
	return &Parser{
		filename: filename,
	}
}

// Open opens the log file
func (p *Parser) Open() error {
	if p.file != nil {
		return fmt.Errorf("file already open")
	}

	f, err := os.Open(p.filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	p.file = f

	// If we have a saved offset, seek to it
	if p.nextOffset > 0 {
		if _, err := f.Seek(p.nextOffset, io.SeekStart); err != nil {
			_ = p.file.Close()
			p.file = nil
			return fmt.Errorf("failed to seek to offset %d: %w", p.nextOffset, err)
		}
	}

	p.reader = bufio.NewReader(f)
	p.consumed = 0
	return nil
}

// Close closes the log file
func (p *Parser) Close() error {
	if p.file == nil {
		return nil
	}

	// Advance the resume offset by the bytes of the COMPLETE lines we consumed.
	// A partial (not-yet-newline-terminated) trailing line is deliberately not
	// counted, so the next Open re-reads it once the schedd finishes writing it --
	// rather than reading past it (skipping the op) or parsing it truncated.
	p.nextOffset += p.consumed

	err := p.file.Close()
	p.file = nil
	p.reader = nil
	p.consumed = 0
	return err
}

// ReadEntry reads the next log entry from the file
// Returns io.EOF when end of file is reached
func (p *Parser) ReadEntry() (*LogEntry, error) {
	if p.file == nil {
		return nil, fmt.Errorf("file not open")
	}

	for {
		raw, err := p.reader.ReadString('\n')
		if err != nil {
			// A trailing chunk without a newline is a partial write in progress (the
			// schedd appends a transaction incrementally). Do NOT consume or parse it:
			// return EOF and leave the bytes to be re-read, complete, on the next Open.
			// Any other error is real.
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			return nil, err
		}
		// A complete, newline-terminated line: count its bytes toward the resume offset.
		p.consumed += int64(len(raw))

		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip blank lines and comments
		}

		entry, perr := p.parseLine(line)
		if perr != nil {
			return nil, fmt.Errorf("failed to parse line %q: %w", line, perr)
		}
		p.lastEntry = entry
		return entry, nil
	}
}

// parseLine parses a single line into a LogEntry
// HTCondor job_queue.log uses numeric operation codes:
//
//	1 = New classad
//	2 = Destroy classad
//	3 = Set attribute
//	4 = Delete attribute
//	5 = Begin transaction
//	6 = End transaction
//	7 = Log historical sequence number
//
// Real HTCondor logs use codes 101-107 (base + 100)
//
// Format: <opcode> <key> [<name> [<value>]]
func (p *Parser) parseLine(line string) (*LogEntry, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty line")
	}

	entry := &LogEntry{}

	// Check if first field is a number (numeric format)
	opcode := parts[0]

	// Handle opcodes 101-107 by normalizing to 1-7
	if len(opcode) == 3 && opcode[0] == '1' && opcode[1] == '0' {
		// 101-107 -> 1-7
		opcode = string(opcode[2])
	}

	switch opcode {
	case "1", "NewClassAd":
		// Format: 1 <key> <mytype> <targettype>
		if len(parts) < 2 {
			return nil, fmt.Errorf("NewClassAd requires at least key")
		}
		entry.OpType = OpNewClassAd
		entry.Key = parts[1]
		if len(parts) >= 3 {
			entry.MyType = parts[2]
		}
		if len(parts) >= 4 {
			entry.TargetType = parts[3]
		}

	case "2", "DestroyClassAd":
		// Format: 2 <key>
		if len(parts) < 2 {
			return nil, fmt.Errorf("DestroyClassAd requires key")
		}
		entry.OpType = OpDestroyClassAd
		entry.Key = parts[1]

	case "3", "SetAttribute":
		// Format: 3 <key> <name> <value>
		if len(parts) < 4 {
			return nil, fmt.Errorf("SetAttribute requires key, name, and value")
		}
		entry.OpType = OpSetAttribute
		entry.Key = parts[1]
		entry.Name = parts[2]
		// Value is everything from the 4th field onward
		entry.Value = strings.Join(parts[3:], " ")

	case "4", "DeleteAttribute":
		// Format: 4 <key> <name>
		if len(parts) < 3 {
			return nil, fmt.Errorf("DeleteAttribute requires key and name")
		}
		entry.OpType = OpDeleteAttribute
		entry.Key = parts[1]
		entry.Name = parts[2]

	case "5", "BeginTransaction":
		entry.OpType = OpBeginTransaction

	case "6", "EndTransaction":
		entry.OpType = OpEndTransaction

	case "7", "LogHistoricalSequenceNumber":
		entry.OpType = OpLogHistoricalSequenceNumber

	default:
		// Unknown operation - skip it rather than failing
		// HTCondor may use other operation codes we don't need to parse
		entry.OpType = OpBeginTransaction // Treat as no-op
	}

	return entry, nil
}

// SetNextOffset sets the file offset for the next read
func (p *Parser) SetNextOffset(offset int64) {
	p.nextOffset = offset
}

// GetNextOffset returns the current file offset
func (p *Parser) GetNextOffset() int64 {
	return p.nextOffset
}

// GetLastEntry returns the last entry read
func (p *Parser) GetLastEntry() *LogEntry {
	return p.lastEntry
}

// GetFilename returns the log filename
func (p *Parser) GetFilename() string {
	return p.filename
}
